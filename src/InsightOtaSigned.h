#ifndef INSIGHT_OTA_SIGNED_H
#define INSIGHT_OTA_SIGNED_H

#include <cstddef>
#include <cstdint>

#include "InsightOta.h"
#include "InsightOtaRunner.h"

// ===========================================================================
// Rollback driven by a post-update health-check, and optional signed images
// Ticket B14 — FR-OTA-06 (rollback) / FR-OTA-07 (signed images) / NFR-SEC-03
// ===========================================================================
//
// This header is the POLICY layer that sits on top of the two pieces the SDK
// already had, and it exists because those two pieces answer two different
// halves of the same question:
//
//   * `InsightOta` (and its signature seam) answers "are these bytes the
//     image we were promised, and did someone we trust sign them?". It owns
//     the DOWNLOAD side: never flash until size, digest and — when configured —
//     the signature all agree.
//
//   * `InsightOtaRunner` answers "the image flashed; did it turn out to be
//     any good?". It owns the BOOT side: a freshly flashed image is on
//     probation until the application says it is healthy, and on ESP32 a
//     probation that is never satisfied is rolled back.
//
// What B14 adds is the JOIN between them — the missing decision that turns the
// runner's raw expiry into a rollback the operator can reason about. That join
// is `HealthCheckRollback`:
//
//   FR-OTA-06 — "rollout bertahap + rollback bila firmware baru gagal boot".
//   The mechanism is a health-check `reconcile`: after the update, the device
//   reports the version it is running and asks the server to reconcile it
//   against what the server believes the device should be running. If the
//   reconcile says the device did NOT come up healthy — it is running the old
//   version, or it is not the version the roller-out expects — the update is
//   declared failed and the trial is rolled back. If the reconcile says the
//   device is healthy, the trial is confirmed and the update is kept.
//
//   FR-OTA-07 — "image bertanda tangan (signed)". The offer may now carry a
//   detached `signature` (+ optional `pubkey_id`), and `InsightOta` checks it
//   through the injected `SignatureVerifier` seam BEFORE the flash. A wrong
//   signature is never flashed; a correct one is. The crypto itself never
//   enters this repo: the seam is a function pointer, so a native test injects
//   a fake verifier and proves the policy, and firmware plugs in its real one.
//
// ---------------------------------------------------------------------------
// The platform asymmetry is the load-bearing fact (INV-O4)
// ---------------------------------------------------------------------------
//
// ESP32 and ESP8266 do NOT behave the same when a health-check fails, and
// pretending they do would be the worst possible outcome. Reproduced from
// InsightOtaRunner (do not duplicate the reasoning there — this layer just
// carries it up to the operator):
//
//   * ESP32 has two application slots, an `otadata` partition and a bootloader
//     rollback. A trial that fails its health-check is rolled back to the
//     previous, known-good image, and the outcome is `rolledBack`.
//   * ESP8266 has ONE image and NO rollback. There is nothing to roll back to —
//     the running image overwrote its only predecessor. A failed health-check
//     there cannot be undone; the honest outcome is `reattemptRequired`, and the
//     only recovery is to REATTEMPT the update (or the app-level recovery the
//     product layer owns). Reporting `rolledBack` on ESP8266 would tell the
//     operator a recovery path exists where none does.
//
// `HealthCheckRollback` is therefore constructed with a platform and a runner,
// and it never flattens the two outcomes into a single "recovered" boolean.
//
// ---------------------------------------------------------------------------
// Seams, and why this is testable on a host
// ---------------------------------------------------------------------------
//
//   * `HealthReport` — the post-update health-check, injected as a function
//     pointer. It performs the `reconcile` (the device reports its version, the
//     server answers whether that is the expected one) and returns a
//     `HealthCheck`. In firmware it wraps the `GET /v1/ota` round-trip that
//     already triggers reconcile (spec §6.4); in tests it is a fixture value.
//     Because the check is a seam, "health-check failed" is an INPUT a test
//     sets, not a network event a test has to fake.
//   * `InsightOtaRunner` — the boot/confirm state machine, injected (borrowed)
//     so both platforms' expiry behaviour are provable in one native binary.
//   * the `SignatureVerifier` inside the `InsightOta` this layer is told to run
//     — see below.
//
// Nothing here blocks: the health-check is one bounded call, and the rollback
// decision reads the runner's clock rather than waiting on it.

namespace insight {

// ===========================================================================
// The post-update health-check
// ===========================================================================

// The three verdicts a post-update health-check can reach. They are deliberately
// distinct because the ACTION each one implies is different, and conflating
// "the device is fine" with "the device did not reach the new version" is how an
// update gets silently lost:
//
//   Healthy   - the device is up and running the EXPECTED image. Confirm the
//               trial; the update is kept.
//   Unhealthy - the device is up but NOT on the expected image (it reports the
//               OLD version, or a different one). The update did not take; the
//               trial is treated as failed and the platform's failure outcome
//               applies (ESP32 rollback / ESP8266 reattempt).
//   Unknown   - the check could not be completed (offline, 5xx, no transport).
//               This is NOT a failure and NOT a success: an unreachable server
//               must never roll back a device that may be perfectly healthy, and
//               must never confirm a trial it cannot vouch for. The caller
//               retries the check; the trial stays on probation.
enum HealthVerdict { HealthHealthy, HealthUnhealthy, HealthUnknown };

// The result of one health-check, as a value. `verdict` is the decision; the
// version strings are carried only for the record (they make a log line and a
// reconcile row self-explanatory) and are never used to make the decision —
// that is `verdict`'s job alone, so a caller cannot smuggle a decision in by
// leaving a string blank.
struct HealthCheck {
  HealthVerdict verdict;
  // The version the device reports it is running ("" when unknown).
  char reportedVersion[64];
  // The version the roller-out expects ("" when unspecified). When both are
  // known, `verdict == HealthHealthy` implies they are equal — a convenience
  // the tests pin, so a health-check that says "healthy" about the wrong
  // version fails loudly instead of being trusted.
  char expectedVersion[64];

  // Construct an "unknown" check (the "not yet performed" default).
  HealthCheck()
      : verdict(HealthUnknown) {
    reportedVersion[0] = '\0';
    expectedVersion[0] = '\0';
  }

  // Build a check with an explicit verdict and version strings.
  static HealthCheck make(HealthVerdict v, const char* reported, const char* expected) {
    HealthCheck h;
    h.verdict = v;
    copyCStr(h.reportedVersion, sizeof(h.reportedVersion), reported);
    copyCStr(h.expectedVersion, sizeof(h.expectedVersion), expected);
    return h;
  }

  // Convenience constructors, so a caller (or a test) reads as intent:
  //   HealthCheck::healthy("2.0.0", "2.0.0")
  //   HealthCheck::unhealthy("1.0.0", "2.0.0")   // still on the old image
  //   HealthCheck::unknown()
  static HealthCheck healthy(const char* reported, const char* expected) {
    return make(HealthHealthy, reported, expected);
  }
  // A device up on a version OTHER than the expected one.
  static HealthCheck unhealthy(const char* reported, const char* expected) {
    return make(HealthUnhealthy, reported, expected);
  }
  // The check could not be completed (offline/5xx/no seam).
  static HealthCheck unknown() { return make(HealthUnknown, 0, 0); }

 private:
  static void copyCStr(char* out, size_t outLen, const char* src) {
    if (out == 0 || outLen == 0) return;
    if (src == 0) {
      out[0] = '\0';
      return;
    }
    size_t i = 0;
    for (; i + 1 < outLen && src[i] != '\0'; ++i) out[i] = src[i];
    out[i] = '\0';
  }
};

// The health-check seam: one bounded call that performs the post-update
// `reconcile` and reports a verdict. A plain C function pointer, the seam style
// used throughout this SDK. A null pointer means "there is no way to check":
// the policy then treats every check as `HealthUnknown` and NEVER rolls back
// on the strength of a check that did not happen (see decide()).
typedef HealthCheck (*HealthReport)();

// ===========================================================================
// The rollback decision
// ===========================================================================

// What the health-driven rollback concluded for one trial, as a value. This is
// the operator-facing record; it is deliberately richer than a bool because
// "we rolled back" and "we are stuck on the new image" are different facts.
struct RollbackOutcome {
  enum Decision {
    // The health-check said the device is healthy on the expected image. The
    // trial was confirmed; the update is KEPT. No rollback, ever, after this.
    Kept,
    // The health-check said the device did not reach the expected image, and
    // the platform could roll back (ESP32): the previous image is restored and
    // the device is rebooted into it. Terminal.
    RolledBack,
    // The health-check said the device did not reach the expected image, and
    // the platform could NOT roll back (ESP8266): the update is on the device
    // and cannot be undone; the operator must reattempt. Terminal in the sense
    // that THIS decision is final, but distinct from RolledBack by design.
    ReattemptRequired,
    // The health-check said the device did not reach the expected image, the
    // platform CAN roll back (ESP32), but the rollback itself FAILED (the
    // bootloader reported false, or no rollback seam is wired). The device is
    // NOT back on a known-good image, so — like ReattemptRequired — the caller
    // must reattempt, and `rolledBack` stays FALSE. Kept distinct from
    // ReattemptRequired so an operator can tell "this chip has no rollback"
    // from "the rollback was attempted and did not take".
    RollbackFailed,
    // The health-check did not complete (offline/5xx/no seam). The trial stays
    // on probation and the CALLER must retry the check; nothing was confirmed
    // and nothing was rolled back. Not terminal.
    KeepTrial,
    // No trial is pending (nothing flashed, or the runner is idle/terminal), so
    // there was nothing to decide. A total no-op, so the caller can drive this
    // unconditionally from loop().
    NoTrial
  };

  // The decision reached for this check.
  Decision decision;
  // The health-check input this decision was made from.
  HealthVerdict verdict;
  // True only for RolledBack. Provided so a caller can log "was there a real
  // rollback?" without switching on the enum; it is false for ReattemptRequired,
  // which is the whole point of keeping the two apart.
  bool rolledBack;
  // True only for ReattemptRequired — the ESP8266 "the update is stuck, retry"
  // outcome. Mutually exclusive with `rolledBack`.
  bool reattemptRequired;
  // True when the trial ended without a successful recovery, so the caller must
  // reattempt the update. True for BOTH ReattemptRequired (no rollback exists)
  // and RollbackFailed (rollback was attempted and failed); false for Kept,
  // RolledBack, KeepTrial and NoTrial. Provided so a caller can log/schedule the
  // retry without conflating a failed rollback with a successful one.
  bool retryRecommended;
  // True when the runner actually expired a trial as a result of this call
  // (i.e. the trial was still pending when a terminal verdict arrived).
  bool trialExpired;

  // Construct a "no trial, nothing decided" outcome.
  RollbackOutcome()
      : decision(NoTrial), verdict(HealthUnknown), rolledBack(false),
        reattemptRequired(false), retryRecommended(false), trialExpired(false) {}
};

// ===========================================================================
// HealthCheckRollback — FR-OTA-06, wired to InsightOtaRunner
// ===========================================================================

// Drives the two-phase trial from InsightOtaRunner using a post-update
// health-check instead of a bare timeout. Usage in firmware (per loop pass after
// an OTA flash armed a trial):
//
//   if (roller.isTrialPending()) {
//     RollbackOutcome o = roller.checkHealth();   // one bounded reconcile
//     if (o.rolledBack)        log("rolled back");
//     else if (o.reattemptRequired) log("must reattempt (no rollback here)");
//     else if (o.decision == RollbackOutcome::KeepTrial) /* retry later */;
//   }
//
// The class owns NOTHING: it borrows an `InsightOtaRunner*` and holds a
// `HealthReport` function pointer. That keeps it allocation-free and safe to
// live in static storage next to the runner.
class HealthCheckRollback {
 public:
  HealthCheckRollback()
      : runner_(0), report_(0), checks_(0), lastVerdict_(HealthUnknown),
        lastRolledBack_(false), lastReattempt_(false),
        lastRollbackFailed_(false),
        nextAllowedMillis_(0), unknownStreak_(0), lastBackoffMillis_(0) {}

  // Borrow a runner and install the health-check seam. Either may be null:
  // a null runner makes every check() a `NoTrial` no-op, and a null report_
  // makes every pending check `HealthUnknown` (nothing is ever confirmed or
  // rolled back on a check that did not happen).
  HealthCheckRollback(InsightOtaRunner* runner, HealthReport report)
      : runner_(runner), report_(report), checks_(0), lastVerdict_(HealthUnknown),
        lastRolledBack_(false), lastReattempt_(false),
        lastRollbackFailed_(false),
        nextAllowedMillis_(0), unknownStreak_(0), lastBackoffMillis_(0) {}

  // --- injected seams ----------------------------------------------------
  void setRunner(InsightOtaRunner* runner) { runner_ = runner; }
  InsightOtaRunner* runner() const { return runner_; }

  void setHealthReport(HealthReport report) { report_ = report; }
  HealthReport healthReport() const { return report_; }

  // Which part we run on. Delegated straight to the runner (the runner owns the
  // asymmetry; this class must not keep a second copy of it that could drift).
  void setPlatform(InsightOtaRunner::Platform platform) {
    if (runner_ != 0) runner_->setPlatform(platform);
  }

  // --- the decision ------------------------------------------------------

  // True while a flashed image is on probation — i.e. a health-check is
  // meaningful. False when no runner is installed or it is idle/terminal.
  bool isTrialPending() const {
    return runner_ != 0 && runner_->isTrial();
  }

  // --- Unknown-verdict backoff (never hammer the reconcile) --------------
  //
  // An `Unknown` verdict is not a decision: the trial stays on probation and
  // the caller retries. Retrying IMMEDIATELY from loop() would hammer the very
  // server that is already failing, so an Unknown verdict records a bounded
  // backoff and the caller waits for it. This mirrors InsightOta's own
  // retry-after/backoff policy: the wait is RECORDED, never slept on.
  //
  // The delay is the shared bounded exponential backoff from InsightReliability
  // (already included through InsightOta.h), keyed on the number of CONSECUTIVE
  // Unknown verdicts, so a longer outage backs off further instead of settling
  // into a fixed-rate poll. A Healthy/Unhealthy verdict or a dropped trial
  // resets the counter, so a single transient Unknown does not penalise the
  // step after it.

  // millis() at or after which the next health-check may run, in the runner's
  // clock domain, or 0 when none is pending (a decision was reached, or no
  // check has run). The caller loops with
  //   if (roller.isReady(millis())) roller.check();
  uint32_t nextAllowedMillis() const { return nextAllowedMillis_; }

  // True when a check may run at `nowMillis`: no pending schedule, or the
  // schedule has been reached. With no pending backoff the answer is true, so a
  // caller can drive this unconditionally from loop().
  bool isReady(uint32_t nowMillis) const {
    return nextAllowedMillis_ == 0 || nowMillis >= nextAllowedMillis_;
  }

  // Run the health-check ONCE and act on its verdict. Bounded and non-blocking:
  // it makes at most one `report_()` call and reads the clock only through the
  // runner. Returns the decision as a value; every field is also latched into
  // the accessors below.
  //
  // The mapping is the whole ticket, so it is stated exactly:
  //
  //   Healthy   -> runner_->confirm()  -> Kept        (ESP32 and ESP8266 alike;
  //                                       a healthy device is healthy on both)
  //   Unhealthy -> trip the trial and let the RUNNER decide:
  //                  ESP32, rollback ok      -> RolledBack
  //                  ESP32, rollback FAILED  -> RollbackFailed
  //                  ESP8266 (no slot)       -> ReattemptRequired
  //                The platform branch is NOT re-implemented here. The runner
  //                performs it through its own expiry path, so there is exactly
  //                one place that knows ESP32 has two slots and ESP8266 does
  //                not — which is what keeps the two from drifting apart.
  //   Unknown   -> nothing happens; the trial stays on probation (KeepTrial)
  //                and the caller retries AFTER a bounded backoff. An
  //                unreachable server is not evidence of a bad image and must
  //                not be hammered.
  RollbackOutcome check() {
    RollbackOutcome out;
    out.decision = RollbackOutcome::NoTrial;
    out.verdict = HealthUnknown;
    if (runner_ == 0 || !runner_->isTrial()) {
      lastVerdict_ = HealthUnknown;
      // No trial: any backoff is over, so a caller cannot be left waiting on a
      // schedule that belonged to a trial that has since ended.
      nextAllowedMillis_ = 0;
      unknownStreak_ = 0;
      return out;
    }

    ++checks_;
    const HealthCheck health = report_ == 0 ? HealthCheck::unknown() : report_();
    out.verdict = health.verdict;
    lastVerdict_ = health.verdict;

    switch (health.verdict) {
      case HealthHealthy:
        // The device came up healthy. Confirm — which marks the image valid and
        // cancels the bootloader's pending rollback (ESP32), or is a successful
        // no-op where there is no flag (the runner owns that detail). After a
        // confirm the trial can never roll back, on either platform.
        runner_->confirm();
        out.decision = RollbackOutcome::Kept;
        out.trialExpired = false;
        nextAllowedMillis_ = 0;   // decided: no retry pending
        unknownStreak_ = 0;
        break;

      case HealthUnhealthy: {
        // The device did not reach the expected image. Trip the trial NOW by
        // driving the runner's expiry path (pollAt(deadline)), so the runner
        // applies ITS platform rule — rollback on ESP32, reattempt on ESP8266.
        // We do not call rollback() ourselves: duplicating that branch here is
        // exactly the drift INV-O4 forbids.
        const bool expired = runner_->pollAt(runner_->deadlineMillis());
        out.trialExpired = expired;
        if (runner_->isRolledBack()) {
          out.decision = RollbackOutcome::RolledBack;
          out.rolledBack = true;
        } else if (runner_->isRollbackFailed()) {
          // ESP32: the rollback was attempted and did NOT take. The device is
          // not on a known-good image; the caller must reattempt. Explicitly
          // not `rolledBack`, so no successful-recovery claim is ever made.
          out.decision = RollbackOutcome::RollbackFailed;
          out.retryRecommended = true;
        } else if (runner_->isReattemptRequired()) {
          out.decision = RollbackOutcome::ReattemptRequired;
          out.reattemptRequired = true;
          out.retryRecommended = true;
        } else {
          // The runner did not reach a terminal state (e.g. its clock is frozen
          // or the deadline is in the future). We cannot honestly claim either
          // recovery happened, so the trial stays pending and the caller
          // retries — fail safe, never a phantom rollback. Back off before the
          // retry, exactly as for an Unknown verdict, so a frozen-clock device
          // cannot spin.
          out.decision = RollbackOutcome::KeepTrial;
          scheduleUnknownBackoff();
        }
        // A terminal verdict ends the backoff question entirely: there is no
        // trial left to re-check.
        if (out.decision != RollbackOutcome::KeepTrial) {
          nextAllowedMillis_ = 0;
          unknownStreak_ = 0;
        }
        break;
      }

      case HealthUnknown:
      default:
        // No verdict -> no action. NOT a rollback (a server outage must not
        // brick a healthy device by rolling it back) and NOT a confirm (we
        // cannot vouch for an image we could not check). The caller retries,
        // but only AFTER a bounded backoff so loop() cannot hammer a server
        // that is already failing.
        out.decision = RollbackOutcome::KeepTrial;
        out.trialExpired = false;
        scheduleUnknownBackoff();
        break;
    }

    lastRolledBack_ = out.rolledBack;
    lastReattempt_ = out.reattemptRequired;
    lastRollbackFailed_ = (out.decision == RollbackOutcome::RollbackFailed);
    return out;
  }

  // Convenience: check() only while a trial is pending. Identical result shape;
  // provided so a caller that does not want to test isTrialPending() first gets
  // a `NoTrial` no-op instead of a surprise.
  RollbackOutcome checkIfPending() {
    if (!isTrialPending()) return RollbackOutcome();
    return check();
  }

  // --- inspection --------------------------------------------------------
  unsigned long checks() const { return checks_; }
  HealthVerdict lastVerdict() const { return lastVerdict_; }
  bool lastRolledBack() const { return lastRolledBack_; }
  bool lastReattemptRequired() const { return lastReattempt_; }
  // The last check ended in an ESP32 rollback that FAILED (the device is not
  // back on a known-good image). Distinct from lastRolledBack(), which is only
  // ever true for a rollback that SUCCEEDED.
  bool lastRollbackFailed() const { return lastRollbackFailed_; }

  // Duration the last non-decisive verdict scheduled before the next check, in
  // millis (0 when nothing was scheduled). Exposed so a test asserts the
  // SCHEDULE rather than observing a sleep — this layer never blocks.
  uint32_t lastBackoffMillis() const { return lastBackoffMillis_; }

  // Number of CONSECUTIVE non-decisive (Unknown / stuck-KeepTrial) verdicts,
  // which drives the exponential backoff. Reset to 0 by any decision.
  uint32_t unknownStreak() const { return unknownStreak_; }

 private:
  // Record a bounded backoff for the NEXT health-check after a non-decisive
  // verdict (Unknown, or an Unhealthy that could not trip a terminal state).
  // The delay is the shared bounded exponential backoff keyed on the number of
  // CONSECUTIVE such verdicts — the same policy InsightOta uses for a transport
  // failure — so a longer outage polls less often instead of at a fixed rate.
  // The deadline is in the RUNNER's clock domain (the only clock this layer can
  // read); a null runner clock reads as 0, which makes the deadline unobservable
  // but never wrong.
  void scheduleUnknownBackoff() {
    ++unknownStreak_;
    const uint32_t now = runner_ != 0 ? static_cast<uint32_t>(runner_->now()) : 0u;
    const uint32_t wait = backoffMillis(unknownStreak_ - 1u);
    nextAllowedMillis_ = now + wait;
    lastBackoffMillis_ = wait;
  }

  InsightOtaRunner* runner_;
  HealthReport report_;
  unsigned long checks_;
  HealthVerdict lastVerdict_;
  bool lastRolledBack_;
  bool lastReattempt_;
  bool lastRollbackFailed_;

  // Unknown-verdict backoff state. `unknownStreak_` counts CONSECUTIVE
  // non-decisive verdicts and resets on any decision or on a dropped trial;
  // `nextAllowedMillis_` is in the runner's clock domain (0 == no wait).
  uint32_t nextAllowedMillis_;
  uint32_t unknownStreak_;
  uint32_t lastBackoffMillis_;
};

// ===========================================================================
// Signed images — a thin, named spine over the InsightOta signature seam
// ===========================================================================
//
// FR-OTA-07 lives in `InsightOta` (the download side owns "verify before
// flash", so the gate must be where the flash sink is). What is added here is
// the small amount of POLICY that is worth naming so a caller does not have to
// remember the ordering, plus a compile-time statement that the seam is a seam:
//
//   * `SignedOtaPolicy` bundles "what does this device require?" — the verifier,
//     and whether a signature is mandatory — and APPLIES it to an InsightOta in
//     one call, so the two settings cannot be half-wired (a device that requires
//     signing but forgot the verifier fails closed rather than silently
//     downgrading; see InsightOta::setRequireSignature()).
//
//   * `makeFailClosedPolicy()` returns the only policy safe to ship on a device
//     that cannot roll back (ESP8266): signatures REQUIRED. Pairing it with a
//     null verifier is still safe — verification then fails closed — which is
//     the property the tests pin.
//
// There is deliberately no second flash path here. A signed image is still
// flashed by `InsightOta`, through the same single sink, gated by the same
// size+digest+signature checks; this class only configures them.

struct SignedOtaPolicy {
  // The verifier to install. Null = "no key on this device" (see InsightOta).
  SignatureVerifier verifier;
  // When true, an offer without a signature is refused. Default false keeps the
  // shipped contract (unsigned firmware still installs) — turn it on once the
  // server signs every image.
  bool requireSignature;

  SignedOtaPolicy() : verifier(0), requireSignature(false) {}

  // Apply this policy to an OTA object. Installing a null verifier with
  // requireSignature == true is legal and FAILS CLOSED at check time, so an
  // operator can arm "only signed images" before the key backend is wired and
  // cannot accidentally accept an unsigned image in the meantime.
  void applyTo(InsightOta* ota) const {
    if (ota == 0) return;
    ota->setSignatureVerifier(verifier);
    ota->setRequireSignature(requireSignature);
  }
};

// The policy for a device that must only ever accept signed firmware: signing
// required. `verifier` may be null (fail-closed) or a real one.
inline SignedOtaPolicy makeFailClosedPolicy(SignatureVerifier verifier) {
  SignedOtaPolicy p;
  p.verifier = verifier;
  p.requireSignature = true;
  return p;
}

// The policy that preserves the pre-B14 behaviour: verify a signature when the
// offer carries one AND a verifier is installed, but accept an unsigned image.
inline SignedOtaPolicy makeOpportunisticPolicy(SignatureVerifier verifier) {
  SignedOtaPolicy p;
  p.verifier = verifier;
  p.requireSignature = false;
  return p;
}

// Is this pass's outcome one in which the image reached the partition? A named
// predicate so callers (and the rollback layer) never re-spell the comparison
// and drift from OtaResult. True for Flashed only — the same definition
// ImageVerification::flashed uses.
inline bool wasFlashed(const OtaResult& result) {
  return result.kind == OtaResult::Flashed;
}

// Is this pass's outcome a SIGNATURE rejection specifically (as opposed to a
// corrupt transfer or a transport failure)? Lets a caller distinguish "someone
// signed this with a key we do not trust" from "the bytes arrived wrong" — two
// events with very different operational responses.
inline bool wasSignatureRejected(const OtaResult& result) {
  return result.kind == OtaResult::SignatureMismatch;
}

}  // namespace insight

#endif  // INSIGHT_OTA_SIGNED_H
