#ifndef INSIGHT_OTA_RUNNER_H
#define INSIGHT_OTA_RUNNER_H

// Arduino's ESP cores define `ESP32` / `ESP8266` as command-line macros naming
// the target. The `Platform` enum below uses those words as enumerators, and a
// macro rewrites them into a numeric constant — `enum Platform { ESP32 }`
// becomes `enum Platform { 1 }` and fails to compile. A device sketch also
// tests `defined(ESP32)` for its own platform split, so the macros cannot
// simply be dropped: they are saved, undefined only while the enum is declared,
// then restored verbatim. The enum is interface, the macros are the toolchain's
// — keeping both means this header is includable from an aggregate like
// Insight.h without breaking the sketch that included it.
#ifdef ESP32
#define INSIGHT_OTA_RUNNER_SAVED_ESP32
#define INSIGHT_OTA_RUNNER_ESP32_VALUE ESP32
#undef ESP32
#endif
#ifdef ESP8266
#define INSIGHT_OTA_RUNNER_SAVED_ESP8266
#define INSIGHT_OTA_RUNNER_ESP8266_VALUE ESP8266
#undef ESP8266
#endif

namespace insight {

// ===========================================================================
// Two-phase OTA boot/confirm runner (ST-O4 / INV-O4)
// ===========================================================================
//
// A freshly flashed image is not trusted just because the bytes verified. It
// is trusted only once the device has BOOTED into it and reported healthy — if
// the new image boot-loops, panics, or never reaches the point where it can
// call confirm(), the device must come back up on the old, known-good image
// instead of being bricked by a bad-but-authentic build.
//
// That is the whole job here, and it is deliberately split into two phases
// because the two phases happen in different boots:
//
//   PHASE 1 — after flash. The image was written (InsightOta reports
//     `OtaResult::Flashed`) and this runner is armed with it. The state becomes
//     `trial`: the new image is running, but it is on probation and its slot is
//     NOT yet marked bootable. A deadline is recorded: `confirmTimeoutMillis`
//     from arm-time.
//
//   PHASE 2 — on the next boot (or later in the same boot), one of:
//     * confirm() — the application came up and declared itself healthy. On
//       ESP32 this calls the injected `markValid()` (which cancels the bootloader's
//       rollback, e.g. `esp_ota_mark_app_valid_cancel_rollback()`), and the
//       state becomes `confirmed`. No rollback ever follows a confirm().
//     * poll(now) reaching the deadline WITHOUT a confirm() — the trial expired.
//       What happens next is where the two platforms diverge (below).
//
// ---------------------------------------------------------------------------
// The platform asymmetry — the load-bearing part (INV-O4)
// ---------------------------------------------------------------------------
//
// ESP32 has TWO application slots and a bootloader that can pick either one, so
// a rolled-back trial is real: `rollback()` (injected; e.g.
// `esp_ota_mark_app_invalid_rollback_and_reboot()`) points the bootloader back
// at the previous image and reboots into it. The outcome is `rolledBack`.
//
// ESP8266 has NO two-slot layout and NO bootloader rollback. There is simply
// nothing to roll back TO — the running image overwrote its only predecessor, so
// the "roll back" operation the ESP32 path performs does not exist on this part.
// Pretending otherwise would be the worst possible answer: firmware that calls
// a rollback that cannot happen, reports a success that did not occur, and
// leaves the operator believing a recovery path exists when it does not.
//
// So on ESP8266 an expired trial does NOT roll back and MUST NOT report
// `rolledBack`. It reports `reattemptRequired`: the new image timed out
// confirmation, it cannot be undone on this chip, and the only honest next step
// is to REATTEMPT the update (re-download/re-flash, or fall back to the app-level
// recovery the product layer owns). The two outcomes are deliberately distinct
// enum values — a caller cannot accidentally conflate "we recovered onto the old
// image" (ESP32) with "we are stuck on the new image and must try again"
// (ESP8266), and the test suite asserts exactly that difference.
//
// A `markValid()` callback is NEVER invoked on a timeout, on either platform: a
// trial that was not confirmed must never be promoted to bootable just because
// the clock ran out. `rollback()` is likewise invoked at most once, only on the
// ESP32 expiry path.
//
// ---------------------------------------------------------------------------
// Seams, and why this is a header-only, allocation-free state machine
// ---------------------------------------------------------------------------
//
// Like the rest of this SDK, nothing here talks to a bootloader, a chip or a
// clock directly. All three are injected:
//
//   * `Platform` — ESP32 vs ESP8266, the one input that selects the expiry
//     outcome. Injected (not #ifdef'd) so BOTH behaviours are provable on the
//     host in one binary; firmware passes its own value.
//   * `Clock` — a monotonic millisecond counter (`millis()` in firmware). Read,
//     never waited on: poll() is non-blocking and total, so it is safe to call
//     from loop() without stalling the watchdog.
//   * `markValid` / `rollback` — plain C function pointers, the seam style used
//     throughout this SDK. Either may be null: a null `markValid` means "there
//     is no bootloader flag to set" (marking is skipped, `confirm()` still
//     succeeds), and a null `rollback` on the ESP32 expiry path is handled
//     WITHOUT a null call, so the runner can never crash or panic on the
//     rollback path — there is no dereference of an absent seam, no assert, no
//     abort, and no exception. That is INV-O4's "never panics on the rollback
//     path", and it is why poll() cannot take the device down while it is
//     already trying to recover from a bad image.
//
// The class holds only POD state and needs no heap, so it is safe to construct
// in static storage at boot.
class InsightOtaRunner {
 public:
  // Which part this build runs on. The value selects the expiry outcome only;
  // everything before the deadline behaves identically on both.
  enum Platform {
    ESP32,    // two-slot, bootloader rollback available -> rolledBack on expiry
    ESP8266   // no two-slot, no rollback -> reattemptRequired on expiry
  };

  // Where the two-phase state machine stands. `Trial` is the only state with a
  // pending deadline; `Confirmed` and `RolledBack` are terminal (a confirmed
  // trial is never rolled back, and a rolled-back one is never confirmed).
  //
  // `ReattemptRequired` is intentionally NOT terminal in the same way: it says
  // the trial expired but no rollback was possible, so the caller owns the next
  // move. It is a distinct outcome from `RolledBack` by design (INV-O4).
  enum State {
    Idle,               // nothing armed yet (the state after construction)
    Trial,              // flashed, running on probation, awaiting confirm()
    Confirmed,          // confirm() arrived in time; markValid() was called
    RolledBack,         // ESP32 trial expired -> rollback() called
    ReattemptRequired   // ESP8266 trial expired -> no rollback possible
  };

  // Mark the running trial image as valid/bootable. Returns true on success.
  // Cancel/rollback semantics are the platform's; a null pointer means "no
  // bootloader flag exists" and is treated as a successful no-op.
  typedef bool (*MarkValidCallback)();

  // Revert to the previous image (ESP32's two-slot rollback). Returns true on
  // success. A null pointer means rollback is unavailable on this target; the
  // runner never calls through it.
  typedef bool (*RollbackCallback)();

  // Monotonic millisecond clock; may wrap (unsigned 32-bit semantics). A null
  // clock reads as a constant zero, which is safe but freezes the deadline.
  typedef unsigned long (*Clock)();

  // Confirmation window default: a trial not confirmed within this many
  // milliseconds is expired. Deliberately generous relative to boot time —
  // the cost of a slightly late rollback is far below the cost of rolling back
  // a good image that merely booted slowly.
  static const unsigned long kDefaultConfirmTimeoutMillis = 30000UL;

  // Construct idle with no seams: ESP32 platform, default confirm window, all
  // callbacks null. Useful as a placeholder before `begin()`.
  InsightOtaRunner()
      : platform_(ESP32), confirmTimeout_(kDefaultConfirmTimeoutMillis),
        markValid_(0), rollback_(0), clock_(0), state_(Idle), trialStartMs_(0),
        markValidCalls_(0), rollbackCalls_(0), expireCount_(0), nowMs_(0) {}

  // Construct armed for a platform. `markValid`/`rollback`/`clock` may be null;
  // see the class comment. `confirmTimeoutMillis == 0` selects the default.
  InsightOtaRunner(Platform platform, MarkValidCallback markValid,
                   RollbackCallback rollback, Clock clock,
                   unsigned long confirmTimeoutMillis =
                       kDefaultConfirmTimeoutMillis)
      : platform_(platform),
        confirmTimeout_(confirmTimeoutMillis ? confirmTimeoutMillis
                                             : kDefaultConfirmTimeoutMillis),
        markValid_(markValid), rollback_(rollback), clock_(clock), state_(Idle),
        trialStartMs_(0), markValidCalls_(0), rollbackCalls_(0), expireCount_(0),
        nowMs_(0) {}

  // --- injected seams ----------------------------------------------------
  // Installing a seam after arm() is fine: the expiry path reads `rollback_`
  // and `platform_` at the moment it runs, not at arm time, so late wiring is
  // honoured. Null detaches a seam; see the class comment for the semantics.
  void setPlatform(Platform platform) { platform_ = platform; }
  Platform platform() const { return platform_; }

  void setMarkValid(MarkValidCallback markValid) { markValid_ = markValid; }
  MarkValidCallback markValid() const { return markValid_; }

  void setRollback(RollbackCallback rollback) { rollback_ = rollback; }
  RollbackCallback rollback() const { return rollback_; }

  void setClock(Clock clock) { clock_ = clock; }
  Clock clock() const { return clock_; }

  // Confirmation window in milliseconds; 0 restores the default. Changing it
  // while a trial is pending re-arms the deadline from the ORIGINAL trial start
  // (armedAtMillis()), so the window can never be silently extended by
  // reconfiguring it mid-trial — expiry stays deterministic.
  void setConfirmTimeout(unsigned long millis) {
    confirmTimeout_ = millis ? millis : kDefaultConfirmTimeoutMillis;
  }
  unsigned long confirmTimeout() const { return confirmTimeout_; }

  // --- phase 1: arm after flash -----------------------------------------
  // Record that a new image was flashed and is now on probation. The state
  // becomes `trial` and the confirmation deadline is `now + confirmTimeout()`.
  // Idempotent by replacement: re-arming restarts the window from the new
  // call's clock reading, which is what a re-flash means. No seam is invoked
  // here — arming marks nothing valid; only confirm() can.
  void arm() {
    nowMs_ = readClock();
    trialStartMs_ = nowMs_;
    state_ = Trial;
  }

  // --- phase 2, first outcome: confirm ----------------------------------
  // The application came up healthy. Calls `markValid()` ONCE when one is
  // installed, then records `confirmed`. Ordering is deliberate: the state
  // flips only after markValid() returns, so an observer never sees `confirmed`
  // for a trial whose flag was not actually set. A null markValid is a
  // successful no-op (nothing to mark), and confirming an already-confirmed
  // trial is idempotent: the second call does NOT re-invoke markValid().
  //
  // Confirming a non-trial state (Idle, RolledBack, ReattemptRequired) is a
  // safe no-op that returns false: a rolled-back trial can never be resurrected
  // into `confirmed` by a late confirm().
  bool confirm() {
    if (state_ != Trial) {
      return false;
    }
    bool ok = true;
    if (markValid_ != 0) {
      ok = markValid_();
      ++markValidCalls_;
    }
    state_ = Confirmed;
    return ok;
  }

  // --- phase 2, second outcome: expiry, via poll ------------------------
  // Non-blocking and total: samples the clock at most once, and does nothing at
  // all unless a trial is pending AND the deadline has been reached. Returns
  // true when THIS call performed the expiry transition (the first poll at or
  // past the deadline), so a caller can log it exactly once; a no-op poll
  // returns false.
  //
  // Deadline rule: expiration happens when `now - armedAt >= confirmTimeout`.
  // The comparison is `>=`, so EXACTLY `confirmTimeout` milliseconds after
  // arming IS expired — the boundary is inclusive and therefore deterministic:
  // poll(arm + N) expires, poll(arm + N - 1) does not. Elapsed time is computed
  // by unsigned subtraction, so it survives a `millis()` rollover.
  //
  // On the ESP32 path it calls `rollback()` (at most once, and NOT AT ALL if no
  // rollback seam is installed) and lands in `rolledBack`. On the ESP8266 path
  // it calls NOTHING and lands in `reattemptRequired`, because there is no
  // two-slot rollback to perform. Neither path can crash: no absent seam is
  // dereferenced, and no failure return from `rollback()` is escalated.
  bool poll() {
    if (state_ != Trial) {
      return false;
    }
    nowMs_ = readClock();
    if (elapsed() < confirmTimeout_) {
      return false;
    }
    expire();
    return true;
  }

  // Convenience for a caller that already has the clock: sample-free form of
  // poll() for a fixed `nowMillis`. Same rules, including the inclusive
  // boundary. Used by tests to make the boundary exact without re-reading a
  // live clock.
  bool pollAt(unsigned long nowMillis) {
    if (state_ != Trial) {
      return false;
    }
    nowMs_ = nowMillis;
    if (elapsed() < confirmTimeout_) {
      return false;
    }
    expire();
    return true;
  }

  // --- inspection --------------------------------------------------------
  State state() const { return state_; }

  bool isTrial() const { return state_ == Trial; }
  bool isConfirmed() const { return state_ == Confirmed; }
  bool isRolledBack() const { return state_ == RolledBack; }
  bool isReattemptRequired() const { return state_ == ReattemptRequired; }

  // True when the trial's confirmation window has closed (state is terminal on
  // both platforms: rolledBack or reattemptRequired).
  bool isExpired() const {
    return state_ == RolledBack || state_ == ReattemptRequired;
  }

  // millis() at which the armed trial began, or 0 before any arm().
  unsigned long armedAtMillis() const { return trialStartMs_; }

  // Deadline of the current/last trial, in the clock's millis() domain. Only
  // meaningful while a trial has been armed at least once.
  unsigned long deadlineMillis() const {
    return trialStartMs_ + confirmTimeout_;
  }

  // Milliseconds elapsed since arm() AS OF NOW: this samples the clock rather
  // than reporting a stale reading, so a caller (or a test) can ask "how far
  // into the window are we?" without having to poll first. Zero before any
  // arm(), and frozen at the trial's final reading once the state is terminal
  // (the clock is no longer consulted for a trial that is over).
  unsigned long elapsedMillis() const {
    if (state_ == Idle) {
      return 0UL;
    }
    if (state_ != Trial) {
      return nowMs_ - trialStartMs_;
    }
    return readClock() - trialStartMs_;
  }

  // How many times each seam was called, over the runner's lifetime. `markValid`
  // is capped at one per successful confirm of a distinct trial, and `rollback`
  // at one per ESP32 expiry — both counters exist so the tests can prove the
  // "exactly once / never" properties instead of asserting them.
  unsigned long markValidCalls() const { return markValidCalls_; }
  unsigned long rollbackCalls() const { return rollbackCalls_; }

  // Number of expiry transitions performed (0 or 1 per armed trial).
  unsigned long expireCount() const { return expireCount_; }

  // The most recent clock reading the runner took (for diagnostics only).
  unsigned long now() const { return nowMs_; }

 private:
  unsigned long readClock() const {
    return clock_ == 0 ? 0UL : static_cast<unsigned long>(clock_());
  }

  unsigned long elapsed() const { return nowMs_ - trialStartMs_; }

  // The single expiry transition, shared by poll() and pollAt(). Branches on
  // the platform and is careful about every seam being optional.
  void expire() {
    ++expireCount_;
    if (platform_ == ESP8266) {
      // No two-slot layout: nothing to roll back to. Do NOT call rollback()
      // (there may not be one) and do NOT report rolledBack — the outcome is
      // explicitly reattemptRequired so the caller knows recovery is on it.
      state_ = ReattemptRequired;
      return;
    }
    // ESP32: the two-slot bootloader can be pointed back at the previous image.
    // A missing rollback seam is not an error here — we simply have no bootloader
    // to talk to, and the state transition is still recorded. The seam is never
    // called when absent, and a false return is not escalated into a panic.
    if (rollback_ != 0) {
      rollback_();
      ++rollbackCalls_;
    }
    state_ = RolledBack;
  }

  Platform platform_;
  unsigned long confirmTimeout_;

  MarkValidCallback markValid_;
  RollbackCallback rollback_;
  Clock clock_;

  State state_;
  unsigned long trialStartMs_;

  unsigned long markValidCalls_;
  unsigned long rollbackCalls_;
  unsigned long expireCount_;
  unsigned long nowMs_;
};

}  // namespace insight

// Restore the target macros saved at the top of this header, so a sketch (or
// any other header) that tests `defined(ESP32)` after including Insight.h still
// sees the platform its toolchain reported.
#ifdef INSIGHT_OTA_RUNNER_SAVED_ESP32
#define ESP32 INSIGHT_OTA_RUNNER_ESP32_VALUE
#undef INSIGHT_OTA_RUNNER_SAVED_ESP32
#undef INSIGHT_OTA_RUNNER_ESP32_VALUE
#endif
#ifdef INSIGHT_OTA_RUNNER_SAVED_ESP8266
#define ESP8266 INSIGHT_OTA_RUNNER_ESP8266_VALUE
#undef INSIGHT_OTA_RUNNER_SAVED_ESP8266
#undef INSIGHT_OTA_RUNNER_ESP8266_VALUE
#endif

#endif  // INSIGHT_OTA_RUNNER_H
