#ifndef INSIGHT_TLS_H
#define INSIGHT_TLS_H

namespace insight {

// TLS certificate-verification POLICY.
//
// The device talks to the backend over HTTPS. Verifying the server certificate
// is what stops a man-in-the-middle from impersonating it, and a certificate
// cannot be trusted until there is *time* to evaluate it against: an
// unsynced (epoch-0) clock reads every certificate as "not yet valid", and a
// caller that "works around" that by disabling verification silently has
// turned a time problem into a security hole. This header encodes the opposite
// rule: the SECURE mode is the only thing reachable without an explicit,
// deliberate, debug-only opt-out, and even that opt-out is refused whenever the
// build reports itself as production.
//
// Two independent gates, both decided here rather than left to callers:
//
//   1. Mode gate — `setInsecure()` succeeds only when the build is NOT
//      production. In production it is refused outright and the mode stays
//      `Secure`, so no configuration path can weaken a shipped device. The
//      refusal is reported as a `PolicyResult`, never as a silent success.
//
//   2. Ordering gate — certificate validation requires SNTP time to already be
//      synced. `canValidateTls()` is the predicate: false while the clock is
//      unsynced, true once `setTimeSynced(true)` reports an SNTP sync. Nothing
//      here quietly substitutes an insecure decision for the unsynced case; it
//      signals "must sync time first" and refuses.
//
// Both facts the policy depends on — whether the build is production, and
// whether SNTP has synced — are injected seams, following the rest of the SDK,
// so the whole policy is exercisable on a host with no network, no TLS stack
// and no hardware clock.

// Security mode requested for the TLS client.
//
//   Secure   — verify the server certificate. The default, and the only mode a
//              production build will accept.
//   Insecure — skip certificate verification. A DEBUG-ONLY escape hatch for
//              bring-up on a device without a synced clock or without a CA
//              bundle. It can never be enabled in a production build (see
//              `setInsecure()`), and it is never selected implicitly.
enum class TlsMode { Secure, Insecure };

// Outcome of a policy call that can be refused. Richer than a bool so callers
// can tell a legitimate state change from a rejected one and say why.
//
//   Ok                    — the requested state change was applied.
//   RejectedInProduction  — refused: the build is production, so no path may
//                           weaken verification. The mode is unchanged.
enum class TlsPolicyResult { Ok, RejectedInProduction };

// Certificate-verification policy with injected build/time seams.
//
// The object starts in the SAFE state for any use: mode `Secure` and time
// unsynced. Note the two defaults pull in opposite directions on purpose — the
// mode defaults to secure, while the time starts unsynced so that a caller who
// forgets to report a sync gets the ordering gate (a refusal) rather than a
// verification decision taken against a bogus clock.
class InsightTlsPolicy {
 public:
  // `isProduction` is the build seam: true for a shipped/production build,
  // false for a debug/bring-up build. Production is the SAFE assumption, so it
  // is what a default-constructed policy (and a null seam) resolves to — a
  // policy that cannot tell where it is running must behave as production and
  // refuse the escape hatch.
  explicit InsightTlsPolicy(bool isProduction = true)
      : mode_(TlsMode::Secure),
        isProduction_(isProduction),
        timeSynced_(false) {}

  // The mode currently in force. Starts `Secure` and only ever changes on an
  // accepted `setInsecure()`; a refused request leaves it untouched.
  TlsMode mode() const { return mode_; }

  // Continue verifying the server certificate. Idempotent, always allowed, and
  // the way back from a debug opt-out. Returns Ok.
  TlsPolicyResult setSecure() {
    mode_ = TlsMode::Secure;
    return TlsPolicyResult::Ok;
  }

  // Request the DEBUG-ONLY insecure mode (skip verification).
  //
  // In a production build this is REFUSED: it returns
  // `TlsPolicyResult::RejectedInProduction` and leaves the mode `Secure`, so a
  // shipped device can never be downgraded. In a non-production build it is
  // accepted (returns Ok) and switches the mode to `Insecure` — the documented,
  // deliberate escape hatch.
  TlsPolicyResult setInsecure() {
    if (isProduction_) {
      return TlsPolicyResult::RejectedInProduction;
    }
    mode_ = TlsMode::Insecure;
    return TlsPolicyResult::Ok;
  }

  // Record whether SNTP time has synced. The result of the SNTP exchange is the
  // caller's to observe (this policy does no I/O); the caller reports it here.
  // A never-synced policy stays gated, which is the safe side of the ordering
  // gate.
  void setTimeSynced(bool synced) { timeSynced_ = synced; }

  // Ordering gate: may TLS certificate validation proceed *right now*? True
  // only once SNTP time has synced. While false, the correct action is to sync
  // time first ("must sync time first") and NOT to validate — and above all not
  // to fall back to skipping verification.
  bool canValidateTls() const { return timeSynced_; }

  // The verification decision for the current state, as a bool:
  //   true  — the client should verify the server certificate. This is the
  //           case only when the ordering gate is open (`canValidateTls()`).
  //   false — verification must not be treated as performed. Either the
  //           ordering gate is closed (time unsynced) or the mode was
  //           deliberately set Insecure when the build allowed it.
  //
  // The unsynced case returns false and nothing else: there is no code path
  // that converts a closed ordering gate into a *validated* decision. An
  // unsynced clock never yields a validated TLS outcome; it forces the caller
  // to sync time first.
  bool shouldVerifyCertificate() const {
    return canValidateTls() && mode_ == TlsMode::Secure;
  }

 private:
  TlsMode mode_;
  bool isProduction_;
  bool timeSynced_;
};

}  // namespace insight

#endif  // INSIGHT_TLS_H
