#ifndef INSIGHT_WIFI_H
#define INSIGHT_WIFI_H

namespace insight {

// A single connection attempt outcome.
enum class WifiResult {
  Connected,  // The station is associated; stop retrying.
  Failed,     // Attempt did not connect (credentials, AP absent, auth, ...).
  Timeout     // Attempt itself timed out at the radio/stack level.
};

// Wi-Fi association with an explicit, bounded deadline.
//
// Nothing here talks to a radio directly: the two things that make Wi-Fi
// untestable on a host — the blocking connect call and the passage of time —
// are injected as seams. `connectAttempt` performs one connection attempt and
// reports whether it succeeded; `clock` returns a monotonic millisecond
// counter. Production code passes the platform's real connect routine and
// Arduino `millis()` (or `std::chrono`); tests pass deterministic doubles.
//
// Both seams may be null. A null `connectAttempt` models a device whose radio
// is absent/unavailable: every attempt fails. A null `clock` freezes time at
// zero, so a bounded request makes its first attempt and then gives up (the
// frozen clock can never advance the deadline); it is the unbounded call that
// a null clock pairs with, where the wait lasts until an attempt succeeds.
//
// Bounding rules — the whole point of this class:
//
//   * `connectWiFi(timeoutMs)` waits at most `timeoutMs` milliseconds before
//     giving up. Each iteration samples the clock once and compares the elapsed
//     time (by unsigned subtraction, so it survives a `millis()` rollover)
//     against the deadline; the window is inclusive, so the loop ends exactly
//     at `timeoutMs`. A bounded request therefore always terminates: either the
//     clock advances to the deadline, or a sample comes back unchanged, which
//     proves the clock cannot drive the deadline forward and the loop stops
//     rather than busy-spinning. The first attempt is always made, so a real
//     connect call is never skipped just because no time has passed yet.
//
//   * `begin(maxAttempts)` performs at most `maxAttempts` connection attempts
//     and returns true as soon as one connects, false once the budget is
//     spent. This is the count-bounded knob for callers that prefer a fixed
//     number of retries over a wall-clock window. It never consults the clock,
//     so it terminates on attempt count alone.
//
//   * Unbounded operation is explicit and opt-in, never the default. Passing
//     `timeoutMs == 0` to `connectWiFi` or `maxAttempts == 0` to `begin`
//     removes that particular bound: the call then blocks until an attempt
//     finally succeeds. This is the documented escape hatch for boot/recovery
//     paths where the device must associate before continuing, and it is only
//     safe when the caller knows it — with a seam that never connects the call
//     simply never returns. Because an unbounded call is an explicit choice
//     rather than something the library does behind its back, a bounded
//     request is always the safer default, and is what the defaults select.
class InsightWifi {
 public:
  // One connection attempt. Must not block past its own radio deadline; must
  // return promptly on failure so the caller keeps control of the loop.
  typedef WifiResult (*ConnectAttempt)();

  // Monotonic millisecond clock. May wrap (unsigned 32-bit semantics). A null
  // clock is read as a constant zero (time frozen): a bounded request then
  // performs its single first attempt and gives up, since the frozen clock can
  // never advance the deadline (see the busy-loop guard below).
  typedef unsigned long (*Clock)();

  // Construct detached with no seams: every attempt fails and time is frozen.
  InsightWifi() : connectAttempt_(0), clock_(0) {}

  // Construct with both seams installed. Either may be null; see the class
  // comment for what a null seam implies.
  InsightWifi(ConnectAttempt connectAttempt, Clock clock)
      : connectAttempt_(connectAttempt), clock_(clock) {}

  // Install / inspect the injected seams. Passing null detaches a seam; see
  // the class comment for what that implies.
  void setConnectAttempt(ConnectAttempt connectAttempt) {
    connectAttempt_ = connectAttempt;
  }
  ConnectAttempt connectAttempt() const { return connectAttempt_; }

  void setClock(Clock clock) { clock_ = clock; }
  Clock clock() const { return clock_; }

  // Connect, giving up after at most `timeoutMs` milliseconds.
  //
  // Returns true if an attempt connected within the window, false if the
  // deadline was reached first. `timeoutMs == 0` is the explicit opt-in to an
  // unbounded wait: it does not return until an attempt succeeds (and never
  // returns at all if nothing ever connects). Passing 0 is deliberate; the
  // default is bounded.
  bool connectWiFi(unsigned long timeoutMs = 30000) {
    attempts_ = 0;
    const unsigned long start = now();
    unsigned long previous = start;

    for (;;) {
      if (attemptOnce()) {
        return true;
      }
      if (timeoutMs == 0) {
        continue;  // Unbounded, explicit opt-in: retry until success.
      }
      // Sample the clock once per iteration and measure elapsed against the
      // start (unsigned subtraction keeps this correct across a millis()
      // rollover). The window is inclusive of `timeoutMs`: elapsed >= timeoutMs
      // means the deadline is reached, so no further attempt is made.
      const unsigned long sample = now();
      if (sample - start >= timeoutMs) {
        return false;
      }
      // A monotonic clock that has not advanced since the previous sample
      // cannot ever make progress against a deadline, so another pass would
      // spin forever. Give up instead of busy-looping; this is the guard that
      // keeps a bounded request bounded even with a stalled or frozen clock.
      if (sample == previous) {
        return false;
      }
      previous = sample;
    }
  }

  // Connect, trying at most `maxAttempts` attempts.
  //
  // Returns true as soon as an attempt connects, false once all attempts have
  // failed. `maxAttempts == 0` is the explicit opt-in to an unbounded wait:
  // it does not return until an attempt succeeds. `maxAttempts == 1` performs
  // exactly one attempt (a plain single-shot connect).
  bool begin(unsigned long maxAttempts = 3) {
    attempts_ = 0;
    for (unsigned long attempt = 0;; ++attempt) {
      if (attemptOnce()) {
        return true;
      }
      if (maxAttempts == 0) {
        continue;  // Unbounded, explicit opt-in: retry until success.
      }
      if (attempt + 1 >= maxAttempts) {
        return false;
      }
    }
  }

  // Number of attempts issued by the most recent connectWiFi()/begin() call.
  // Observable so tests can pin the exact attempt count the bounds imply.
  unsigned long attempts() const { return attempts_; }

 private:
  bool attemptOnce() {
    ++attempts_;
    if (connectAttempt_ == 0) {
      return false;  // No radio seam installed: the attempt cannot connect.
    }
    return connectAttempt_() == WifiResult::Connected;
  }

  unsigned long now() const { return clock_ == 0 ? 0 : clock_(); }

  ConnectAttempt connectAttempt_;
  Clock clock_;
  unsigned long attempts_ = 0;
};

}  // namespace insight

#endif  // INSIGHT_WIFI_H
