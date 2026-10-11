#ifndef INSIGHT_RELIABILITY_H
#define INSIGHT_RELIABILITY_H

#include <cstdint>

#include "InsightTransport.h"

namespace insight {

// Longest wait between two retries: 30 seconds. Kept as a shared constant so
// the policy below and its callers cannot drift apart.
const uint32_t kBackoffMaxMillis = 30000;

// Bounded exponential backoff delay, in milliseconds, for a 0-based retry
// `attempt`:
//
//   attempt: 0     1     2     3      4      5      6      ... 100  ...
//   millis:  1000  2000  4000  8000  16000  30000  30000  ... 30000 ...
//
// i.e. 1000 * 2^attempt, clamped to kBackoffMaxMillis (30s). The delay never
// exceeds the cap, for any attempt, including the negative/overflow edges.
//
// This returns a DURATION and nothing else: it is a pure function of `attempt`
// with no I/O and no side effects. In particular it NEVER sleeps or blocks —
// there is no delay()/sleep()/delayMicroseconds() call anywhere in this header,
// so it is safe to call from an interrupt-adjacent or watchdog-sensitive path.
// Scheduling the wait is the caller's job: capture millis() when the attempt
// fails, re-issue the request once millis() - start >= backoffMillis(attempt),
// and keep the loop non-blocking so the watchdog stays fed.
inline uint32_t backoffMillis(uint32_t attempt) {
  uint32_t delayMillis = 1000u;

  // Double per attempt. Stop once the value would reach (or pass) the cap, so
  // neither a huge `attempt` nor the `1000 * 2^attempt` multiply can overflow:
  // 32 attempts would need 2^32 ms of headroom, which is past the cap anyway.
  for (uint32_t i = 0; i < attempt && delayMillis < kBackoffMaxMillis; ++i) {
    delayMillis *= 2u;
  }

  // Clamp. The loop above never overshoots by much, but clamping here makes
  // "never exceeds the cap" a property of the function itself, not of the loop.
  if (delayMillis > kBackoffMaxMillis) {
    delayMillis = kBackoffMaxMillis;
  }
  return delayMillis;
}

// What the caller should do with the outcome of a single transport attempt.
//
//   Success - the server accepted the request (2xx); move on.
//   Retry   - the failure is transient: try exactly the same request again.
//   Discard - the failure is permanent: retrying will not help, drop the
//             request (and surface/log the rejection).
enum class Decision { Success, Retry, Discard };

// Pure classification of a transport outcome into a retry decision.
//
// Deliberately side-effect free and dependency free: it looks only at the
// HttpOutcome passed in, so both firmware and native tests can share it and
// the retry policy (backoff, caps) can be layered on top by the caller.
//
// Rules (see spec §6.1):
//   * Ok + 2xx                     -> Success
//   * Ok + 408 / 429 / 5xx         -> Retry   (transient server-side)
//   * Ok + any other 4xx           -> Discard (permanent client error)
//   * Ok + anything else (1xx/3xx/0) -> Discard (unexpected; not retryable)
//   * Timeout / Error              -> Retry   (no server verdict yet)
inline Decision decide(const HttpOutcome& outcome) {
  switch (outcome.kind) {
    case HttpOutcome::Timeout:
    case HttpOutcome::Error:
      // No server verdict was received; the request never got a fair chance.
      return Decision::Retry;

    case HttpOutcome::Ok:
    default:
      break;
  }

  const int status = outcome.status;

  // 2xx: accepted.
  if (status >= 200 && status < 300) {
    return Decision::Success;
  }

  // Transient server-side failures worth repeating verbatim.
  if (status == 408 || status == 429 || (status >= 500 && status <= 599)) {
    return Decision::Retry;
  }

  // Everything else — other 4xx, 1xx, 3xx, and the degenerate 0 — is a
  // definitive "this request will not succeed" answer: discard it.
  return Decision::Discard;
}

}  // namespace insight

#endif  // INSIGHT_RELIABILITY_H
