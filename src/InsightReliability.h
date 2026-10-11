#ifndef INSIGHT_RELIABILITY_H
#define INSIGHT_RELIABILITY_H

#include "InsightTransport.h"

namespace insight {

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
