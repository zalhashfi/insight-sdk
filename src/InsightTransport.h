#ifndef INSIGHT_TRANSPORT_H
#define INSIGHT_TRANSPORT_H

#include <cstddef>

namespace insight {

// Result of a single transport operation. Richer than a bool so callers can
// distinguish a real server reply (and inspect its HTTP status) from a
// timeout and from any other transport-level error.
struct HttpOutcome {
  enum Kind {
    Ok,       // A server response was received; `status` is meaningful.
    Timeout,  // No response within the transport's deadline.
    Error     // Transport-level failure (DNS, socket, TLS, ...).
  };

  Kind kind;
  int status;  // HTTP status code; only meaningful when kind == Ok.

  HttpOutcome() : kind(Error), status(0) {}
  HttpOutcome(Kind k, int httpStatus = 0) : kind(k), status(httpStatus) {}

  static HttpOutcome ok(int httpStatus) { return HttpOutcome(Ok, httpStatus); }
  static HttpOutcome timeout() { return HttpOutcome(Timeout, 0); }
  static HttpOutcome error() { return HttpOutcome(Error, 0); }
};

// Abstract transport seam. Deliberately minimal: exactly two operations.
// - POST a JSON body to a path.
// - GET a path into a caller-supplied buffer.
// No websocket, no streaming, no other verbs.
class InsightTransport {
 public:
  virtual ~InsightTransport() {}

  // POST `json` to `path`. Reports the outcome of the attempt.
  virtual HttpOutcome postJson(const char* path, const char* json) = 0;

  // GET `path` into `buffer` of `bufferLen` bytes (null-terminated on
  // success). Reports the outcome of the attempt; `buffer` is only filled
  // on a response.
  //
  // `contentLength`, when non-null, receives the number of BODY bytes the
  // response delivered, independent of any NUL terminator. A TEXT body (for
  // example a JSON envelope) may be measured with strlen(); an OPAQUE body —
  // a firmware image — may contain NUL bytes and MUST be measured with this
  // count, which is exactly why the seam exposes it. On a non-OK outcome the
  // count is left at 0.
  virtual HttpOutcome get(const char* path, char* buffer, size_t bufferLen,
                          size_t* contentLength = 0) = 0;
};

}  // namespace insight

#endif  // INSIGHT_TRANSPORT_H
