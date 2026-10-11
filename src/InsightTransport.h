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

  // Which of the three outcomes this is.
  Kind kind;
  int status;  // HTTP status code; only meaningful when kind == Ok.

  // Default-construct an Error outcome (status 0) — the safe "no reply" state.
  HttpOutcome() : kind(Error), status(0) {}
  // Construct an explicit outcome; `httpStatus` matters only for Ok.
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

  // GET `path` into `buffer` of `bufferLen` bytes. Reports the outcome of the
  // attempt; `buffer` is only filled on a response.
  //
  // `contentLength`, when non-null, receives the number of BODY bytes the
  // response delivered, independent of any NUL terminator. A TEXT body (for
  // example a JSON envelope) may be measured with strlen(); an OPAQUE body —
  // a firmware image — may contain NUL bytes and MUST be measured with this
  // count, which is exactly why the seam exposes it. On a non-OK outcome the
  // count is left at 0.
  //
  // The buffer is filled with AT MOST `bufferLen` body bytes and is NOT
  // null-terminated when the body may fill it (an opaque image can be exactly
  // `bufferLen` bytes). An adapter that serves a text body and wants
  // null-termination MUST terminate it itself, keeping one byte spare; a caller
  // that parses text (e.g. the JSON offer) MUST provide a zeroed buffer and
  // rely on `contentLength`, as {@link InsightOta} does.
  virtual HttpOutcome get(const char* path, char* buffer, size_t bufferLen,
                          size_t* contentLength = 0) = 0;
};

}  // namespace insight

#endif  // INSIGHT_TRANSPORT_H
