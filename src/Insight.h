#ifndef INSIGHT_H
#define INSIGHT_H

#ifdef ARDUINO
#include <Arduino.h>
#endif

#include "InsightTransport.h"

namespace insight {

// Minimal foundation stub. The real client is layered on top of the
// transport seam declared in InsightTransport.h.
class Insight {
 public:
  Insight() : transport_(0) {}
  ~Insight() {}

  // Returns true once the client has been initialised. Kept trivial for
  // the foundation milestone so native smoke tests can link it.
  bool begin() { return true; }

  // Install the transport the client routes its requests through. Passing
  // null detaches it. Does not take ownership.
  void setTransport(InsightTransport* transport) { transport_ = transport; }

  // The transport currently installed, or null when detached.
  InsightTransport* transport() const { return transport_; }

  // POST `json` to `path` through the installed transport. Without a
  // transport this reports a transport-level error rather than crashing.
  HttpOutcome post(const char* path, const char* json) {
    if (transport_ == 0) {
      return HttpOutcome::error();
    }
    return transport_->postJson(path, json);
  }

  // GET `path` into `buffer` through the installed transport.
  HttpOutcome get(const char* path, char* buffer, size_t bufferLen) {
    if (transport_ == 0) {
      return HttpOutcome::error();
    }
    return transport_->get(path, buffer, bufferLen);
  }

 private:
  InsightTransport* transport_;
};

}  // namespace insight

#endif  // INSIGHT_H
