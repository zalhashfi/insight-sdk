#ifndef INSIGHT_H
#define INSIGHT_H

#ifdef ARDUINO
#include <Arduino.h>
#endif

namespace insight {

// Minimal foundation stub. The real client is layered on top of the
// transport seam declared in InsightTransport.h.
class Insight {
 public:
  Insight() {}
  ~Insight() {}

  // Returns true once the client has been initialised. Kept trivial for
  // the foundation milestone so native smoke tests can link it.
  bool begin() { return true; }
};

}  // namespace insight

#endif  // INSIGHT_H
