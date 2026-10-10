#ifndef INSIGHT_TRANSPORT_H
#define INSIGHT_TRANSPORT_H

#include <cstddef>

namespace insight {

// Abstract transport seam. Deliberately minimal: exactly two operations.
// - POST a JSON body to a path.
// - GET a path into a caller-supplied buffer.
// No websocket, no streaming, no other verbs.
class InsightTransport {
 public:
  virtual ~InsightTransport() {}

  // POST `json` to `path`. Returns true on success.
  virtual bool postJson(const char* path, const char* json) = 0;

  // GET `path` into `buffer` of `bufferLen` bytes (null-terminated on
  // success). Returns true on success.
  virtual bool get(const char* path, char* buffer, size_t bufferLen) = 0;
};

}  // namespace insight

#endif  // INSIGHT_TRANSPORT_H
