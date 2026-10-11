#ifndef INSIGHT_DEVICE_H
#define INSIGHT_DEVICE_H

#include <cstddef>
#include <cstring>

namespace insight {

// ---------------------------------------------------------------------------
// Frozen header names (device ingress)
// ---------------------------------------------------------------------------
//
// Byte-for-byte identical to `CONTRACT_HEADERS` in the frozen lock
// (`insight/test/contracts/contract-lock.ts`): both names are LOWERCASE, and
// even the CLI overrides in pio accept only these exact bytes. The mirror test
// `insight-sdk/test/test_identity/test_main.cpp` (and, cross-repo,
// `insight/test/contracts/mirror.test.ts`) hold this side to the lock so a
// one-sided rename fails rather than silently shipping a header the server
// ignores, because HTTP field names are case-insensitive on the wire but the
// lock — the tripwire — is not.
//
//   * `x-insight-device`   — the sending device's key (FR-DEV-03).
//   * `x-insight-firmware` — the RUNNING firmware version (FR-SDK-08).
const char* const kDeviceHeaderName = "x-insight-device";
const char* const kFirmwareHeaderName = "x-insight-firmware";

// ---------------------------------------------------------------------------
// The OTA route
// ---------------------------------------------------------------------------
//
// `x-insight-firmware` accompanies OTA requests only — the frozen
// `GET_OTA.headers` lists `[authorization, firmware]` while every plain
// request (`POST_TELEMETRY.headers`) lists `[authorization, device]`. The
// check is deliberately *prefix*-based rather than an exact compare against
// "/v1/ota": the OTA read surface and its image download
// (`/v1/ota`, `/v1/ota/image`) both describe the running firmware, and spec
// §6.4/§6.5 freeze them under one path family. Since the router uses a path
// *prefix* here, the firmware header is attached to the whole `/v1/ota`
// subtree, which is the broader, correct reading. The `/v1` segment is
// required, so an unrelated path that merely ends in "ota" is not treated as
// OTA.
inline bool isOtaPath(const char* path) {
  if (path == 0) return false;
  return std::strncmp(path, "/v1/ota", 7) == 0;
}

// Longest firmware version the ingress will accept in `x-insight-firmware`.
// Matches the SDK-side cap recorded in the plan (B07): versions longer than
// this are truncated on the wire rather than rejected.
const size_t kMaxFirmwareVersionLength = 32;

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------
//
// The SDK's answer to "what do I put on the wire to say who I am?". It is a
// pure, standard-C++ description of the two identity headers; it holds NO
// transport and performs NO I/O, so it is fully testable on the host and can
// be shared by every request path. The class is named `DeviceIdentity` (not
// `InsightDevice`) so it does not collide with the frozen header filename.
//
// Attaching is two headers, never zero and never empty:
//   * `x-insight-device` is emitted on EVERY request, provided a device key has
//     been set. An unset key is reported as absent, so a caller cannot
//     transmit an empty header that the ingress would silently collapse to the
//     default `"unknown"` device (spec §6.1) — leaving the device anonymous
//     under a name two devices could share.
//   * `x-insight-firmware` is emitted only when the running firmware version
//     is BOTH non-empty AND the request targets the OTA route. An empty
//     version OMITS the header entirely (it is never sent as `""`), which
//     matches the ingress contract: `{"update":null}` is the answer to a
//     device that does not — or cannot — report its version.
//
// Overlong versions are truncated to kMaxFirmwareVersionLength bytes rather
// than refused, so a long build stamp still identifies the firmware.
class DeviceIdentity {
 public:
  DeviceIdentity() { deviceKey_[0] = '\0'; firmwareVersion_[0] = '\0'; }

  // Install the device key sent as `x-insight-device` on every request.
  // Passing null (or an empty string) clears it and suppresses the header.
  // Stored truncated to the ingress limit so the wire form is stable.
  void setDeviceKey(const char* key) {
    copyBounded(deviceKey_, sizeof(deviceKey_), key, 0);
  }

  // The device key as it would go on the wire, or "" when unset/cleared.
  const char* deviceKey() const { return deviceKey_; }

  // Install the RUNNING firmware version sent as `x-insight-firmware` on OTA
  // requests. Passing null (or an empty string) clears it; the header is then
  // omitted even on OTA requests.
  void setFirmwareVersion(const char* version) {
    copyBounded(firmwareVersion_, sizeof(firmwareVersion_), version,
                kMaxFirmwareVersionLength);
  }

  // The firmware version as it would go on the wire, truncated to
  // kMaxFirmwareVersionLength bytes, or "" when unset/cleared.
  const char* firmwareVersion() const { return firmwareVersion_; }

  // True when a device key is set, i.e. `x-insight-device` will be attached.
  bool hasDeviceKey() const { return deviceKey_[0] != '\0'; }

  // True when `x-insight-firmware` will be attached to a request for `path`:
  // an OTA request with a non-empty firmware version.
  bool hasFirmwareHeader(const char* path) const {
    return isOtaPath(path) && firmwareVersion_[0] != '\0';
  }

 private:
  // Copy `src` into a fixed buffer, null-terminated and truncated to
  // `maxLen` bytes (0 = as many as the buffer holds). A null `src` clears.
  static void copyBounded(char* dst, size_t dstLen, const char* src,
                          size_t maxLen) {
    if (dst == 0 || dstLen == 0) return;
    dst[0] = '\0';
    if (src == 0) return;

    const size_t room = dstLen - 1;
    size_t limit = (maxLen == 0 || maxLen > room) ? room : maxLen;
    size_t i = 0;
    for (; i < limit && src[i] != '\0'; ++i) {
      dst[i] = src[i];
    }
    dst[i] = '\0';
  }

  // Sized to hold the full wire value plus the terminator. `deviceKey_` may
  // hold the ingress limit (128) so `deviceKey()` round-trips what the server
  // would persist; `firmwareVersion_` need only hold the 32-byte cap.
  char deviceKey_[129];
  char firmwareVersion_[kMaxFirmwareVersionLength + 1];
};

}  // namespace insight

#endif  // INSIGHT_DEVICE_H
