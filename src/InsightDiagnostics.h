#ifndef INSIGHT_DIAGNOSTICS_H
#define INSIGHT_DIAGNOSTICS_H

#include <cstddef>
#include <cstdint>

namespace insight {

// ---------------------------------------------------------------------------
// Optional per-flush diagnostics: RSSI + uptime
// ---------------------------------------------------------------------------
//
// Two facts make field failures diagnosable from the dashboard: how good the
// radio link was (RSSI, dBm) and how long the device has been up (uptime, ms).
// They are DIAGNOSTIC, not telemetry: an app reading temperature must not have
// two extra keys invented for it, and a device that never wired the feature on
// must not start paying for it. Hence the rule this header exists to enforce:
//
//   * DISABLED by default. A fresh InsightDiagnostics contributes NOTHING —
//     the payload is byte-for-byte what it was before — so this is a strictly
//     opt-in addition (FR-SDK-11) and existing sketches keep working.
//   * When ENABLED, both fields are appended together: the int RSSI and the ms
//     uptime. "Enabled" means "this device reports diagnostics", not "report
//     whichever metric happens to be set"; the session flags therefore gate
//     the whole pair, not each field.
//
// The payload is produced the same way the send policy produces its body — a
// tiny, dependency-free JSON writer, so the result is asserted on the host
// without pulling in ArduinoJson. The class owns no transport and does NO I/O:
// it only describes the fields and appends them, so a caller (a future client)
// stitches it into whatever envelope it already sends.

// Where the two fields sit in the payload. These are the FLAT telemetry keys
// (the same flat map `insight-internal/src/iot-sim` publishes and the ingress
// validates), not a nested object: a diagnostic rides as a sibling of the app
// metrics, addressed by the same key rules. Kept as named constants so the
// keys and the tests cannot drift.
inline const char* diagnosticsRssiKey() { return "rssi"; }
inline const char* diagnosticsUptimeKey() { return "uptime_ms"; }

// Capacity of the payload buffer appendJsonTo() writes into (including the NUL
// terminator). Like the send policy's body buffer, an over-long payload is
// TRUNCATED rather than allowed to run off the end: the writer stops at the
// last byte it can fit and still NUL-terminates. Sizing up is a compile-time
// define if a caller needs more room.
#ifndef INSIGHT_DIAGNOSTICS_JSON_MAX
#define INSIGHT_DIAGNOSTICS_JSON_MAX 128
#endif

// The same cap as a namespaced constant, so callers can size a buffer with
// `insight::kDiagnosticsJsonMax` (an enum/const can be qualified; a macro
// cannot). Kept in sync with the define above by construction.
const size_t kDiagnosticsJsonMax = INSIGHT_DIAGNOSTICS_JSON_MAX;

// Optional RSSI + uptime diagnostics, appended to a payload ONLY when enabled.
//
// The two flags are the whole on/off story and are independent of one another,
// because the two values have different "do I have one yet?" semantics:
//
//   * RSSI often may not be known at boot (the station is still associating);
//     it is an `int` where a NEGATIVE value is normal and any int is
//     representable, so no value can be pressed into service as "absent".
//   * Uptime is always known and may legitimately be 0.
//
// So enabling says "I intend to report diagnostics"; each field then follows
// its own flag. A field is written only when the feature is enabled AND that
// field's flag is set — which covers the boot window (diagnostics on, RSSI not
// sampled yet) without ever emitting a made-up RSSI.
class InsightDiagnostics {
 public:
  InsightDiagnostics()
      : enabled_(false),
        rssiEnabled_(false),
        uptimeEnabled_(false),
        rssi_(0),
        uptimeMs_(0) {}

  // Master switch. `on` false makes the object inert: hasAny() is false and
  // appendJsonTo() writes nothing, whatever the field flags or values say.
  void setEnabled(bool on) { enabled_ = on; }
  bool enabled() const { return enabled_; }

  // Report RSSI in dBm (a negative value on Wi-Fi; any int is accepted). Turn
  // it on with setRssiEnabled(true); setting the value does NOT turn it on, so
  // a caller cannot leak a field it did not intend to report.
  void setRssi(int dbm) { rssi_ = dbm; }
  void setRssiEnabled(bool on) { rssiEnabled_ = on; }
  bool rssiEnabled() const { return rssiEnabled_; }
  int rssi() const { return rssi_; }

  // Report device uptime in milliseconds. Same opt-in shape as RSSI; uptime 0
  // is a real reading and is emitted when the field is enabled.
  void setUptimeMillis(uint32_t ms) { uptimeMs_ = ms; }
  void setUptimeEnabled(bool on) { uptimeEnabled_ = on; }
  bool uptimeEnabled() const { return uptimeEnabled_; }
  uint32_t uptimeMillis() const { return uptimeMs_; }

  // True when appendJsonTo() would actually write a field: the feature is on
  // and at least one of the two fields is enabled. Callers use this to skip
  // the append entirely, keeping the disabled payload truly unchanged.
  bool hasAny() const {
    return enabled_ && (rssiEnabled_ || uptimeEnabled_);
  }

  bool hasRssi() const { return enabled_ && rssiEnabled_; }
  bool hasUptime() const { return enabled_ && uptimeEnabled_; }

  // Append the enabled fields, comma-separated, to `buffer` at `*len` and
  // NUL-terminate. The buffer already holds the leading `{` (and any metrics);
  // this emits only the diagnostic members, so the caller's payload is
  // `{<...>}`, not a document of its own. `*len` is the current content length
  // (its NUL terminator position) and is advanced past what was written.
  //
  // Writes NOTHING — returns false and leaves `*len` untouched — when disabled
  // or when no field is enabled, so the off path cannot accidentally alter the
  // payload. When enabled it writes `"rssi":<int>` and/or `"uptime_ms":<uint>`
  // in that order; the caller adds the separators around it.
  bool appendJsonTo(char* buffer, size_t capacity, size_t* len) const {
    if (buffer == 0 || len == 0 || capacity == 0 || !hasAny()) return false;

    size_t n = *len;
    if (n >= capacity) return false;
    const size_t start = n;
    bool wrote = false;
    if (hasRssi()) {
      n = appendPair(buffer, capacity, n, diagnosticsRssiKey());
      n = appendInt(buffer, capacity, n, rssi_);
      wrote = true;
    }
    if (hasUptime()) {
      if (wrote) n = appendChar(buffer, capacity, n, ',');
      n = appendPair(buffer, capacity, n, diagnosticsUptimeKey());
      n = appendUint(buffer, capacity, n, uptimeMs_);
      wrote = true;
    }
    buffer[n < capacity ? n : capacity - 1] = '\0';
    *len = n;
    (void)start;
    return wrote;
  }

 private:
  // --- bounded writers (no <cstring>/<cstdio> dependency) ---------------
  static size_t appendChar(char* buffer, size_t capacity, size_t n, char c) {
    if (n + 1 < capacity) buffer[n++] = c;
    return n;
  }

  static size_t appendRaw(char* buffer, size_t capacity, size_t n,
                          const char* s) {
    while (s != 0 && *s != '\0' && n + 1 < capacity) buffer[n++] = *s++;
    return n;
  }

  // `"key":` — the quoted key and the colon that introduces its value.
  static size_t appendPair(char* buffer, size_t capacity, size_t n,
                           const char* key) {
    n = appendChar(buffer, capacity, n, '"');
    n = appendRaw(buffer, capacity, n, key);
    n = appendChar(buffer, capacity, n, '"');
    n = appendChar(buffer, capacity, n, ':');
    return n;
  }

  // A signed decimal int. -2^31 is handled by negating in the magnitude via
  // unsigned arithmetic, so the most negative int does not overflow.
  static size_t appendInt(char* buffer, size_t capacity, size_t n, int value) {
    if (value < 0) {
      n = appendChar(buffer, capacity, n, '-');
      const unsigned int magnitude =
          static_cast<unsigned int>(-(value + 1)) + 1u;
      return appendUint(buffer, capacity, n, magnitude);
    }
    return appendUint(buffer, capacity, n, static_cast<unsigned int>(value));
  }

  static size_t appendUint(char* buffer, size_t capacity, size_t n,
                           unsigned int value) {
    char tmp[10];  // uint32 max is 10 digits
    size_t digits = 0;
    if (value == 0) {
      tmp[digits++] = '0';
    } else {
      while (value > 0 && digits < sizeof(tmp)) {
        tmp[digits++] = static_cast<char>('0' + (value % 10u));
        value /= 10u;
      }
    }
    while (digits > 0 && n + 1 < capacity) buffer[n++] = tmp[--digits];
    return n;
  }

  bool enabled_;        // master switch; false => contributes nothing
  bool rssiEnabled_;    // report RSSI (no int value encodes "unknown")
  bool uptimeEnabled_;  // report uptime (0 is a legitimate value)
  int rssi_;            // dBm; meaningful only with rssiEnabled_
  uint32_t uptimeMs_;   // milliseconds; meaningful only with uptimeEnabled_
};

}  // namespace insight

#endif  // INSIGHT_DIAGNOSTICS_H
