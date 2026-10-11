#ifndef INSIGHT_H
#define INSIGHT_H

// ===========================================================================
// insight-sdk — the single include for the public SDK
// ===========================================================================
//
// `#include <Insight.h>` and you have the whole public API: the foundation
// client and every capability header the SDK ships. The headers below are the
// only include paths a sketch needs; include them directly if you prefer a
// narrower surface, but their ORDER never matters and no header depends on
// being pulled in through this one (NFR-MNT-06: each public overload and
// capability is documented where it lives, and this aggregate is stable).
//
//   Insight.h              foundation client: begin / transport / post / get
//   InsightTransport.h     the two-operation transport seam + HttpOutcome
//   InsightReliability.h   retry/backoff policy: classify + decide
//   InsightBuffer.h        fixed-capacity RAM FIFO of metric samples
//   InsightSend.h          send()/flush() policy over buffer + transport
//   InsightDevice.h        x-insight-device / x-insight-firmware identity
//   InsightWifi.h          bounded / counted Wi-Fi association
//   InsightWatchdog.h      scheduled feeding, pausable for flash writes
//   InsightTls.h           certificate-verification policy (prod gate)
//   InsightControl.h       downlink poll -> execute -> ack
//   InsightSensor.h        sensor read with bounded retry (never invents)
//   InsightDiagnostics.h   optional RSSI/uptime reporting
//   InsightOta.h           OTA offer parse + SHA-256 verification
//   InsightOtaRunner.h     the OTA state machine (download/verify/flash)
//   InsightOtaSigned.h     health-check rollback + optional signed images
//
// Source compatibility (FR-SDK-11): newer capabilities are opt-in headers and
// opt-in calls. A sketch written against an earlier milestone keeps compiling
// against this one; the single documented exception is the `send()` -> bool
// signature change, recorded in CHANGELOG.md at the repository root.

#ifdef ARDUINO
#include <Arduino.h>
#endif

#include "InsightBuffer.h"
#include "InsightControl.h"
#include "InsightDevice.h"
#include "InsightDiagnostics.h"
#include "InsightOta.h"
#include "InsightOtaRunner.h"
#include "InsightOtaSigned.h"
#include "InsightReliability.h"
#include "InsightSensor.h"
#include "InsightSend.h"
#include "InsightTls.h"
#include "InsightTransport.h"
#include "InsightWatchdog.h"
#include "InsightWifi.h"

namespace insight {

// The SDK's public version. Kept in step with the newest entry in
// CHANGELOG.md (NFR-MNT-06); `test/test_docs` asserts the CHANGELOG carries an
// entry for exactly this string, so a release cannot ship undocumented.
inline const char* sdkVersion() { return "0.2.0"; }

// Foundation HTTP client over the transport seam.
//
// The client owns NOTHING: it points at an `InsightTransport` installed by the
// caller and routes its requests through it. That is what keeps the SDK
// board-agnostic — the platform bits (WiFiClient/HTTPClient/TLS) live in a
// transport adapter, and everything above the seam is exercisable on a host
// with no hardware. The richer capabilities above compose around this class
// rather than living inside it.
class Insight {
 public:
  // Construct a detached, uninitialised client. No transport is installed, so
  // every request reports a transport-level error until setTransport() runs.
  Insight() : transport_(0) {}

  // Nothing is owned, so there is no transport to free or close here.
  ~Insight() {}

  // Bring the client up. Returns true once the client is ready to be used.
  //
  // Idempotent and side-effect free in the foundation milestone: there is no
  // hardware to initialise at this layer (the caller owns WiFi/clock/OTA), so
  // a second call is as valid as the first. Kept as the natural place for a
  // future initialisation step without changing call sites (FR-SDK-11).
  bool begin() { return true; }

  // Install the transport every request below is routed through. The client
  // does NOT take ownership: the transport must outlive the client (or be
  // detached with setTransport(0) before it goes away). Passing null detaches
  // the current transport, after which requests report a transport-level error
  // instead of dereferencing anything.
  void setTransport(InsightTransport* transport) { transport_ = transport; }

  // The transport currently installed, or null when detached. Handy for a
  // caller that wants to reuse the same seam across two client objects.
  InsightTransport* transport() const { return transport_; }

  // POST `json` to `path` through the installed transport.
  //
  // `path` is the request path only (for example "/v1/telemetry"); `json` is
  // the already-serialised body, which the transport is free to forward byte
  // for byte. With no transport installed this reports
  // `HttpOutcome::error()` — a request that cannot be made is a transport-level
  // failure, which the reliability policy then retries — rather than crashing
  // on a null pointer.
  HttpOutcome post(const char* path, const char* json) {
    if (transport_ == 0) {
      return HttpOutcome::error();
    }
    return transport_->postJson(path, json);
  }

  // GET `path` into the caller's `buffer` of `bufferLen` bytes.
  //
  // The body is NUL-terminated on success. `contentLength`, when non-null,
  // receives the number of BODY bytes delivered — independently of the
  // terminator — which is the only correct measure for an OPAQUE body (a
  // firmware image) that may itself contain NUL bytes; see InsightTransport.
  // With no transport installed this reports `HttpOutcome::error()` and leaves
  // `buffer` untouched.
  HttpOutcome get(const char* path, char* buffer, size_t bufferLen,
                  size_t* contentLength = 0) {
    if (transport_ == 0) return HttpOutcome::error();
    return transport_->get(path, buffer, bufferLen, contentLength);
  }

 private:
  // Borrowed, never owned; null until setTransport() is called.
  InsightTransport* transport_;
};

}  // namespace insight

#endif  // INSIGHT_H
