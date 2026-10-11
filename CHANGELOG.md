# Changelog

All notable changes to the insight-sdk are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The newest version below is the one `insight::sdkVersion()` reports and the one
`test/test_docs` requires an entry for (NFR-MNT-06).

## [Unreleased]

### Added
- **OTA rollback on a failed post-update health-check** and **optional signed
  images** (B14 / FR-OTA-06 / FR-OTA-07 / NFR-SEC-03):
  - `InsightOtaSigned.h` — `HealthCheckRollback` drives the two-phase trial from
    `InsightOtaRunner` with a `reconcile`-style `HealthReport` seam: healthy →
    keep, unhealthy → roll back (ESP32) or `reattemptRequired` (ESP8266, no
    rollback), unknown → stay on probation. The platform branch is delegated to
    the runner, so there is one place that knows the asymmetry.
  - `InsightOta` gained a `SignatureVerifier` seam (`setSignatureVerifier`,
    `setRequireSignature`) — a wrong signature is never flashed, a correct one is.
    The crypto is behind the seam, so native tests inject a fake verifier and no
    crypto library is required.
  - `OtaResult::SignatureMismatch`, `ImageVerification`, and the offer's optional
    `signature`/`pubkey_id` fields.

## [0.2.0] — 2026-10-11

Public API documentation and the CHANGELOG itself (B15 / FR-SDK-11 / NFR-MNT-06).

### Added
- `Insight.h` is now the **stable public aggregate**: one include pulls in the
  foundation client plus every capability header (`InsightTransport`,
  `InsightReliability`, `InsightBuffer`, `InsightSend`, `InsightDevice`,
  `InsightWifi`, `InsightWatchdog`, `InsightTls`, `InsightControl`,
  `InsightSensor`, `InsightDiagnostics`, `InsightOta`, `InsightOtaRunner`).
- `insight::sdkVersion()` — the SDK's public version string, kept in step with
  the newest entry in this file.
- Doc-comments on every public overload and capability, so each declaration is
  documented where it lives.
- `test/test_docs` — a native suite that SCANS the public headers and fails the
  build when a public declaration lacks a preceding doc-comment, or when this
  CHANGELOG has no entry for the current `sdkVersion()`.

### Changed
- `Insight.h` no longer stands alone as a foundation stub: it now aggregates the
  full public surface. This is source-compatible — including the header keeps
  working, and the ordering of includes never mattered (NFR-MNT-04).

### Documented
- **FR-SDK-11 (opt-in, source-compatible).** Every API added since the
  foundation milestone is opt-in: the newer capabilities live in their own
  headers and must be included and called explicitly, so a sketch written
  against an earlier milestone keeps compiling against this one.
- The one deliberate exception remains the `send()` -> `bool` signature change,
  first recorded under `[0.1.0]` below.

## [0.1.0] — 2026-01-01

The M2 "field-hardened firmware" milestone: reliability, OTA verification and
identity, exercised by the native test suites and compiled for ESP32/ESP8266.

### Added
- `InsightTransport` seam (`postJson` / `get`) with `HttpOutcome`
  (`Ok` / `Timeout` / `Error`, HTTP status on `Ok`).
- `InsightReliability`: transport-failure classification and bounded
  exponential backoff (`classify`, `decide`, `retryAfter`).
- `InsightBuffer`: fixed-capacity RAM FIFO of metric samples — FIFO order,
  last-wins per key, NaN/Inf and key validation, explicit `MetricValue::null()`
  sentinel.
- `InsightSend`: `send()` / non-blocking `flush()` policy over buffer +
  transport, with `Retry-After` handling and per-instance retry state.
- `InsightDevice`: `x-insight-device` / `x-insight-firmware` identity headers.
- `InsightWifi`: bounded (`connectWiFi(timeoutMs)`) and counted (`begin(maxAttempts)`)
  association, plus explicit opt-in unbounded waits.
- `InsightWatchdog`: scheduled, pausable watchdog feeding for flash/OTA windows.
- `InsightTls`: certificate-verification policy with a production gate and an
  SNTP ordering gate.
- `InsightControl`: downlink `poll -> execute -> ack` with idempotent acks.
- `InsightSensor`: sensor read with bounded retries that never fabricates a value.
- `InsightDiagnostics`: optional RSSI/uptime reporting.
- `InsightOta` / `InsightOtaRunner`: `GET /v1/ota` offer parsing, SHA-256
  verification before flashing, and two-phase confirm/rollback.
- Example sketches for ESP32 and ESP8266 (sensor telemetry, OTA update,
  control/ack, legacy).

### Changed
- **BREAKING:** `send()` now returns `bool` (accepted / rejected) instead of
  `void`. Sketches that ignored the result keep compiling; sketches that
  depended on the old `void` signature must be updated. This is the only
  source-incompatible change in the SDK.

[Unreleased]: https://example.invalid/insight-sdk/compare/v0.2.0...HEAD
[0.2.0]: https://example.invalid/insight-sdk/compare/v0.1.0...v0.2.0
[0.1.0]: https://example.invalid/insight-sdk/releases/tag/v0.1.0
