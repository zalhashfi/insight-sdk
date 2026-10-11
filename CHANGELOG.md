# Changelog

All notable changes to the insight-sdk are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The newest version below is the one `insight::sdkVersion()` reports and the one
`test/test_docs` requires an entry for (NFR-MNT-06).

## [Unreleased]

### Fixed
- **OTA rollback outcome integrity (review finding 3 / INV-O4).** `InsightOtaRunner`
  no longer reports `RolledBack` for a rollback the bootloader did not perform:
  `expire()` records `RolledBack` only when the rollback seam RAN AND SUCCEEDED,
  and otherwise a new `RollbackFailed` state (the seam returned false, or none is
  wired). `RollbackOutcome` gains the matching `RollbackFailed` decision and a
  `retryRecommended` flag, so a caller can never read a successful recovery out of
  a rollback that did not happen.
- **Uninitialised verification record (finding 4).** `InsightOta`'s constructor now
  initialises `lastComputedSha256_`/`lastOfferSize_`/`lastReceived_`, so
  `lastVerification()` before the first `run()` reads its documented inert state
  instead of indeterminate memory.
- **Over-long body clamped instead of rejected (finding 5).** `downloadImage()`
  reports the delivered length verbatim, so a seam that claims more than the offer
  promised is a `SizeMismatch` at the size gate — not silently smoothed to equal
  the promised size.
- **Retryable-without-schedule + over-eager `UnsupportedSize` (finding 7).**
  `UnsupportedSize` is now a permanent refusal (`retry == false`, no schedule), and
  the no-sink/no-transport `TransportFailure` paths now carry a bounded backoff —
  closing the "retryable with no deadline" hole that let a caller hot-loop
  (INV-O2). `run()` clears a stale schedule at the start of every pass.
- **Mismatch diagnostics discarded (finding 8).** `HashMismatch`/`SizeMismatch`
  now populate `OtaResult::computedSha256` and the `lastVerification()` record
  (digest, offered size, received count), instead of returning an empty record in
  exactly the cases that need diagnosing.
- **Loose offer parser (finding 9).** `findField()` is now string-aware (skips
  `,`/key-shaped runs inside values), `isNull()` matches `null` only as a whole
  token (not a bare prefix like `nullify`), and `parseString()` refuses an
  over-long value instead of silently truncating it (a truncated security field
  must not be a silent downgrade).
- **Health-check `Unknown` had no backoff (finding 11).** `HealthCheckRollback`
  now records a bounded exponential backoff (the shared `backoffMillis`) after a
  non-decisive verdict, exposed via `nextAllowedMillis()`/`isReady()`, so an
  offline server is not hammered from `loop()`.
- **Non-constant-time digest compare (finding 16).** The offered/computed SHA-256
  comparison is now a fixed-length constant-time compare, removing a timing oracle
  on a security-critical equality. The `SignatureVerifier` seam's "backend owns
  constant-time crypto / null-is-a-failure" contract is now documented.
- **`InsightOtaRunner::deadlineMillis()` (finding 18)** is documented (and pinned
  by test) as a modular, rollover-correct value rather than a saturated one.
- **`removeAt()` + O(1)-stack removal; ~10 KB ESP8266 stack (finding 17).**
  `InsightBuffer` gains a heap-free `removeAt(index)`, and `InsightSend` uses it
  instead of snapshotting the whole queue onto the stack — a several-KB frame that
  would overflow the ESP8266 loop-task stack.
- **`OtaUpdate` example (findings 1, 6, 12, 13, 14, 15).** The example now reboots
  after a successful flash (so the trial is actually exercised by the boot that
  runs the new image), aborts/invalidates a failed flash write per platform, does
  not let the hourly poll gate discard a `retry-after` schedule, feeds the
  watchdog during the (rollover-safe) image read, handles `SignatureMismatch` in
  the result switch, and builds its URLs into a caller buffer instead of a
  non-reentrant function-static.

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
