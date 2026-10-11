// OtaUpdate — the full, safe OTA flow, end to end:
//
//     offer -> verify (size + SHA-256) -> flash -> confirm
//
// It composes the two OTA pieces the SDK ships, each of which is a non-blocking
// policy driven from loop():
//
//   * insight::InsightOta      — fetch the offer (GET /v1/ota), download the
//                                image WHOLE from zero, and hand it to the flash
//                                sink ONLY once received == offer.size AND the
//                                digest matches. Not one byte reaches the
//                                partition before both checks pass. A 429 is
//                                honoured (scheduled, never hammered).
//   * insight::InsightOtaRunner — the two-phase trial: after flashing, the new
//                                image is on PROBATION. It is confirmed only
//                                once the app comes up healthy; if it boot-loops
//                                the trial expires. The expiry outcome is the
//                                platform asymmetry: ESP32 rolls back to the
//                                previous slot; ESP8266 has no two-slot layout,
//                                so it reports reattemptRequired (no rollback
//                                is pretended).
//
// The WATCHDOG is paused around the flash write only. Erasing/writing flash
// stalls the CPU and cache for hundreds of milliseconds, so a watchdog fed from
// a timer mid-write bricks the device; pause()/resume() bracket that window and
// the feed guarantee is deliberately withdrawn inside it.
//
// Compiles for ESP32 and ESP8266; the Wi-Fi include and the flash sink are the
// only board-specific code.

#if defined(ESP8266)
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <Updater.h>
#elif defined(ESP32)
#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <esp_ota_ops.h>
#else
#include <Arduino.h>
#endif

#include <InsightBuffer.h>
#include <InsightOta.h>
// Both Arduino platforms pass a bare `-DESP32` / `-DESP8266` (each expands to
// `1`), and InsightOtaRunner.h names enumerators `ESP32` and `ESP8266`. The SDK
// header cannot be changed here, so BOTH macros are neutralised for its
// duration: save whatever was set, undef, include, then restore. Neither name
// is used afterwards — `gRunner.setPlatform()` later selects the platform by the
// enum's integer slot, which is unaffected by this.
#ifdef ESP32
#define INSIGHT_OTA_EXAMPLE_SAVED_ESP32 ESP32
#undef ESP32
#endif
#ifdef ESP8266
#define INSIGHT_OTA_EXAMPLE_SAVED_ESP8266 ESP8266
#undef ESP8266
#endif
#include <InsightOtaRunner.h>
#ifdef INSIGHT_OTA_EXAMPLE_SAVED_ESP32
#undef INSIGHT_OTA_EXAMPLE_SAVED_ESP32
#define ESP32 1
#endif
#ifdef INSIGHT_OTA_EXAMPLE_SAVED_ESP8266
#undef INSIGHT_OTA_EXAMPLE_SAVED_ESP8266
#define ESP8266 1
#endif
#include <InsightTransport.h>
#include <InsightWatchdog.h>

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
static const char* kWifiSsid = "your-ssid";
static const char* kWifiPass = "your-password";
static const char* kApiBase = "http://192.168.1.10:8080";
static const char* kDeviceKey = "esp-node-01";
static const char* kFirmwareVersion = "1.0.0";  // x-insight-firmware
static const uint32_t kOtaPollPeriodMs = 3600000UL;  // once an hour (quota)

// Watchdog seam: the single definition lives here so the transport adapter's
// read loop (below) can feed it while it waits for body bytes. The real feed
// routine is installed in setup() via setFeed(); the constructor takes a
// millisecond clock and no feed fn yet.
static insight::InsightWatchdog gWatchdog(10000UL, /*feed=*/0, &millis);

// ---------------------------------------------------------------------------
// Transport adapter (same seam as SensorTelemetry).
// ---------------------------------------------------------------------------
class HttpClientTransport : public insight::InsightTransport {
 public:
  explicit HttpClientTransport(const char* base) : base_(base) {}

  insight::HttpOutcome postJson(const char* path, const char* json) override {
#if defined(ESP8266) || defined(ESP32)
    char url[192];
    WiFiClient client;
    HTTPClient http;
    if (!http.begin(client, buildUrl(base_, path, url, sizeof(url)))) {
      return insight::HttpOutcome::error();
    }
    http.addHeader("Content-Type", "application/json");
    http.addHeader("x-insight-device", kDeviceKey);
    const int status =
        http.POST(reinterpret_cast<uint8_t*>(const_cast<char*>(json)), strlen(json));
    http.end();
    if (status < 0) return insight::HttpOutcome::timeout();
    return insight::HttpOutcome::ok(status);
#else
    (void)path;
    (void)json;
    return insight::HttpOutcome::error();
#endif
  }

  insight::HttpOutcome get(const char* path, char* buffer, size_t bufferLen,
                           size_t* contentLength) override {
#if defined(ESP8266) || defined(ESP32)
    char url[192];
    WiFiClient client;
    HTTPClient http;
    if (!http.begin(client, buildUrl(base_, path, url, sizeof(url)))) {
      return insight::HttpOutcome::error();
    }
    // OTA requests carry BOTH identity headers: the device key and the RUNNING
    // firmware version (the firmware header is OTA-only, per the contract).
    http.addHeader("x-insight-device", kDeviceKey);
    http.addHeader("x-insight-firmware", kFirmwareVersion);
    const int status = http.GET();
    if (status < 0) {
      http.end();
      return insight::HttpOutcome::timeout();
    }
    if (status >= 200 && status < 300) {
      // OPAQUE bodies (the image may contain NULs) must be read by length, not
      // by strlen; the seam's contentLength is what makes that possible. This
      // adapter serves BOTH the JSON offer body and the binary image, and the
      // caller demands an EXACT size for the image (a short read is a
      // SizeMismatch) — so the full `bufferLen` capacity is used and NO NUL
      // terminator is appended: reserving a byte would make every image one
      // byte short.
      WiFiClient* stream = http.getStreamPtr();
      size_t total = 0;
      // Wall-clock budget for the WHOLE body. `millis()`-based (not a loop
      // counter) so it is bounded regardless of chunk cadence; the caller's
      // policy measures the delivered length and reports SizeMismatch if this
      // budget cuts the transfer short, so a timeout is a clean, recoverable
      // outcome rather than a hang.
      const uint32_t deadline = millis() + 30000UL;
      while (total < bufferLen) {
        // Rollover-safe: `millis() - deadline` is an unsigned subtraction, so
        // the comparison survives a wrap of the 32-bit counter.
        if (static_cast<int32_t>(millis() - deadline) >= 0) break;
        const int avail = stream->available();
        if (avail > 0) {
          size_t room = bufferLen - total;
          const int chunk = avail < static_cast<int>(room)
                                ? avail
                                : static_cast<int>(room);
          const size_t got =
              stream->readBytes(reinterpret_cast<uint8_t*>(buffer) + total,
                                static_cast<size_t>(chunk));
          if (got == 0) break;
          total += got;
        } else if (!http.connected()) {
          // Nothing buffered and the socket is closed: the body is complete
          // (or the server hung up). Stop rather than spin.
          break;
        } else {
          // Waiting for more bytes. Feed the WATCHDOG while we wait: a blocking
          // delay(1) loop here would starve the feed and trip the watchdog
          // during a slow image transfer. gWatchdog.poll() is a no-op while the
          // flash write has it paused, so this is safe to call unconditionally.
          gWatchdog.poll();
          delay(1);
        }
      }
      if (contentLength != 0) *contentLength = total;
    }
    http.end();
    return insight::HttpOutcome::ok(status);
#else
    (void)path;
    (void)buffer;
    (void)bufferLen;
    (void)contentLength;
    return insight::HttpOutcome::error();
#endif
  }

 private:
  const char* base_;

  // Build the absolute URL for `path` into the CALLER-supplied buffer and return
  // it. `url`/`urlLen` belong to the caller (a per-call local), so two threads
  // or two nested requests can never clobber a shared static — the previous
  // version returned a pointer into a function-local `static char url[192]`,
  // which is not reentrant and would silently corrupt an in-flight URL if this
  // transport were ever driven from more than one context. Truncation is
  // impossible for the sizes here (base + path << the caller's buffer), but the
  // copy still bounds the write so it can never overrun.
  static const char* buildUrl(const char* base, const char* path, char* url,
                              size_t urlLen) {
    if (url == 0 || urlLen == 0) return "";
    size_t n = 0;
    for (const char* b = base != 0 ? base : ""; *b != '\0' && n + 1 < urlLen;
         ++b) {
      url[n++] = *b;
    }
    for (const char* p = path; p != 0 && *p != '\0' && n + 1 < urlLen; ++p) {
      url[n++] = *p;
    }
    url[n] = '\0';
    return url;
  }
};

// ---------------------------------------------------------------------------
// Watchdog feed routine (the object itself is defined at the top, before the
// transport adapter that also feeds it), installed in setup() with setFeed().
// The watchdog is paused around the flash write.
// ---------------------------------------------------------------------------
static void feedWatchdog() {
#if defined(ESP8266)
  ESP.wdtFeed();
#elif defined(ESP32)
  // No explicit per-task feed is required here (the Arduino loop task feeds
  // itself), so an empty body is the correct "the platform is watched" seam.
#else
  // host/no-op
#endif
}

// ---------------------------------------------------------------------------
// Flash sink: the ONLY path to the partition. It is called at most once, and
// only with a fully verified image. The watchdog is PAUSED for the whole write
// so a mid-write feed cannot reset the device.
//
// Any failure ABORTS or otherwise leaves the update uncommitted, so a torn
// write cannot be booted. A partially written slot left committed is the
// danger: the next boot could select a half-written image. On ESP32
// `Update.abort()` closes the session and invalidates the incomplete slot; on
// ESP8266 the Updater has no public abort and the image is simply never
// committed (end(true) — the step that makes it bootable — is skipped on
// failure). Either way a failed write leaves the device on the KNOWN-GOOD image.
// Returning false then tells the policy to report TransportFailure and retry —
// the flash failure is PROPAGATED, never swallowed.
// ---------------------------------------------------------------------------
static bool flashImage(const uint8_t* image, size_t len) {
  gWatchdog.pause();
  bool ok = false;
#if defined(ESP8266)
  // ESP8266 has a single application slot; Update.begin() maps the next image
  // over the running one. Its Updater exposes no abort(); a failed write leaves
  // the update session unfinished, and `Update.end(true)` is the only public
  // close. We therefore do NOT call end() on failure — end() would commit a
  // partial image — and simply return false so the policy reports the failure
  // and the device keeps running the current image until a clean retry. (The
  // ESP8266 core's Updater has no public cancel; the partial write is not
  // committed because end() is what makes the image bootable.)
  if (Update.begin(len)) {
    ok = Update.write(const_cast<uint8_t*>(image), len) == len;
    if (ok) ok = Update.end(true);
  }
#elif defined(ESP32)
  // ESP32 has two app slots; the running image is left alone, so a failed boot
  // of the new slot can be rolled back by the bootloader. abort() marks the
  // in-progress slot invalid so the bootloader cannot select it.
  ok = Update.begin(len);
  if (ok) {
    ok = Update.write(const_cast<uint8_t*>(image), len) == len;
    if (ok) ok = Update.end(true);
  }
  if (!ok) Update.abort();
#else
  (void)image;
  (void)len;
  ok = true;  // host: nothing to flash
#endif
  gWatchdog.resume();
  return ok;
}

// ---------------------------------------------------------------------------
// OTA runner seams (bootloader integration).
// ---------------------------------------------------------------------------
static bool markRunningImageValid() {
#if defined(ESP32)
  return esp_ota_mark_app_valid_cancel_rollback() == ESP_OK;
#else
  return true;  // ESP8266 has no bootloader flag to set; a successful no-op.
#endif
}

static bool rollbackToPrevious() {
#if defined(ESP32)
  // ESP-IDF 4.2 API: point the bootloader back at the previous slot and reboot.
  return esp_ota_mark_app_invalid_rollback_and_reboot() == ESP_OK;
#else
  return false;  // No two-slot layout to roll back to on ESP8266.
#endif
}

// ---------------------------------------------------------------------------
// SDK objects.
// ---------------------------------------------------------------------------
static HttpClientTransport gTransport(kApiBase);
static insight::InsightOta gOta;
static insight::InsightOtaRunner gRunner;

static uint32_t gLastOtaPollMs = 0;
static bool gConfirmedThisBoot = false;

// Reboot into the freshly flashed image. The two-phase trial is only meaningful
// ACROSS a boot: InsightOtaRunner holds its trial state in RAM, so on the next
// power-up the runner is `Idle` again and would never see the trial this boot
// armed. The runner's job — confirm the NEW image, or roll it back to the OLD
// one — only happens on the boot that actually RUNS the new image. So once a
// successful flash has armed the trial, the device must reboot now: on ESP32 the
// bootloader boots the new slot on probation and, if this sketch never confirms
// there, rolls back; on ESP8266 there is one slot and the new image simply runs.
//
// Without this reboot the trial armed here expires against the STILL-RUNNING old
// image (which of course never confirms the version it is not running), and the
// ESP32 rollback path would be invoked for a slot the device never booted —
// exactly the false-recovery the trial exists to prevent.
static void rebootIntoNewImage() {
#if defined(ESP8266) || defined(ESP32)
  Serial.println("OTA: image flashed + verified — rebooting to confirm");
  delay(100);  // let the serial line flush before the reset
  ESP.restart();
#else
  // host: there is no bootloader to reboot into; nothing to do.
#endif
}

// Read the `retry-after` header a 429 carried. The transport seam surfaces only
// the status, so the honoured value is supplied to the OTA policy through its
// per-instance seam: this function is installed with
// `gOta.setRetryAfterSource(&retryAfterHeaderSeconds)` in setup().
//
// A real adapter would parse the last response's `retry-after` header here and
// return it in whole seconds; absent a usable header it returns a negative
// value, and the policy falls back to its one-hour default — which is the
// correct quota behaviour (never an immediate retry).
static long retryAfterHeaderSeconds() {
  // No header was captured in this example: report "absent" so the policy uses
  // its built-in one-hour default. (A real build returns the parsed value.)
  return -1;
}

void setup() {
  Serial.begin(115200);

#if defined(ESP8266) || defined(ESP32)
  WiFi.mode(WIFI_STA);
  WiFi.begin(kWifiSsid, kWifiPass);
  const uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(100);
  }
#endif

  gWatchdog.setFeed(&feedWatchdog);

  // Wire the OTA policy: transport, the flash sink, the monotonic clock and
  // the built-in SHA-256 (the default; shown here explicitly for clarity).
  gOta.setTransport(&gTransport);
  gOta.setFlashSink(&flashImage);
  gOta.setClock(&millis);
  gOta.setHasher(insight::InsightOta::builtInSha256());
  gOta.setMaxImageSize(1024);  // narrow the RAM guard for this build
  // Per-instance 429 handling: the policy reads `retry-after` from THIS object's
  // source, so different OTA objects never share a header.
  gOta.setRetryAfterSource(&retryAfterHeaderSeconds);

  // Wire the trial runner for THIS platform. NOTE: the espressif32 toolchain
  // passes `-DESP32`, so `InsightOtaRunner::ESP32`/`::ESP8266` cannot appear by
  // name in an Arduino sketch (the macro would expand to `1`). The enum's
  // declared order is knowable, so platform selection uses the enum's own
  // integer slot — 0 = ESP32 (two-slot), 1 = ESP8266 (no rollback).
  const insight::InsightOtaRunner::Platform kPlatformId =
#if defined(ESP8266)
      static_cast<insight::InsightOtaRunner::Platform>(1)
#else
      static_cast<insight::InsightOtaRunner::Platform>(0)
#endif
      ;
  gRunner.setPlatform(kPlatformId);
  gRunner.setMarkValid(&markRunningImageValid);
  gRunner.setRollback(&rollbackToPrevious);
  gRunner.setClock(&millis);
  gRunner.setConfirmTimeout(30000UL);

  // PHASE 2a: mark the running image healthy once the app is up. Doing it early
  // in setup() is the "I booted far enough to be useful" signal; a build that
  // panics before this point never confirms, and its trial expires instead.
  if (!gConfirmedThisBoot && gRunner.isTrial()) {
    gRunner.confirm();
    gConfirmedThisBoot = true;
  }
}

void loop() {
  const uint32_t now = millis();

  // Regular watchdog feeding; a no-op while paused inside flashImage().
  gWatchdog.poll();

  // PHASE 2b: expire an unconfirmed trial. Non-blocking and safe to call every
  // pass; it acts at most once, exactly at or past the deadline.
  gRunner.poll();

  // --- offer -> verify -> flash --------------------------------------------
  //
  // The poll cadence and the RETRY cadence are separate gates, and both must be
  // honoured:
  //
  //   * kOtaPollPeriodMs is the QUOTA cadence (one offer per hour, D2.8) — the
  //     most often we even ASK about an update in the steady state.
  //   * isReady(now) is the POLICY's own schedule, which a 429 or a transport
  //     failure sets to `retryAtMillis` (for a 429, `now + retry-after`).
  //
  // Gating ONLY on the hourly period (the previous code) let the hour throw away
  // the schedule the policy had just recorded: a 429 with a 5-minute
  // retry-after would be ignored for the rest of the hour. Here the policy's
  // readiness can PULL THE NEXT OFFER FORWARD — if it says it is ready before the
  // hour is up, we act on that (a scheduled retry is authoritative), but we
  // never poll MORE than the quota period unless the policy explicitly asked.
  const bool quotaElapsed = (now - gLastOtaPollMs) >= kOtaPollPeriodMs;
  if (gOta.isReady(now) && (quotaElapsed || gOta.nextAttemptAtMillis() != 0)) {
    gLastOtaPollMs = now;
    const insight::OtaResult result = gOta.run();

    switch (result.kind) {
      case insight::OtaResult::Flashed:
        // The image wrote in full and verified. PHASE 1: arm the trial — the
        // new image is on probation — then REBOOT so the trial is actually
        // exercised by the boot that runs the new image (see
        // rebootIntoNewImage()). This reboots; nothing after it runs.
        gRunner.arm();
        gConfirmedThisBoot = false;
        rebootIntoNewImage();
        break;

      case insight::OtaResult::RateLimited:
      case insight::OtaResult::TransportFailure:
      case insight::OtaResult::SizeMismatch:
      case insight::OtaResult::HashMismatch:
      case insight::OtaResult::SignatureMismatch:
        // Retryable (or a bad-signature/stuck-trial case the operator must see):
        // the policy already recorded retryAtMillis; the loop simply respects
        // isReady() and never sleeps on it. SignatureMismatch is included so the
        // switch is EXHAUSTIVE over the enum — a signed image rejected by the
        // verifier must not fall through to the "permanent, ignore" default.
        break;

      case insight::OtaResult::UnsupportedSize:
      case insight::OtaResult::InvalidOffer:
      case insight::OtaResult::NoUpdate:
        break;  // Permanent (or nothing to do): do not retry this offer.
    }
  }

  // Report the trial outcome for the operator.
  if (gRunner.isRolledBack()) {
    Serial.println("OTA: trial expired, rolled back to previous image (ESP32)");
  } else if (gRunner.isReattemptRequired()) {
    Serial.println("OTA: trial expired, no rollback possible — reattempt (ESP8266)");
  } else if (gRunner.isRollbackFailed()) {
    Serial.println("OTA: trial expired, rollback FAILED — reattempt (ESP32)");
  } else if (gRunner.isConfirmed()) {
    Serial.println("OTA: running image confirmed healthy");
  }

  delay(50);
}
