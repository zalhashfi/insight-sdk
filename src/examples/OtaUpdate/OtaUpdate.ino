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

// ---------------------------------------------------------------------------
// Transport adapter (same seam as SensorTelemetry).
// ---------------------------------------------------------------------------
class HttpClientTransport : public insight::InsightTransport {
 public:
  explicit HttpClientTransport(const char* base) : base_(base) {}

  insight::HttpOutcome postJson(const char* path, const char* json) override {
#if defined(ESP8266) || defined(ESP32)
    WiFiClient client;
    HTTPClient http;
    if (!http.begin(client, urlFor(path))) return insight::HttpOutcome::error();
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
    WiFiClient client;
    HTTPClient http;
    if (!http.begin(client, urlFor(path))) return insight::HttpOutcome::error();
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
      const uint32_t deadline = millis() + 30000UL;
      while ((http.connected() || stream->available()) &&
             millis() < deadline && total < bufferLen) {
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
        } else {
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
  const char* urlFor(const char* path) {
    static char url[192];
    size_t n = 0;
    const char* b = base_ != 0 ? base_ : "";
    while (*b != '\0' && n + 1 < sizeof(url)) url[n++] = *b++;
    while (path != 0 && *path != '\0' && n + 1 < sizeof(url)) url[n++] = *path++;
    url[n] = '\0';
    return url;
  }
};

// ---------------------------------------------------------------------------
// Watchdog seam: a real feed routine, paused around the flash write.
// ---------------------------------------------------------------------------
static insight::InsightWatchdog gWatchdog(10000UL, /*feed=*/0, &millis);

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
// ---------------------------------------------------------------------------
static bool flashImage(const uint8_t* image, size_t len) {
  gWatchdog.pause();
  bool ok = false;
#if defined(ESP8266)
  // ESP8266 has a single application slot; Update.begin() maps the next image
  // over the running one.
  if (Update.begin(len)) {
    ok = Update.write(const_cast<uint8_t*>(image), len) == len;
    if (ok) ok = Update.end(true);
  }
#elif defined(ESP32)
  // ESP32 has two app slots; the running image is left alone, so a failed boot
  // of the new slot can be rolled back by the bootloader.
  ok = Update.begin(len);
  if (ok) {
    ok = Update.write(const_cast<uint8_t*>(image), len) == len;
    if (ok) ok = Update.end(true);
  }
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

  // --- offer -> verify -> flash, scheduled by the policy (429-aware) --------
  if (now - gLastOtaPollMs >= kOtaPollPeriodMs) {
    gLastOtaPollMs = now;
    if (gOta.isReady(now)) {
      const insight::OtaResult result = gOta.run();

      switch (result.kind) {
        case insight::OtaResult::Flashed:
          // The image wrote in full and verified. PHASE 1: arm the trial — the
          // new image is on probation and must confirm itself on the next boot.
          gRunner.arm();
          gConfirmedThisBoot = false;
          break;

        case insight::OtaResult::RateLimited:
        case insight::OtaResult::TransportFailure:
        case insight::OtaResult::SizeMismatch:
        case insight::OtaResult::HashMismatch:
          // Retryable: the policy already recorded retryAtMillis; the loop
          // simply respects isReady() and never sleeps on it.
          break;

        case insight::OtaResult::UnsupportedSize:
        case insight::OtaResult::InvalidOffer:
        case insight::OtaResult::NoUpdate:
        default:
          break;  // Permanent (or nothing to do): do not retry this offer.
      }
    }
  }

  // Report the trial outcome for the operator.
  if (gRunner.isRolledBack()) {
    Serial.println("OTA: trial expired, rolled back to previous image (ESP32)");
  } else if (gRunner.isReattemptRequired()) {
    Serial.println("OTA: trial expired, no rollback possible — reattempt (ESP8266)");
  } else if (gRunner.isConfirmed()) {
    Serial.println("OTA: running image confirmed healthy");
  }

  delay(50);
}
