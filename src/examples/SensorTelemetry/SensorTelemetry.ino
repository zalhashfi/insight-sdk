// SensorTelemetry — the telemetry loop every sensor app eventually writes:
// read a flaky sensor WITH retries, queue the sample, and let the send policy
// drain it over the network without ever blocking the loop.
//
// It exercises three SDK pieces and the seam style they share:
//
//   * insight::readSensor()   — bounded retries; a failed read and a NaN/Inf
//                               read are the SAME kind of miss, and the reader
//                               NEVER fabricates a value. When every attempt
//                               misses we send an explicit null ("sensor is
//                               down"), which is the honest report the ingress
//                               contract accepts — not a made-up number.
//   * insight::InsightSend    — buffering is separated from transmitting, so a
//                               sample is captured at full rate without waiting
//                               on the network. flush() is NON-BLOCKING: a
//                               retryable failure is SCHEDULED, never slept on,
//                               so a watchdog stays fed.
//   * insight::InsightDiagnostics — RSSI + uptime, OFF by default, appended
//                               only when the feature is enabled (strict
//                               opt-in; a fresh object contributes nothing).
//
// Compiles for ESP32 and ESP8266. The Wi-Fi include differs per platform, and
// a small transport adapter (below) is the only board-specific code; the SDK
// itself is transport-agnostic and was proven on the host.

#if defined(ESP8266)
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#elif defined(ESP32)
#include <WiFi.h>
#include <HTTPClient.h>
#else
#include <Arduino.h>
#endif

#include <Insight.h>
#include <InsightBuffer.h>
#include <InsightDiagnostics.h>
#include <InsightSensor.h>
#include <InsightSend.h>
#include <InsightTransport.h>

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
static const char* kWifiSsid = "your-ssid";
static const char* kWifiPass = "your-password";
static const char* kApiBase = "http://192.168.1.10:8080";  // ingress base URL
static const char* kDeviceKey = "esp-node-01";
static const char* kTempKey = "temperature_c";
static const char* kLightKey = "light_lux";
static const uint32_t kSamplePeriodMs = 5000;

// ---------------------------------------------------------------------------
// Transport adapter: the one place that knows about the platform's HTTP stack.
// It is the exact seam the SDK expects (InsightTransport), so the send/flush
// policy drives it without knowing whether it is ESP32 or ESP8266 underneath.
// ---------------------------------------------------------------------------
class HttpClientTransport : public insight::InsightTransport {
 public:
  explicit HttpClientTransport(const char* base) : base_(base) {}

  insight::HttpOutcome postJson(const char* path, const char* json) override {
#if defined(ESP8266) || defined(ESP32)
    WiFiClient client;
    HTTPClient http;
    if (!http.begin(client, urlFor(path))) {
      return insight::HttpOutcome::error();
    }
    http.addHeader("Content-Type", "application/json");
    http.addHeader("x-insight-device", kDeviceKey);
    const int status =
        http.POST(reinterpret_cast<uint8_t*>(const_cast<char*>(json)),
                  strlen(json));
    http.end();
    if (status < 0) {
      // A negative return is a connection-level failure, not an HTTP status.
      return insight::HttpOutcome::timeout();
    }
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
    if (!http.begin(client, urlFor(path))) {
      return insight::HttpOutcome::error();
    }
    http.addHeader("x-insight-device", kDeviceKey);
    const int status = http.GET();
    if (status < 0) {
      http.end();
      return insight::HttpOutcome::timeout();
    }
    if (status >= 200 && status < 300) {
      const String body = http.getString();
      size_t n = body.length();
      if (n >= bufferLen) n = bufferLen - 1;
      memcpy(buffer, body.c_str(), n);
      buffer[n] = '\0';
      if (contentLength != 0) *contentLength = n;
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
  // Bounded, dependency-free URL join into a static buffer (single-threaded
  // loop, so one scratch buffer is enough; length is bounded by the caller's
  // path size).
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
// The sensor read seam: ONE read. It reports whether the read itself succeeded;
// the SDK's readSensor() decides whether the returned number is usable.
// ---------------------------------------------------------------------------
static bool readTemperatureC(float* out) {
  if (out == 0) return false;
  // Replace with a real driver call (DHT/DS18B20/BME280/...). This stand-in
  // simulates an intermittent bus: it fails some reads outright and, on a
  // third kind of attempt, returns a non-finite value the reader must retry.
  static uint32_t n = 0;
  ++n;
  if (n % 5 == 0) {
    *out = NAN;  // answered, but not with a number -> InvalidValue path
    return true;
  }
  if (n % 3 == 0) {
    return false;  // no reading at all (bus glitch) -> retried
  }
  *out = 21.5f + static_cast<float>(n % 7) * 0.25f;
  return true;
}

// ---------------------------------------------------------------------------
// SDK objects (static storage; no heap, safe to construct at boot).
// ---------------------------------------------------------------------------
static insight::InsightBuffer gBuffer;
static insight::InsightSend gSend;
static insight::InsightDiagnostics gDiag;
static HttpClientTransport gTransport(kApiBase);

static uint32_t gLastSampleMs = 0;

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

  // Wire the send policy's two seams. Buffering is separated from transmitting,
  // so captures keep flowing even while the network is down.
  gBuffer.setBufferSize(64);
  gSend.setBuffer(&gBuffer);
  gSend.setTransport(&gTransport);  // path defaults to /v1/telemetry

  // Diagnostics are OPT-IN. RSSI is only known once associated; uptime is
  // always known. Turning the master switch on with both fields enabled makes
  // the payload carry "rssi" + "uptime_ms" alongside the app metrics.
  gDiag.setEnabled(true);
  gDiag.setRssiEnabled(true);
  gDiag.setUptimeEnabled(true);
}

void loop() {
  const uint32_t now = millis();

  // --- sample on a fixed cadence, with retries, never fabricating a value ---
  if (now - gLastSampleMs >= kSamplePeriodMs) {
    gLastSampleMs = now;

    float celsius = 0.0f;
    const insight::SensorReadResult r =
        insight::readSensor(&readTemperatureC, insight::kSensorDefaultAttempts,
                            &celsius);
    if (insight::isSensorReading(r)) {
      gSend.send(kTempKey, celsius);  // queued; transmitted by flush()
    } else {
      // Honest "sensor is down" report: an explicit null, never a made-up
      // number. The ingress contract accepts it.
      gSend.send(kTempKey, insight::MetricValue::null());
    }

    // A second, plain metric that rides the same queue.
    gSend.send(kLightKey, 300.0f + static_cast<float>(now % 100));
  }

  // --- diagnostics: refreshed each pass, still inert unless enabled above ---
  gDiag.setUptimeMillis(now);
#if defined(ESP8266) || defined(ESP32)
  if (WiFi.status() == WL_CONNECTED) {
    gDiag.setRssi(WiFi.RSSI());
  }
#endif

  // --- non-blocking flush: schedule retries, never sleep on them ----------
  if (gSend.isReady(now)) {
    gSend.flush(now);
  }

  // A healthy loop yields; a real watchdog feed would live here too.
  delay(20);
}
