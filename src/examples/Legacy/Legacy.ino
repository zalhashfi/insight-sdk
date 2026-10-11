// Legacy — an OLD-STYLE sketch, written before the modern surface existed.
//
// It proves the new API is OPT-IN: a sketch that reaches for nothing but the
// original minimal client (insight::Insight + the transport seam) still
// compiles and works unchanged. No buffering, no send policy, no diagnostics,
// no OTA, no watchdog, no sensor-retry helper — none of it is required, and
// none of it is pulled in by including <Insight.h>. That source compatibility
// is the point: existing firmware keeps building, and the richer policies are
// things a sketch must deliberately reach for.
//
// The whole sketch is: include the two original headers, point a transport at
// a path, and POST. Nothing here changed when the rest of the SDK grew.
//
// Compiles for ESP32 and ESP8266; the Wi-Fi include is the only platform split.

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
#include <InsightTransport.h>

static const char* kWifiSsid = "your-ssid";
static const char* kWifiPass = "your-password";
static const char* kApiBase = "http://192.168.1.10:8080";

// A minimal transport, exactly the seam the client has always required.
class LegacyTransport : public insight::InsightTransport {
 public:
  explicit LegacyTransport(const char* base) : base_(base) {}

  insight::HttpOutcome postJson(const char* path, const char* json) override {
#if defined(ESP8266) || defined(ESP32)
    WiFiClient client;
    HTTPClient http;
    if (!http.begin(client, urlFor(path))) return insight::HttpOutcome::error();
    http.addHeader("Content-Type", "application/json");
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

static LegacyTransport gTransport(kApiBase);
static insight::Insight gClient;

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

  gClient.begin();
  gClient.setTransport(&gTransport);
}

void loop() {
  // The plain, hand-rolled POST that predates every policy in the modern SDK.
  gClient.post("/v1/telemetry", "{\"key\":\"temperature_c\",\"value\":21.5}");
  delay(10000);
}
