// ControlAck — the downlink half of a two-way device, end to end:
//
//     poll -> execute -> ack
//
// A project sets a variable in the UI; the server queues it as a pending
// control command addressed to this device; the device polls for it, acts on
// it, and acknowledges it by id so it is never handed back. It exercises the
// SDK's control policy:
//
//   * insight::InsightControl::poll()  — GET /v1/control and parse the frozen
//                                        envelope `{"control":[{"id","variable",
//                                        "value"}]}` into a bounded batch. A
//                                        malformed body, a non-2xx status, a
//                                        timeout or a transport error all yield
//                                        "no batch", so the device NEVER acts on
//                                        half an answer. An empty array is a
//                                        VALID "nothing to do" answer.
//   * nextCommand()                    — walks the batch oldest-first, skipping
//                                        any id already acknowledged, so the
//                                        "execute" step is a plain loop.
//   * ack(ids, count)                  — POST {"ids":[...]} to
//                                        /v1/control/ack. Idempotent from the
//                                        device's own side: an id already acked
//                                        is filtered out (no second round trip)
//                                        and ids are remembered only once the
//                                        server has accepted, so a retry after a
//                                        lost 204 re-sends rather than stranding
//                                        the command.
//
// The loop never sleeps on a failed poll: the cadence is a millis() comparison,
// so a watchdog stays fed.
//
// Compiles for ESP32 and ESP8266; the Wi-Fi include and the small transport
// adapter below are the only board-specific code (the SDK itself is
// transport-agnostic and was proven on the host).

#if defined(ESP8266)
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#elif defined(ESP32)
#include <WiFi.h>
#include <HTTPClient.h>
#else
#include <Arduino.h>
#endif

#include <InsightControl.h>
#include <InsightTransport.h>

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
static const char* kWifiSsid = "your-ssid";
static const char* kWifiPass = "your-password";
static const char* kApiBase = "http://192.168.1.10:8080";  // ingress base URL
static const char* kDeviceKey = "esp-node-01";
static const uint32_t kControlPollPeriodMs = 3000;

// Pin the `led` variable drives. LED_BUILTIN is not defined for every
// esp32dev board definition, so fall back to the common on-board pin (2).
#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

// ---------------------------------------------------------------------------
// Transport adapter: the one place that knows about the platform's HTTP stack.
// It is the exact seam the SDK expects (InsightTransport), so the control
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
// Local actuation: map a variable/value pair onto this board.
//
// A real sketch routes these to its own hardware (a relay, an LED, a setpoint).
// The mapping is deliberately local: the SDK carries the command and the id; it
// never decides what a variable means. Returning false means "could not act",
// and the caller then leaves the id UN-acked so the server keeps offering it.
// ---------------------------------------------------------------------------
static bool executeCommand(const insight::ControlCommand& command) {
  if (command.variable[0] == '\0') return false;

#if defined(ESP8266) || defined(ESP32)
  if (strcmp(command.variable, "led") == 0) {
    const int level = command.valueIsNull ? 0 : atoi(command.value);
    pinMode(LED_BUILTIN, OUTPUT);
    digitalWrite(LED_BUILTIN, level ? HIGH : LOW);
    return true;
  }
#endif

  // Unknown variable: report the miss so the caller does not pretend success.
  return false;
}

// ---------------------------------------------------------------------------
// SDK objects (static storage; no heap, safe to construct at boot).
// ---------------------------------------------------------------------------
static HttpClientTransport gTransport(kApiBase);
static insight::InsightControl gControl;

static uint32_t gLastPollMs = 0;

void setup() {
  Serial.begin(115200);

#if defined(ESP8266) || defined(ESP32)
  pinMode(LED_BUILTIN, OUTPUT);
  WiFi.mode(WIFI_STA);
  WiFi.begin(kWifiSsid, kWifiPass);
  const uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(100);
  }
#endif

  // Wire the control policy's only seam. Paths default to the frozen
  // /v1/control and /v1/control/ack; nothing else needs configuring.
  gControl.setTransport(&gTransport);
}

void loop() {
  const uint32_t now = millis();

  // Poll on a fixed cadence (never a blocking wait).
  if (now - gLastPollMs < kControlPollPeriodMs) {
    delay(20);
    return;
  }
  gLastPollMs = now;

  // --- poll: GET /v1/control ------------------------------------------------
  insight::ControlBatch batch;
  if (!gControl.poll(&batch)) {
    // No usable answer this pass (offline, 401, 5xx, a malformed body). The
    // policy holds no state to unwind; just try again next cadence.
    Serial.println("control: poll failed, will retry");
    return;
  }
  if (batch.count == 0) {
    return;  // a valid "nothing to do" answer
  }

  // --- execute, then collect the ids that succeeded --------------------------
  // Two steps, not one-per-command: the batch is acknowledged in a SINGLE POST,
  // which is the shape the wire contract freezes (`{"ids":[...]}`). nextCommand()
  // reuses one `command` object, so ids are copied before the walk continues.
  char idStore[INSIGHT_CONTROL_MAX_COMMANDS][INSIGHT_CONTROL_ID_MAX + 1];
  const char* ackedIds[INSIGHT_CONTROL_MAX_COMMANDS];
  size_t ackedCount = 0;

  insight::ControlCommand command;
  while (gControl.nextCommand(batch, &command)) {
    Serial.print("control: ");
    Serial.print(command.variable);
    Serial.print(" = ");
    Serial.println(command.valueIsNull ? "(null)" : command.value);

    if (executeCommand(command)) {
      // Keep a copy of the id to acknowledge after the walk.
      size_t n = 0;
      while (command.id[n] != '\0' && n < INSIGHT_CONTROL_ID_MAX) {
        idStore[ackedCount][n] = command.id[n];
        ++n;
      }
      idStore[ackedCount][n] = '\0';
      ackedIds[ackedCount] = idStore[ackedCount];
      ++ackedCount;
    }
    // On a failed execution the id is NOT acked, so the server keeps the
    // command pending and we will see it again on the next poll.
  }

  // --- ack: POST {"ids":[...]} to /v1/control/ack ---------------------------
  if (ackedCount > 0 && !gControl.ack(ackedIds, ackedCount)) {
    // The POST was attempted and rejected; the ids were not recorded, so the
    // next poll re-offers the commands and this pass retries them.
    Serial.println("control: ack failed, will retry");
  }

  // A healthy loop yields; a real watchdog feed would live here too.
  delay(20);
}
