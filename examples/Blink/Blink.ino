#include <Insight.h>
#include <InsightTransport.h>

// Minimal compile gate: the public headers (client + transport seam) must
// build cleanly for both ESP32 and ESP8266 Arduino toolchains.
void setup() {
  insight::Insight client;
  client.begin();
}

void loop() {}
