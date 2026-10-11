#include <unity.h>

#include <cstring>

#include "Insight.h"
#include "InsightTransport.h"

// Records every call and returns a scripted outcome, so the seam can be
// exercised end-to-end without touching a real network.
class FakeTransport : public insight::InsightTransport {
 public:
  int postCount = 0;
  int getCount = 0;
  char lastPath[128] = {0};
  char lastJson[256] = {0};

  // Scripted results. Defaults model a successful round trip.
  insight::HttpOutcome postResult = insight::HttpOutcome::ok(204);
  insight::HttpOutcome getResult = insight::HttpOutcome::ok(200);
  const char* getBody = "ok";

  insight::HttpOutcome postJson(const char* path, const char* json) override {
    ++postCount;
    std::strncpy(lastPath, path, sizeof(lastPath) - 1);
    std::strncpy(lastJson, json, sizeof(lastJson) - 1);
    return postResult;
  }

  insight::HttpOutcome get(const char* path, char* buffer, size_t bufferLen,
                           size_t* contentLength) override {
    ++getCount;
    std::strncpy(lastPath, path, sizeof(lastPath) - 1);
    if (bufferLen > 0) {
      std::strncpy(buffer, getBody, bufferLen - 1);
      buffer[bufferLen - 1] = '\0';
    }
    if (contentLength != 0) {
      const size_t len = std::strlen(getBody);
      *contentLength = len < bufferLen ? len : bufferLen;
    }
    return getResult;
  }
};

void setUp(void) {}

void tearDown(void) {}

// The client must route its request through the injected transport: the
// fake records the call, which is proof the seam is actually used.
void test_insight_routes_request_through_transport(void) {
  insight::Insight client;
  FakeTransport fake;

  client.setTransport(&fake);
  TEST_ASSERT_EQUAL_INT(0, fake.postCount);

  insight::HttpOutcome outcome =
      client.post("/v1/events", "{\"event\":\"blink\"}");

  TEST_ASSERT_EQUAL_INT(1, fake.postCount);
  TEST_ASSERT_EQUAL_STRING("/v1/events", fake.lastPath);
  TEST_ASSERT_EQUAL_STRING("{\"event\":\"blink\"}", fake.lastJson);
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Ok, outcome.kind);
  TEST_ASSERT_EQUAL_INT(204, outcome.status);
}

// A response is surfaced with its HTTP status code, whatever the code.
void test_status_is_surfaced_on_success(void) {
  insight::Insight client;
  FakeTransport fake;

  fake.postResult = insight::HttpOutcome::ok(204);
  client.setTransport(&fake);
  insight::HttpOutcome accepted = client.post("/v1/events", "{}");
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Ok, accepted.kind);
  TEST_ASSERT_EQUAL_INT(204, accepted.status);

  fake.postResult = insight::HttpOutcome::ok(400);
  insight::HttpOutcome rejected = client.post("/v1/events", "{}");
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Ok, rejected.kind);
  TEST_ASSERT_EQUAL_INT(400, rejected.status);
  TEST_ASSERT_EQUAL_INT(2, fake.postCount);
}

// A timeout is distinct from a server response and from an error.
void test_timeout_is_surfaced(void) {
  insight::Insight client;
  FakeTransport fake;

  fake.postResult = insight::HttpOutcome::timeout();
  client.setTransport(&fake);
  insight::HttpOutcome outcome = client.post("/v1/events", "{}");

  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Timeout, outcome.kind);
}

// A transport-level failure is surfaced as Error.
void test_transport_error_is_surfaced(void) {
  insight::Insight client;
  FakeTransport fake;

  fake.postResult = insight::HttpOutcome::error();
  client.setTransport(&fake);
  insight::HttpOutcome outcome = client.post("/v1/events", "{}");

  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Error, outcome.kind);
}

// With no transport installed the client fails cleanly instead of crashing.
void test_request_without_transport_is_error(void) {
  insight::Insight client;
  insight::HttpOutcome outcome = client.post("/v1/events", "{}");
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Error, outcome.kind);
}

void test_get_fills_caller_buffer(void) {
  insight::Insight client;
  FakeTransport fake;
  char buffer[16] = {0};

  client.setTransport(&fake);
  insight::HttpOutcome outcome = client.get("/v1/health", buffer, sizeof(buffer));

  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Ok, outcome.kind);
  TEST_ASSERT_EQUAL_INT(1, fake.getCount);
  TEST_ASSERT_EQUAL_STRING("/v1/health", fake.lastPath);
  TEST_ASSERT_EQUAL_STRING("ok", buffer);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_insight_routes_request_through_transport);
  RUN_TEST(test_status_is_surfaced_on_success);
  RUN_TEST(test_timeout_is_surfaced);
  RUN_TEST(test_transport_error_is_surfaced);
  RUN_TEST(test_request_without_transport_is_error);
  RUN_TEST(test_get_fills_caller_buffer);
  return UNITY_END();
}
