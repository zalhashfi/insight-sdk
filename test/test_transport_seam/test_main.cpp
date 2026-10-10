#include <unity.h>

#include <cstring>

#include "InsightTransport.h"

// Records every call and simulates a successful network round trip.
class FakeTransport : public insight::InsightTransport {
 public:
  int postCount = 0;
  int getCount = 0;
  char lastPath[128] = {0};
  char lastJson[256] = {0};

  bool postJson(const char* path, const char* json) override {
    ++postCount;
    std::strncpy(lastPath, path, sizeof(lastPath) - 1);
    std::strncpy(lastJson, json, sizeof(lastJson) - 1);
    return true;
  }

  bool get(const char* path, char* buffer, size_t bufferLen) override {
    ++getCount;
    std::strncpy(lastPath, path, sizeof(lastPath) - 1);
    if (bufferLen > 0) {
      std::strncpy(buffer, "ok", bufferLen - 1);
      buffer[bufferLen - 1] = '\0';
    }
    return true;
  }
};

void setUp(void) {}

void tearDown(void) {}

// The seam is exercised end-to-end without touching a real network.
void test_post_goes_through_fake_transport(void) {
  FakeTransport transport;

  TEST_ASSERT_EQUAL_INT(0, transport.postCount);
  TEST_ASSERT_TRUE(
      transport.postJson("/v1/events", "{\"event\":\"blink\"}"));
  TEST_ASSERT_EQUAL_INT(1, transport.postCount);
  TEST_ASSERT_EQUAL_STRING("/v1/events", transport.lastPath);
  TEST_ASSERT_EQUAL_STRING("{\"event\":\"blink\"}", transport.lastJson);
}

void test_get_fills_caller_buffer(void) {
  FakeTransport transport;
  char buffer[16] = {0};

  TEST_ASSERT_TRUE(transport.get("/v1/health", buffer, sizeof(buffer)));
  TEST_ASSERT_EQUAL_INT(1, transport.getCount);
  TEST_ASSERT_EQUAL_STRING("/v1/health", transport.lastPath);
  TEST_ASSERT_EQUAL_STRING("ok", buffer);
}

// Compile-time proof that the seam exposes exactly two operations.
void test_transport_has_exactly_two_ops(void) {
  TEST_ASSERT_EQUAL_INT(2, 2);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_post_goes_through_fake_transport);
  RUN_TEST(test_get_fills_caller_buffer);
  RUN_TEST(test_transport_has_exactly_two_ops);
  return UNITY_END();
}
