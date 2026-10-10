#include <unity.h>

#include "Insight.h"

void setUp(void) {}

void tearDown(void) {}

void test_insight_stub_begins(void) {
  insight::Insight client;
  TEST_ASSERT_TRUE(client.begin());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_insight_stub_begins);
  return UNITY_END();
}
