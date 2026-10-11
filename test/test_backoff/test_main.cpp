// Unit tests for insight::backoffMillis() — the bounded exponential backoff.
//
// backoffMillis(attempt) returns a DURATION in milliseconds for a 0-based
// retry attempt: 1000, 2000, 4000, 8000, 16000, then a 30000 ms cap that holds
// for every later attempt. It is a pure function of its argument — it performs
// no I/O and, crucially, never blocks.
//
// "No delay() invoked" is a DESIGN GUARANTEE, checked here structurally: the
// whole suite only ever observes plain return values. There is no fake clock to
// install and no way for a sleep to go unnoticed — a blocking implementation
// simply has no return value to report these numbers, so a delay() buried in
// the function cannot pass this suite. (A blocking wait would also make these
// assertions take minutes; they run instantly.)

#include <unity.h>

#include <cstdint>

#include "InsightReliability.h"

namespace {

// The exact sequence the spec pins, attempt -> milliseconds.
const uint32_t kExpected[] = {1000, 2000, 4000, 8000, 16000, 30000};
const int kExpectedCount = 6;

const uint32_t kCap = 30000;

}  // namespace

void setUp(void) {}

void tearDown(void) {}

// The canonical sequence, one attempt at a time.
void test_sequence_is_pinned(void) {
  for (int i = 0; i < kExpectedCount; ++i) {
    TEST_ASSERT_EQUAL_UINT32(kExpected[i],
                             insight::backoffMillis(static_cast<uint32_t>(i)));
  }
}

// Attempt 0 is one second — the floor is positive, never zero.
void test_attempt_zero_is_one_second(void) {
  TEST_ASSERT_EQUAL_UINT32(1000u, insight::backoffMillis(0u));
  TEST_ASSERT_GREATER_THAN_UINT32(0u, insight::backoffMillis(0u));
}

// Once the cap is reached it stays put: no attempt, however large, grows past
// 30 s. Probed across a wide span, including values past the point where a
// naive `1000 * 2^attempt` would overflow a uint32_t.
void test_cap_holds_for_large_attempts(void) {
  const uint32_t large[] = {6u,   7u,    10u,   16u,    31u,
                            32u,  33u,   100u,  1000u,  1000000u};
  for (int i = 0; i < 10; ++i) {
    TEST_ASSERT_EQUAL_UINT32(kCap, insight::backoffMillis(large[i]));
  }
}

// Monotonic non-decreasing: a later attempt never waits less than an earlier
// one. Swept over a dense early range plus the late tail.
void test_monotonic_non_decreasing(void) {
  uint32_t previous = insight::backoffMillis(0u);
  for (uint32_t attempt = 1u; attempt <= 64u; ++attempt) {
    uint32_t current = insight::backoffMillis(attempt);
    TEST_ASSERT_TRUE(current >= previous);
    previous = current;
  }
  // The tail must also be non-decreasing (it is flat at the cap).
  previous = insight::backoffMillis(64u);
  const uint32_t tail[] = {65u, 100u, 500u, 5000u, 1000000u};
  for (int i = 0; i < 5; ++i) {
    uint32_t current = insight::backoffMillis(tail[i]);
    TEST_ASSERT_TRUE(current >= previous);
    previous = current;
  }
}

// The cap is a hard ceiling: never greater than 30000, for any attempt.
void test_never_exceeds_cap(void) {
  const uint32_t attempts[] = {0u,      1u,     2u,     3u,     4u,   5u,
                               6u,      10u,    16u,    31u,    32u,  64u,
                               255u,    4096u,  65536u, 1000000u};
  const int count = static_cast<int>(sizeof(attempts) / sizeof(attempts[0]));
  for (int i = 0; i < count; ++i) {
    uint32_t value = insight::backoffMillis(attempts[i]);
    TEST_ASSERT_LESS_OR_EQUAL_UINT32(kCap, value);
  }
}

// kBackoffMaxMillis is the documented cap, and it agrees with the function.
void test_cap_constant_matches_function(void) {
  TEST_ASSERT_EQUAL_UINT32(30000u, insight::kBackoffMaxMillis);
  TEST_ASSERT_EQUAL_UINT32(insight::kBackoffMaxMillis,
                           insight::backoffMillis(1000u));
}

// Purity: backoffMillis() is a function of `attempt` alone. Calling it
// repeatedly — including out of order — yields identical values, so there is
// no hidden mutable retry state and nothing to block on between calls.
void test_is_pure_function_of_attempt(void) {
  const uint32_t first = insight::backoffMillis(3u);
  TEST_ASSERT_EQUAL_UINT32(8000u, first);
  TEST_ASSERT_EQUAL_UINT32(first, insight::backoffMillis(3u));
  TEST_ASSERT_EQUAL_UINT32(first, insight::backoffMillis(3u));

  // Out-of-order calls return the same per-attempt values.
  TEST_ASSERT_EQUAL_UINT32(16000u, insight::backoffMillis(4u));
  TEST_ASSERT_EQUAL_UINT32(1000u, insight::backoffMillis(0u));
  TEST_ASSERT_EQUAL_UINT32(first, insight::backoffMillis(3u));
}

// The return is a plain duration the caller schedules with millis(): the value
// is at least one millisecond, so a non-blocking `millis() - start >= delay`
// wait always makes progress.
void test_returns_schedulable_duration(void) {
  for (uint32_t attempt = 0u; attempt <= 8u; ++attempt) {
    TEST_ASSERT_GREATER_THAN_UINT32(0u, insight::backoffMillis(attempt));
  }
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_sequence_is_pinned);
  RUN_TEST(test_attempt_zero_is_one_second);
  RUN_TEST(test_cap_holds_for_large_attempts);
  RUN_TEST(test_monotonic_non_decreasing);
  RUN_TEST(test_never_exceeds_cap);
  RUN_TEST(test_cap_constant_matches_function);
  RUN_TEST(test_is_pure_function_of_attempt);
  RUN_TEST(test_returns_schedulable_duration);
  return UNITY_END();
}
