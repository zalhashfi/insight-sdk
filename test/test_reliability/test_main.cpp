// Unit tests for insight::decide() — the reachability/retry classifier.
//
// The classifier is pure: given a transport HttpOutcome it says whether the
// request succeeded, should be retried verbatim, or should be discarded. This
// suite pins every branch of that table, including the boundaries, so a
// refactor cannot silently turn e.g. a 400 into a retry or a 503 into a drop.
//
// Decisions are surfaced as a plain enum class, so each assertion first
// narrows it to int to keep the diagnostics readable in the Unity output.

#include <unity.h>

#include "InsightReliability.h"
#include "InsightTransport.h"

namespace {

// Convenience: classify an "Ok" reply with a given HTTP status.
int decideStatus(int httpStatus) {
  return static_cast<int>(
      insight::decide(insight::HttpOutcome::ok(httpStatus)));
}

int decideKind(insight::HttpOutcome::Kind kind) {
  return static_cast<int>(
      insight::decide(insight::HttpOutcome(kind, 0)));
}

const int SUCCESS = static_cast<int>(insight::Decision::Success);
const int RETRY = static_cast<int>(insight::Decision::Retry);
const int DISCARD = static_cast<int>(insight::Decision::Discard);

}  // namespace

void setUp(void) {}

void tearDown(void) {}

// 2xx is the only success class; 200 and 204 are the common shapes.
void test_2xx_is_success(void) {
  TEST_ASSERT_EQUAL_INT(SUCCESS, decideStatus(200));
  TEST_ASSERT_EQUAL_INT(SUCCESS, decideStatus(201));
  TEST_ASSERT_EQUAL_INT(SUCCESS, decideStatus(204));
  TEST_ASSERT_EQUAL_INT(SUCCESS, decideStatus(299));
}

// 408 (request timeout) and 429 (rate limited) are the two transient 4xx.
void test_408_and_429_are_retried(void) {
  TEST_ASSERT_EQUAL_INT(RETRY, decideStatus(408));
  TEST_ASSERT_EQUAL_INT(RETRY, decideStatus(429));
}

// Any 5xx is a server-side failure worth repeating.
void test_5xx_is_retried(void) {
  TEST_ASSERT_EQUAL_INT(RETRY, decideStatus(500));
  TEST_ASSERT_EQUAL_INT(RETRY, decideStatus(502));
  TEST_ASSERT_EQUAL_INT(RETRY, decideStatus(503));
  TEST_ASSERT_EQUAL_INT(RETRY, decideStatus(504));
}

// Permanent 4xx (bad request, auth, not found, ...) must not be retried.
void test_other_4xx_is_discarded(void) {
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(400));
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(401));
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(403));
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(404));
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(413));
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(499));
}

// Boundaries around the retryable set: 407/409 are ordinary 4xx, while the
// 5xx window starts exactly at 500.
void test_status_class_boundaries(void) {
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(407));
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(409));
  TEST_ASSERT_EQUAL_INT(RETRY, decideStatus(500));
  TEST_ASSERT_EQUAL_INT(RETRY, decideStatus(599));
}

// 1xx/3xx, and the degenerate status 0, are unexpected on this seam: they are
// definitive answers, so they are discarded rather than retried.
void test_other_statuses_are_discarded(void) {
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(0));
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(100));
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(301));
  TEST_ASSERT_EQUAL_INT(DISCARD, decideStatus(399));
}

// A timeout carries no server verdict, so the request is retried.
void test_timeout_is_retried(void) {
  TEST_ASSERT_EQUAL_INT(RETRY, decideKind(insight::HttpOutcome::Timeout));
}

// A transport-level error is likewise retried.
void test_error_is_retried(void) {
  TEST_ASSERT_EQUAL_INT(RETRY, decideKind(insight::HttpOutcome::Error));
}

// The classifier is pure: the same outcome always yields the same decision and
// the outcome itself is left untouched.
void test_decide_is_pure_and_total(void) {
  insight::HttpOutcome outcome = insight::HttpOutcome::ok(429);
  TEST_ASSERT_EQUAL_INT(RETRY, static_cast<int>(insight::decide(outcome)));
  TEST_ASSERT_EQUAL_INT(RETRY, static_cast<int>(insight::decide(outcome)));
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Ok, outcome.kind);
  TEST_ASSERT_EQUAL_INT(429, outcome.status);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_2xx_is_success);
  RUN_TEST(test_408_and_429_are_retried);
  RUN_TEST(test_5xx_is_retried);
  RUN_TEST(test_other_4xx_is_discarded);
  RUN_TEST(test_status_class_boundaries);
  RUN_TEST(test_other_statuses_are_discarded);
  RUN_TEST(test_timeout_is_retried);
  RUN_TEST(test_error_is_retried);
  RUN_TEST(test_decide_is_pure_and_total);
  return UNITY_END();
}
