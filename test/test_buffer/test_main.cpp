// Unit tests for insight::InsightBuffer — the RAM FIFO of metric samples.
//
// The buffer is the retry/drain staging area the client flushes to the
// server, so its contract is pinned here rather than left to the call sites:
// what capacity means, what happens on overflow, how duplicate keys collapse,
// which values/keys survive validation, and what "disabled" (size 0) means.
//
// The rules asserted below are the ones documented on InsightBuffer itself;
// if the two ever disagree, this suite is the tie-breaker.

#include <unity.h>

#include <cmath>
#include <cstring>
#include <limits>

#include "InsightBuffer.h"

namespace {

// Reach into the buffer through its documented public accessors only.
const char* keyOf(const insight::InsightBuffer& b, size_t i) {
  insight::BufferEntryView v;
  if (!b.at(i, &v)) return "<out-of-range>";
  return v.key;
}

bool nullOf(const insight::InsightBuffer& b, size_t i) {
  insight::BufferEntryView v;
  return b.at(i, &v) && v.null;
}

float valueOf(const insight::InsightBuffer& b, size_t i) {
  insight::BufferEntryView v;
  return b.at(i, &v) ? v.value : 0.0f;
}

// Drain-only sink: records the keys in the order they were visited.
struct KeyLog {
  char seen[64][INSIGHT_BUFFER_KEY_MAX + 1];
  int count;
  KeyLog() : count(0) {}
  void operator()(const insight::BufferEntryView& v) {
    if (count >= 64) return;
    std::strncpy(seen[count], v.key, INSIGHT_BUFFER_KEY_MAX);
    seen[count][INSIGHT_BUFFER_KEY_MAX] = '\0';
    ++count;
  }
};

}  // namespace

void setUp(void) {}

void tearDown(void) {}

// ---------------------------------------------------------------------------
// Capacity / FIFO eviction
// ---------------------------------------------------------------------------

// The constructor applies the documented default of 200.
void test_default_capacity_is_200(void) {
  insight::InsightBuffer b;
  TEST_ASSERT_EQUAL_INT(200, static_cast<int>(b.capacity()));
  TEST_ASSERT_EQUAL_INT(200, static_cast<int>(insight::InsightBuffer::kDefaultSize));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.dropped()));
}

// Filling to N keeps size at N; the (N+1)th push drops the OLDEST (FIFO) and
// bumps dropped() by exactly one.
void test_capacity_boundary_evicts_oldest_fifo(void) {
  insight::InsightBuffer b;
  b.setBufferSize(3);

  TEST_ASSERT_TRUE(b.push("a", 1.0f));
  TEST_ASSERT_TRUE(b.push("b", 2.0f));
  TEST_ASSERT_TRUE(b.push("c", 3.0f));
  TEST_ASSERT_EQUAL_INT(3, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.dropped()));

  TEST_ASSERT_TRUE(b.push("d", 4.0f));
  TEST_ASSERT_EQUAL_INT(3, static_cast<int>(b.size()));  // capacity honoured
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.dropped()));

  // Oldest ("a") is gone; b, c, d remain in arrival order.
  TEST_ASSERT_EQUAL_STRING("b", keyOf(b, 0));
  TEST_ASSERT_EQUAL_STRING("c", keyOf(b, 1));
  TEST_ASSERT_EQUAL_STRING("d", keyOf(b, 2));
  TEST_ASSERT_FLOAT_WITHIN(0.001f, 4.0f, valueOf(b, 2));
}

// Eviction keeps being the oldest as the ring wraps, and dropped() counts
// every eviction (not just the first).
void test_eviction_is_continuous_and_counted(void) {
  insight::InsightBuffer b;
  b.setBufferSize(2);

  b.push("k0", 0.0f);
  b.push("k1", 1.0f);
  b.push("k2", 2.0f);  // evicts k0
  b.push("k3", 3.0f);  // evicts k1
  b.push("k4", 4.0f);  // evicts k2

  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(3, static_cast<int>(b.dropped()));
  TEST_ASSERT_EQUAL_STRING("k3", keyOf(b, 0));
  TEST_ASSERT_EQUAL_STRING("k4", keyOf(b, 1));
}

// ---------------------------------------------------------------------------
// Last-wins per key
// ---------------------------------------------------------------------------

// Pushing a key that is already queued overwrites its value in place; it does
// NOT create a second entry and does NOT move the entry's queue position.
void test_last_wins_per_key(void) {
  insight::InsightBuffer b;
  b.setBufferSize(4);

  b.push("temp", 10.0f);
  b.push("hum", 50.0f);
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.size()));

  TEST_ASSERT_TRUE(b.push("temp", 11.0f));  // same key again
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.size()));  // still two entries

  // The newer value is what is stored, and the entry stays at its slot.
  insight::MetricValue mv;
  TEST_ASSERT_TRUE(b.get("temp", &mv));
  TEST_ASSERT_TRUE(mv.hasValue);
  TEST_ASSERT_FLOAT_WITHIN(0.001f, 11.0f, mv.value);
  TEST_ASSERT_EQUAL_STRING("temp", keyOf(b, 0));
  TEST_ASSERT_EQUAL_STRING("hum", keyOf(b, 1));
}

// Last-wins survives a wrapped ring: the duplicate is found wherever it sits.
void test_last_wins_after_wrap(void) {
  insight::InsightBuffer b;
  b.setBufferSize(2);

  b.push("x", 1.0f);
  b.push("y", 2.0f);
  b.push("z", 3.0f);  // evicts x; queue is y, z

  TEST_ASSERT_TRUE(b.push("y", 22.0f));  // y is now the older entry
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.dropped()));  // no extra eviction

  insight::MetricValue mv;
  TEST_ASSERT_TRUE(b.get("y", &mv));
  TEST_ASSERT_FLOAT_WITHIN(0.001f, 22.0f, mv.value);
  TEST_ASSERT_EQUAL_STRING("y", keyOf(b, 0));
}

// ---------------------------------------------------------------------------
// Value validation: NaN/Inf rejected, null accepted
// ---------------------------------------------------------------------------

// A non-finite numeric value is rejected outright: it is not stored and it
// does not evict anything.
void test_nan_and_inf_are_rejected(void) {
  insight::InsightBuffer b;
  b.setBufferSize(3);
  b.push("ok", 1.0f);

  const float nan = std::numeric_limits<float>::quiet_NaN();
  const float inf = std::numeric_limits<float>::infinity();

  TEST_ASSERT_FALSE(b.push("nan", nan));
  TEST_ASSERT_FALSE(b.push("pinf", inf));
  TEST_ASSERT_FALSE(b.push("ninf", -inf));

  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.size()));      // only "ok" held
  TEST_ASSERT_EQUAL_INT(3, static_cast<int>(b.rejected()));  // all three counted
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.dropped()));   // no eviction

  insight::MetricValue mv;
  TEST_ASSERT_FALSE(b.get("nan", &mv));
  TEST_ASSERT_FALSE(b.get("pinf", &mv));
  TEST_ASSERT_FALSE(b.get("ninf", &mv));
}

// A null value is a legitimate sample: accepted and stored, flagged null.
void test_null_is_accepted_and_stored(void) {
  insight::InsightBuffer b;
  b.setBufferSize(3);

  TEST_ASSERT_TRUE(b.push("hum", insight::MetricValue::null()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.rejected()));
  TEST_ASSERT_EQUAL_STRING("hum", keyOf(b, 0));
  TEST_ASSERT_TRUE(nullOf(b, 0));

  insight::MetricValue mv;
  TEST_ASSERT_TRUE(b.get("hum", &mv));
  TEST_ASSERT_FALSE(mv.hasValue);  // stored as JSON null, not a number
}

// A later numeric push for a key that held null replaces it (last-wins), and
// vice versa; the null flag tracks the newest value.
void test_null_and_number_interleave_last_wins(void) {
  insight::InsightBuffer b;
  b.setBufferSize(3);

  b.push("k", insight::MetricValue::null());
  b.push("k", 7.0f);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.size()));
  TEST_ASSERT_FALSE(nullOf(b, 0));
  TEST_ASSERT_FLOAT_WITHIN(0.001f, 7.0f, valueOf(b, 0));

  b.push("k", insight::MetricValue::null());
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.size()));
  TEST_ASSERT_TRUE(nullOf(b, 0));
}

// A rejected (NaN) push must NOT clobber a good value already stored; the
// overwrite only happens once validation has passed.
void test_rejected_push_does_not_overwrite_stored_value(void) {
  insight::InsightBuffer b;
  b.push("temp", 20.0f);

  TEST_ASSERT_FALSE(b.push("temp", std::numeric_limits<float>::quiet_NaN()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.dropped()));

  insight::MetricValue mv;
  TEST_ASSERT_TRUE(b.get("temp", &mv));
  TEST_ASSERT_FLOAT_WITHIN(0.001f, 20.0f, mv.value);  // untouched
}

// ---------------------------------------------------------------------------
// Key validation
// ---------------------------------------------------------------------------

// Empty (and null) keys are rejected and counted as rejections.
void test_empty_key_is_rejected(void) {
  insight::InsightBuffer b;
  b.setBufferSize(3);

  TEST_ASSERT_FALSE(b.push("", 1.0f));
  TEST_ASSERT_FALSE(b.push(static_cast<const char*>(0), 1.0f));
  TEST_ASSERT_FALSE(b.push("", insight::MetricValue::null()));

  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(3, static_cast<int>(b.rejected()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.dropped()));
}

// A key of exactly kMaxKeyLen bytes is the inclusive upper bound and is
// accepted, stored in full.
void test_key_at_max_length_is_accepted(void) {
  insight::InsightBuffer b;
  const size_t max = insight::InsightBuffer::kMaxKeyLen;

  char key[INSIGHT_BUFFER_KEY_MAX + 2];
  for (size_t i = 0; i < max; ++i) key[i] = 'k';
  key[max] = '\0';

  TEST_ASSERT_TRUE(b.push(key, 1.0f));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.rejected()));
  TEST_ASSERT_EQUAL_STRING(key, keyOf(b, 0));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(max), static_cast<int>(std::strlen(b.oldest().key)));
}

// One byte past the limit is overlong and rejected (not truncated).
void test_overlong_key_is_rejected(void) {
  insight::InsightBuffer b;
  const size_t max = insight::InsightBuffer::kMaxKeyLen;

  char overlong[INSIGHT_BUFFER_KEY_MAX + 2];
  for (size_t i = 0; i <= max; ++i) overlong[i] = 'x';
  overlong[max + 1] = '\0';  // max + 1 characters

  TEST_ASSERT_FALSE(b.push(overlong, 1.0f));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.rejected()));
}

// ---------------------------------------------------------------------------
// Disabled buffering (size 0)
// ---------------------------------------------------------------------------

// Documented rule: with size 0 the buffer is disabled — pushes still return
// true (they are valid samples) but nothing is retained, and because a whole
// disabled stream is discarded by design, individual samples are NOT counted
// as `dropped`.
void test_disabled_buffer_accepts_but_retains_nothing(void) {
  insight::InsightBuffer b;
  b.setBufferSize(0);

  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.capacity()));
  TEST_ASSERT_TRUE(b.push("a", 1.0f));
  TEST_ASSERT_TRUE(b.push("a", 2.0f));
  TEST_ASSERT_TRUE(b.push("b", insight::MetricValue::null()));

  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.dropped()));

  insight::MetricValue mv;
  TEST_ASSERT_FALSE(b.get("a", &mv));
  TEST_ASSERT_EQUAL_STRING("", b.oldest().key);
}

// Validation still applies while disabled: an invalid key or a NaN is
// rejected (returns false) rather than silently accepted.
void test_disabled_buffer_still_validates(void) {
  insight::InsightBuffer b;
  b.setBufferSize(0);

  TEST_ASSERT_FALSE(b.push("", 1.0f));
  TEST_ASSERT_FALSE(b.push("n", std::numeric_limits<float>::quiet_NaN()));
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.rejected()));

  // A null with a bad key is still a bad key.
  TEST_ASSERT_FALSE(b.push("", insight::MetricValue::null()));
  TEST_ASSERT_EQUAL_INT(3, static_cast<int>(b.rejected()));
}

// Disabling an already-populated buffer discards what it held; re-enabling
// starts it empty again.
void test_disable_then_reenable_starts_empty(void) {
  insight::InsightBuffer b;
  b.setBufferSize(4);
  b.push("a", 1.0f);
  b.push("b", 2.0f);
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.size()));

  b.setBufferSize(0);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.dropped()));  // both evicted

  b.setBufferSize(2);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.capacity()));
  TEST_ASSERT_TRUE(b.push("c", 3.0f));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.size()));
}

// ---------------------------------------------------------------------------
// Resizing
// ---------------------------------------------------------------------------

// Growing preserves entries; shrinking evicts the oldest and counts them.
void test_resize_shrink_keeps_newest(void) {
  insight::InsightBuffer b;
  b.setBufferSize(4);
  b.push("a", 1.0f);
  b.push("b", 2.0f);
  b.push("c", 3.0f);
  b.push("d", 4.0f);

  b.setBufferSize(2);
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.dropped()));
  TEST_ASSERT_EQUAL_STRING("c", keyOf(b, 0));  // a, b evicted (oldest)
  TEST_ASSERT_EQUAL_STRING("d", keyOf(b, 1));

  b.setBufferSize(5);  // grow: existing entries kept
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_STRING("c", keyOf(b, 0));
}

// ---------------------------------------------------------------------------
// Iteration / drain
// ---------------------------------------------------------------------------

// at() walks oldest -> newest and reports out-of-range cleanly.
void test_iteration_is_oldest_to_newest(void) {
  insight::InsightBuffer b;
  b.setBufferSize(3);
  b.push("a", 1.0f);
  b.push("b", 2.0f);
  b.push("c", 3.0f);

  const char* expected[] = {"a", "b", "c"};
  for (size_t i = 0; i < 3; ++i) {
    insight::BufferEntryView v;
    TEST_ASSERT_TRUE(b.at(i, &v));
    TEST_ASSERT_EQUAL_STRING(expected[i], v.key);
    TEST_ASSERT_EQUAL_INT(static_cast<int>(std::strlen(expected[i])),
                          static_cast<int>(v.keyLen));
  }

  insight::BufferEntryView out;
  TEST_ASSERT_FALSE(b.at(3, &out));  // past the end
  TEST_ASSERT_FALSE(b.at(0, 0));     // null out-param
}

// drain() visits every entry oldest -> newest and empties the buffer, while
// leaving the cumulative counters alone.
void test_drain_visits_in_order_then_empties(void) {
  insight::InsightBuffer b;
  b.setBufferSize(3);
  b.push("a", 1.0f);
  b.push("b", 2.0f);
  b.push("c", 3.0f);
  b.push("d", 4.0f);  // evicts a; dropped == 1

  KeyLog log;
  b.drain(&log);

  TEST_ASSERT_EQUAL_INT(3, log.count);
  TEST_ASSERT_EQUAL_STRING("b", log.seen[0]);
  TEST_ASSERT_EQUAL_STRING("c", log.seen[1]);
  TEST_ASSERT_EQUAL_STRING("d", log.seen[2]);

  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.dropped()));  // cumulative
}

// A null visitor is a valid "discard everything" flush.
void test_drain_with_null_visitor_clears(void) {
  insight::InsightBuffer b;
  b.push("a", 1.0f);
  b.push("b", 2.0f);

  KeyLog* none = 0;
  b.drain(none);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.size()));
}

// clear() empties the buffer without touching the counters.
void test_clear_empties_without_touching_counters(void) {
  insight::InsightBuffer b;
  b.setBufferSize(2);
  b.push("a", 1.0f);
  b.push("b", 2.0f);
  b.push("c", 3.0f);  // dropped == 1

  b.clear();
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.dropped()));
  TEST_ASSERT_EQUAL_STRING("", b.oldest().key);
}

// get() reports absence for a key that was never pushed or has been evicted.
void test_get_reports_absent_keys(void) {
  insight::InsightBuffer b;
  b.setBufferSize(2);
  b.push("a", 1.0f);
  b.push("b", 2.0f);
  b.push("c", 3.0f);  // evicts a

  insight::MetricValue mv;
  TEST_ASSERT_FALSE(b.get("a", &mv));  // evicted
  TEST_ASSERT_FALSE(b.get("nope", &mv));
  TEST_ASSERT_TRUE(b.get("c", &mv));
  TEST_ASSERT_FLOAT_WITHIN(0.001f, 3.0f, mv.value);
}

// A wrapped ring (head at the end of storage) still iterates in FIFO order.
void test_wrapped_ring_iterates_in_order(void) {
  insight::InsightBuffer b;
  b.setBufferSize(3);
  b.push("a", 1.0f);
  b.push("b", 2.0f);
  b.push("c", 3.0f);
  b.push("d", 4.0f);  // evicts a, head wraps past slot 0

  TEST_ASSERT_EQUAL_STRING("b", b.oldest().key);
  TEST_ASSERT_EQUAL_STRING("d", b.newest().key);
  TEST_ASSERT_EQUAL_INT(3, static_cast<int>(b.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(b.dropped()));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_default_capacity_is_200);
  RUN_TEST(test_capacity_boundary_evicts_oldest_fifo);
  RUN_TEST(test_eviction_is_continuous_and_counted);
  RUN_TEST(test_last_wins_per_key);
  RUN_TEST(test_last_wins_after_wrap);
  RUN_TEST(test_nan_and_inf_are_rejected);
  RUN_TEST(test_null_is_accepted_and_stored);
  RUN_TEST(test_null_and_number_interleave_last_wins);
  RUN_TEST(test_rejected_push_does_not_overwrite_stored_value);
  RUN_TEST(test_empty_key_is_rejected);
  RUN_TEST(test_key_at_max_length_is_accepted);
  RUN_TEST(test_overlong_key_is_rejected);
  RUN_TEST(test_disabled_buffer_accepts_but_retains_nothing);
  RUN_TEST(test_disabled_buffer_still_validates);
  RUN_TEST(test_disable_then_reenable_starts_empty);
  RUN_TEST(test_resize_shrink_keeps_newest);
  RUN_TEST(test_iteration_is_oldest_to_newest);
  RUN_TEST(test_drain_visits_in_order_then_empties);
  RUN_TEST(test_drain_with_null_visitor_clears);
  RUN_TEST(test_clear_empties_without_touching_counters);
  RUN_TEST(test_get_reports_absent_keys);
  RUN_TEST(test_wrapped_ring_iterates_in_order);
  return UNITY_END();
}
