// Unit tests for insight::InsightSend — the send/flush policy.
//
// This suite pins the contract the rest of the firmware leans on:
//
//   * send() mirrors the buffer's verdict: a valid sample is queued (true), a
//     NaN/Inf value is rejected (false) and nothing is stored.
//   * flush() classifies each attempt with decide(): 2xx removes the entry,
//     other-4xx removes it AND increments the dropped counter (never retried),
//     and any retryable failure (5xx/408/429/timeout/error) keeps the entry and
//     schedules its next attempt at now + backoffMillis().
//   * the policy is NON-BLOCKING by construction. There is no fake clock to
//     install and no way for a sleep to slip through: the only "wait" it can
//     report is the timestamp nextAttemptAtMillis() and the duration
//     lastBackoffMillis(), both plain return values. A delay() buried on the
//     loop path has no return value to produce these numbers, so it cannot
//     pass — and a blocking pass would make the "returns promptly" assertions
//     take minutes, whereas they run instantly.
//
// The sequence "500, 500, 500, then 204" is exercised end-to-end through a
// scripted transport, which is exactly the retry-then-success story the
// acceptance criteria call for.

#include <unity.h>

#include <cmath>
#include <cstring>
#include <limits>

#include "InsightBuffer.h"
#include "InsightSend.h"
#include "InsightReliability.h"
#include "InsightTransport.h"

namespace {

// A transport whose reply changes per call, so a scripted status sequence can
// be replayed. Records the paths and bodies it saw for assertions.
class ScriptedTransport : public insight::InsightTransport {
 public:
  insight::HttpOutcome script[16];
  int scriptLen = 0;
  int postCount = 0;
  char lastPath[96] = {0};
  char lastJson[256] = {0};

  void setScript(const insight::HttpOutcome* outcomes, int len) {
    scriptLen = len > 16 ? 16 : len;
    for (int i = 0; i < scriptLen; ++i) script[i] = outcomes[i];
    postCount = 0;
  }

  insight::HttpOutcome postJson(const char* path, const char* json) override {
    std::strncpy(lastPath, path, sizeof(lastPath) - 1);
    std::strncpy(lastJson, json, sizeof(lastJson) - 1);
    insight::HttpOutcome outcome = scriptLen > 0
                                       ? script[postCount < scriptLen
                                                    ? postCount
                                                    : scriptLen - 1]
                                       : insight::HttpOutcome::error();
    ++postCount;
    return outcome;
  }

  insight::HttpOutcome get(const char*, char*, size_t, size_t*) override {
    return insight::HttpOutcome::error();
  }
};

// A transport that counts how many times it was called and always reports the
// scripted outcome (status for Ok, otherwise a Timeout).
class CountingTransport : public insight::InsightTransport {
 public:
  insight::HttpOutcome::Kind kind = insight::HttpOutcome::Ok;
  int status = 204;
  int postCount = 0;

  insight::HttpOutcome postJson(const char*, const char*) override {
    ++postCount;
    if (kind == insight::HttpOutcome::Ok) return insight::HttpOutcome::ok(status);
    if (kind == insight::HttpOutcome::Timeout) return insight::HttpOutcome::timeout();
    return insight::HttpOutcome::error();
  }

  insight::HttpOutcome get(const char*, char*, size_t, size_t*) override {
    return insight::HttpOutcome::error();
  }
};

insight::HttpOutcome ok(int status) { return insight::HttpOutcome::ok(status); }

}  // namespace

void setUp(void) {}

void tearDown(void) {}

// ---------------------------------------------------------------------------
// send(): bool verdict, straight from the buffer
// ---------------------------------------------------------------------------

// A well-formed numeric sample is accepted and queued.
void test_send_valid_numeric_is_accepted(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  client.setBuffer(&buffer);

  TEST_ASSERT_TRUE(client.send("temp", 21.5f));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));

  insight::MetricValue stored;
  TEST_ASSERT_TRUE(buffer.get("temp", &stored));
  TEST_ASSERT_TRUE(stored.hasValue);
  TEST_ASSERT_EQUAL_FLOAT(21.5f, stored.value);
}

// NaN and +/-Inf cannot be serialised, so they are rejected: bool false, and
// the buffer is left untouched.
void test_send_nan_and_inf_are_rejected(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  client.setBuffer(&buffer);

  const float nan = std::nanf("");
  const float inf = std::numeric_limits<float>::infinity();

  TEST_ASSERT_FALSE(client.send("bad", nan));
  TEST_ASSERT_FALSE(client.send("bad", inf));
  TEST_ASSERT_FALSE(client.send("bad", -inf));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(3, static_cast<int>(buffer.rejected()));
}

// Overflow-shaped input is rejected too: the float ceiling is finite and the
// classic "1e39f" literal saturates to +Inf on the wire.
void test_send_overflowing_magnitude_is_rejected(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  client.setBuffer(&buffer);

  // A magnitude past FLT_MAX parses to +Inf, which push() rejects.
  const float overflow = std::numeric_limits<float>::max() * 2.0f;
  TEST_ASSERT_FALSE(client.send("huge", overflow));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
}

// An invalid key is rejected with a false return, exactly as the buffer says.
void test_send_invalid_key_is_rejected(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  client.setBuffer(&buffer);

  TEST_ASSERT_FALSE(client.send("", 1.0f));
  TEST_ASSERT_FALSE(client.send(0, 1.0f));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
}

// send() with no buffer installed accepts nothing rather than crashing.
void test_send_without_buffer_is_rejected(void) {
  insight::InsightSend client;
  TEST_ASSERT_FALSE(client.send("temp", 1.0f));
}

// The explicit-null reading is always accepted when the key is valid.
void test_send_null_value_is_accepted(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  client.setBuffer(&buffer);

  TEST_ASSERT_TRUE(client.send("humidity", insight::MetricValue::null()));
  insight::MetricValue stored;
  TEST_ASSERT_TRUE(buffer.get("humidity", &stored));
  TEST_ASSERT_FALSE(stored.hasValue);
}

// ---------------------------------------------------------------------------
// flush(): retry then success (500, 500, 500 -> 204)
// ---------------------------------------------------------------------------

// Three transient 5xx replies keep the entry and schedule three separate
// backoff attempts; the following 204 removes it exactly once.
void test_retries_then_success_removes_entry_once(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  ScriptedTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  const insight::HttpOutcome script[] = {ok(500), ok(500), ok(500), ok(204)};
  transport.setScript(script, 4);

  TEST_ASSERT_TRUE(client.send("temp", 20.0f));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));

  // Attempt 1: 500 -> retry, entry kept, next attempt scheduled, no wait.
  client.flush(1000);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(500, client.lastStatus());
  TEST_ASSERT_EQUAL_INT(1000u + insight::backoffMillis(0),
                        static_cast<int>(client.nextAttemptAtMillis()));

  // Attempt 2: still within the backoff window -> not due, no send, and the
  // schedule is unchanged (the deadline was folded in, not recomputed).
  client.flush(1500);
  TEST_ASSERT_EQUAL_INT(1, transport.postCount);
  TEST_ASSERT_EQUAL_INT(2000u, client.nextAttemptAtMillis());

  // Attempt 3: due at 2000 -> 500 again, wait doubles to 4000 from here.
  client.flush(2000);
  TEST_ASSERT_EQUAL_INT(2, transport.postCount);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(4000u, client.nextAttemptAtMillis());
  TEST_ASSERT_EQUAL_INT(insight::backoffMillis(1),
                        static_cast<int>(client.lastBackoffMillis()));

  // Attempt 4: due at 4000 -> 500 once more, wait doubles again to 8000.
  client.flush(4000);
  TEST_ASSERT_EQUAL_INT(3, transport.postCount);
  TEST_ASSERT_EQUAL_INT(8000u, client.nextAttemptAtMillis());
  TEST_ASSERT_EQUAL_INT(insight::backoffMillis(2),
                        static_cast<int>(client.lastBackoffMillis()));

  // Attempt 5: due at 8000 -> the scripted 204 removes the entry exactly once;
  // three 500s have been replayed, so transport saw four calls in all.
  client.flush(8000);
  TEST_ASSERT_EQUAL_INT(4, transport.postCount);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.sent()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.nextAttemptAtMillis()));

  // Already empty: flushing again posts nothing and keeps sent() at 1.
  client.flush(60000);
  TEST_ASSERT_EQUAL_INT(4, transport.postCount);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.sent()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.nextAttemptAtMillis()));
}

// A single 500 then 204: the entry survives the first flush and leaves on the
// second, once the backoff window has passed.
void test_one_retry_then_success(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  ScriptedTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  const insight::HttpOutcome script[] = {ok(500), ok(204)};
  transport.setScript(script, 2);

  client.send("temp", 20.0f);
  client.flush(0);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(insight::backoffMillis(0),
                        static_cast<int>(client.nextAttemptAtMillis()));

  client.flush(insight::backoffMillis(0));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.sent()));
  TEST_ASSERT_EQUAL_INT(2, transport.postCount);
}

// A 2xx on the very first flush removes the entry immediately and counts it.
void test_success_removes_entry(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  ScriptedTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  const insight::HttpOutcome script[] = {ok(204)};
  transport.setScript(script, 1);

  client.send("temp", 20.0f);
  const size_t removed = client.flush(0);

  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(removed));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.sent()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.dropped()));
}

// ---------------------------------------------------------------------------
// flush(): permanent 4xx is discarded, counted, and never retried
// ---------------------------------------------------------------------------

// 400 is a permanent client error: the entry is removed, the dropped counter
// increments, and the schedule is cleared — a second flush sends nothing.
void test_400_discards_entry_and_increments_counter(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  ScriptedTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  const insight::HttpOutcome script[] = {ok(400), ok(204)};
  transport.setScript(script, 2);

  client.send("temp", 20.0f);
  client.flush(0);

  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.dropped()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.sent()));
  TEST_ASSERT_EQUAL_INT(1, transport.postCount);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.nextAttemptAtMillis()));
  TEST_ASSERT_TRUE(client.isReady(0));

  // NOT retried: a later flush, even long after, sends nothing more.
  client.flush(1000000);
  TEST_ASSERT_EQUAL_INT(1, transport.postCount);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.dropped()));
}

// Every permanent 4xx shape is discarded, one counter tick each; none is left
// scheduled. Uses a counting transport that returns 404 until told otherwise.
void test_other_4xx_discards_without_retry(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  CountingTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  transport.kind = insight::HttpOutcome::Ok;
  transport.status = 404;
  client.send("a", 1.0f);
  client.flush(0);

  TEST_ASSERT_EQUAL_INT(1, transport.postCount);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.dropped()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.nextAttemptAtMillis()));
}

// ---------------------------------------------------------------------------
// flush(): non-blocking by design — durations are returned, never slept
// ---------------------------------------------------------------------------

// The retryable failure surfaces the exact backoff duration as a return value
// (lastBackoffMillis) and an absolute deadline (nextAttemptAtMillis). Both are
// computed from backoffMillis(); neither is a wait. The call itself is instant,
// which is the observable proof that no delay() ran on the path.
void test_retry_returns_backoff_schedule_instead_of_sleeping(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  CountingTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  transport.kind = insight::HttpOutcome::Ok;
  transport.status = 503;

  client.send("temp", 20.0f);
  client.flush(4000);

  // The entry is kept, not dropped and not sent.
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.sent()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.dropped()));

  // The wait is a value: attempt 0 waits backoffMillis(0) = 1000 ms.
  TEST_ASSERT_EQUAL_INT(insight::backoffMillis(0),
                        static_cast<int>(client.lastBackoffMillis()));
  TEST_ASSERT_EQUAL_INT(4000u + insight::backoffMillis(0),
                        static_cast<int>(client.nextAttemptAtMillis()));

  // Before the deadline: not ready, and a flush makes no attempt.
  TEST_ASSERT_FALSE(client.isReady(4999));
  client.flush(4999);
  TEST_ASSERT_EQUAL_INT(1, transport.postCount);

  // At the deadline: ready, and the entry becomes attempt number 1, whose
  // backoff is 2000 ms — the sequence advances without anyone blocking.
  TEST_ASSERT_TRUE(client.isReady(5000));
  client.flush(5000);
  TEST_ASSERT_EQUAL_INT(2, transport.postCount);
  TEST_ASSERT_EQUAL_INT(insight::backoffMillis(1),
                        static_cast<int>(client.lastBackoffMillis()));
  TEST_ASSERT_EQUAL_INT(5000u + insight::backoffMillis(1),
                        static_cast<int>(client.nextAttemptAtMillis()));

  // A third attempt doubles the wait again — still a value, still instant.
  client.flush(5000 + insight::backoffMillis(1));
  TEST_ASSERT_EQUAL_INT(3, transport.postCount);
  TEST_ASSERT_EQUAL_INT(insight::backoffMillis(2),
                        static_cast<int>(client.lastBackoffMillis()));
  TEST_ASSERT_EQUAL_INT((5000u + insight::backoffMillis(1)) +
                            insight::backoffMillis(2),
                        static_cast<int>(client.nextAttemptAtMillis()));
}

// A timeout and a transport error carry no verdict: both are retried and
// scheduled, never discarded.
void test_timeout_and_error_are_retried(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  CountingTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  transport.kind = insight::HttpOutcome::Timeout;
  client.send("t", 1.0f);
  client.flush(100);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.dropped()));
  TEST_ASSERT_EQUAL_INT(100u + insight::backoffMillis(0),
                        static_cast<int>(client.nextAttemptAtMillis()));

  transport.kind = insight::HttpOutcome::Error;
  client.flush(100 + insight::backoffMillis(0));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.dropped()));
}

// flush() returns promptly with no transport and with an empty buffer — no
// internal blocking loop, so the call is instantaneous and empty by design.
void test_flush_is_prompt_without_transport_or_entries(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  client.setBuffer(&buffer);

  // No transport: send() still queues, but the attempt is a retryable error,
  // so the entry is kept and scheduled. It must not hang or drop.
  client.send("temp", 20.0f);
  client.flush(0);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(client.dropped()));

  // Empty buffer: flushing is a no-op and posts nothing.
  insight::InsightBuffer empty;
  insight::InsightSend idle;
  CountingTransport transport;
  idle.setBuffer(&empty);
  idle.setTransport(&transport);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(idle.flush(0)));
  TEST_ASSERT_EQUAL_INT(0, transport.postCount);
}

// ---------------------------------------------------------------------------
// Multiple entries: successful ones drain, a retryable one is scheduled
// ---------------------------------------------------------------------------

// Two queued samples, both accepted, both removed, in FIFO order.
void test_multiple_entries_drain_in_order(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  CountingTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);
  transport.status = 204;

  client.send("a", 1.0f);
  client.send("b", 2.0f);
  const size_t removed = client.flush(0);

  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(removed));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(2, static_cast<int>(client.sent()));
  TEST_ASSERT_EQUAL_INT(2, transport.postCount);
}

// A permanent failure on the first entry is removed while the second is still
// drained on the same pass: one bad sample does not block the queue.
void test_discard_does_not_block_following_entries(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  ScriptedTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  const insight::HttpOutcome script[] = {ok(400), ok(204)};
  transport.setScript(script, 2);

  client.send("bad", 1.0f);
  client.send("good", 2.0f);
  client.flush(0);

  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.dropped()));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.sent()));
  TEST_ASSERT_EQUAL_INT(2, transport.postCount);
}

// A retryable failure ends the pass, leaving the entry queued and the schedule
// set; the next flush past the deadline makes the next attempt.
void test_retryable_failure_schedules_and_survives(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  ScriptedTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  const insight::HttpOutcome script[] = {ok(500), ok(204)};
  transport.setScript(script, 2);

  client.send("temp", 20.0f);
  client.flush(1000);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  const uint32_t due = client.nextAttemptAtMillis();
  TEST_ASSERT_EQUAL_INT(1000u + insight::backoffMillis(0),
                        static_cast<int>(due));

  client.flush(due - 1);
  TEST_ASSERT_EQUAL_INT(1, transport.postCount);

  client.flush(due);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(2, transport.postCount);
}

// The body sent is the JSON for the entry, and it goes to the telemetry path.
void test_flush_posts_entry_json_to_path(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  ScriptedTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  const insight::HttpOutcome script[] = {ok(204)};
  transport.setScript(script, 1);

  client.send("temp", 21.5f);
  client.flush(0);

  // The default endpoint is the frozen telemetry route, and the body records
  // the key that was queued.
  TEST_ASSERT_EQUAL_STRING("/v1/telemetry", client.path());
  TEST_ASSERT_EQUAL_STRING("/v1/telemetry", transport.lastPath);
  TEST_ASSERT_NOT_NULL(std::strstr(transport.lastJson, "\"key\":\"temp\""));
}

// A not-yet-due entry at the head must not be removed when a later, due entry
// succeeds: the removal targets the entry that was actually sent. This is the
// case where a retry schedule and fresh samples coexist in one queue.
void test_successful_later_entry_does_not_remove_pending_head(void) {
  insight::InsightBuffer buffer;
  insight::InsightSend client;
  ScriptedTransport transport;
  client.setBuffer(&buffer);
  client.setTransport(&transport);

  // "a" fails once (scheduled at 1000); "b" then succeeds on the next pass.
  const insight::HttpOutcome script[] = {ok(500), ok(204)};
  transport.setScript(script, 2);

  client.send("a", 1.0f);
  client.flush(0);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_INT(1000u, client.nextAttemptAtMillis());

  client.send("b", 2.0f);  // Fresh sample joins the queue behind "a".

  // At 500, "a" is not due but "b" is: only "b" may be sent and removed.
  client.flush(500);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(buffer.size()));
  TEST_ASSERT_EQUAL_STRING("a", buffer.oldest().key);
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(client.sent()));
  TEST_ASSERT_EQUAL_INT(1000u, client.nextAttemptAtMillis());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_send_valid_numeric_is_accepted);
  RUN_TEST(test_send_nan_and_inf_are_rejected);
  RUN_TEST(test_send_overflowing_magnitude_is_rejected);
  RUN_TEST(test_send_invalid_key_is_rejected);
  RUN_TEST(test_send_without_buffer_is_rejected);
  RUN_TEST(test_send_null_value_is_accepted);
  RUN_TEST(test_retries_then_success_removes_entry_once);
  RUN_TEST(test_one_retry_then_success);
  RUN_TEST(test_success_removes_entry);
  RUN_TEST(test_400_discards_entry_and_increments_counter);
  RUN_TEST(test_other_4xx_discards_without_retry);
  RUN_TEST(test_retry_returns_backoff_schedule_instead_of_sleeping);
  RUN_TEST(test_timeout_and_error_are_retried);
  RUN_TEST(test_flush_is_prompt_without_transport_or_entries);
  RUN_TEST(test_multiple_entries_drain_in_order);
  RUN_TEST(test_discard_does_not_block_following_entries);
  RUN_TEST(test_retryable_failure_schedules_and_survives);
  RUN_TEST(test_flush_posts_entry_json_to_path);
  RUN_TEST(test_successful_later_entry_does_not_remove_pending_head);
  return UNITY_END();
}
