// Unit tests for insight::InsightWifi — bounded Wi-Fi association.
//
// InsightWifi owns no radio and no clock of its own: both are injected. That
// is what makes the timeout testable at all. A `connectAttempt` seam performs
// one attempt and reports WifiResult; a `clock` seam returns milliseconds.
//
// These tests therefore drive the two interesting quantities — attempts and
// elapsed time — with seams that are fully under test control:
//
//   * The clock is a plain counter that advances by a fixed step on every
//     read. connectWiFi() reads it once up front and once per subsequent
//     attempt, so `step` is literally "milliseconds consumed per sample".
//   * The attempt seam is a scripted sequence of results (failing by default),
//     so "succeeds on attempt 2" is expressed directly.
//
// Every bounded case asserts the exact attempt count as well as the boolean,
// so a regression that silently drops the bound (or off-by-ones it) fails
// loudly instead of merely being slow.

#include <unity.h>

#include "InsightWifi.h"

namespace {

// Scripted attempt seam: fails until the Nth call, then connects on every call
// from there on. Counts how many attempts it was asked to make, so the tests
// can assert the exact number rather than inferring it from time.
class ScriptedAttempt {
 public:
  // Start connecting on the `n`-th call (1-based). 0 means never connect.
  void connectedFrom(unsigned long n) { connectedFrom_ = n; }
  void alwaysFails() { connectedFrom_ = 0; }  // 0 => never connects

  unsigned long calls() const { return calls_; }

  static ScriptedAttempt* active() { return active_; }

  insight::WifiResult attempt() {
    ++calls_;
    if (connectedFrom_ != 0 && calls_ >= connectedFrom_) {
      return insight::WifiResult::Connected;
    }
    return insight::WifiResult::Failed;
  }

  // Make this instance the seam that the free function below dispatches to.
  void bind() { active_ = this; }

 private:
  unsigned long calls_ = 0;
  unsigned long connectedFrom_ = 0;
  static ScriptedAttempt* active_;
};

ScriptedAttempt* ScriptedAttempt::active_ = nullptr;

insight::WifiResult scriptedAttempt() { return ScriptedAttempt::active()->attempt(); }

// Deterministic millisecond clock: every read advances time by `step` ms, so a
// single read models one time-consuming operation. Test-owned, monotonic, and
// independent of the host wall clock.
struct StepClock {
  unsigned long t = 0;
  unsigned long step = 0;

  unsigned long read() {
    const unsigned long value = t;
    t += step;
    return value;
  }
};

StepClock* g_clock = nullptr;

unsigned long stepClockRead() { return g_clock->read(); }

insight::InsightWifi makeClient(ScriptedAttempt& attempts, StepClock& clock) {
  attempts.bind();
  g_clock = &clock;
  return insight::InsightWifi(&scriptedAttempt, &stepClockRead);
}

}  // namespace

void setUp(void) {}
void tearDown(void) {}

// A seam that never connects, plus a clock that advances a little on every
// read, must give up. The loop samples the deadline after each attempt and
// stops once the window closes, so it terminates rather than spinning forever.
void test_timeout_gives_up_after_deadline(void) {
  ScriptedAttempt attempts;
  StepClock clock;
  clock.step = 10;  // 10 ms per attempt
  insight::InsightWifi wifi = makeClient(attempts, clock);

  const bool connected = wifi.connectWiFi(100);

  TEST_ASSERT_FALSE(connected);
  // Each iteration spends one attempt and then samples the clock once, so a
  // 100 ms window at 10 ms per sample admits 10 attempts: the tenth sample
  // reads t=100, elapsed == 100, and the loop stops exactly at the deadline.
  TEST_ASSERT_EQUAL_UINT32(10, (uint32_t)attempts.calls());
  TEST_ASSERT_EQUAL_UINT32(10, (uint32_t)wifi.attempts());
  // The clock advanced by exactly the start read plus one read per iteration
  // (11 reads * 10 ms = 110 ms) for a 100 ms request: bounded overshoot of a
  // single sample, never unbounded.
  TEST_ASSERT_EQUAL_UINT32(110, (uint32_t)clock.t);
}

// The same never-connecting seam with time frozen at zero must still terminate:
// after the first failed attempt the clock sample is unchanged from the start,
// which proves it can never reach the deadline, so the loop gives up instead of
// busy-spinning. Exactly one attempt, and the call returns.
void test_frozen_clock_still_terminates(void) {
  ScriptedAttempt attempts;
  StepClock clock;
  clock.step = 0;  // time never advances
  insight::InsightWifi wifi = makeClient(attempts, clock);

  TEST_ASSERT_FALSE(wifi.connectWiFi(1));
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)attempts.calls());
}

// A deadline shorter than one attempt's cost is honest about it: the first
// attempt is still made (the seams are only consulted afterwards), then the
// single sample shows the elapsed time blowing past the deadline and the call
// gives up.
void test_deadline_shorter_than_attempt_cost(void) {
  ScriptedAttempt attempts;
  StepClock clock;
  clock.step = 5000;  // a single attempt consumes 5000 ms
  insight::InsightWifi wifi = makeClient(attempts, clock);

  TEST_ASSERT_FALSE(wifi.connectWiFi(100));  // 5000 ms attempt > 100 ms window
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)attempts.calls());
}

// Connecting on the first attempt returns true immediately: no further attempt
// is made and the timeout is not consulted.
void test_connect_on_first_attempt(void) {
  ScriptedAttempt attempts;
  attempts.connectedFrom(1);
  StepClock clock;
  clock.step = 10;
  insight::InsightWifi wifi = makeClient(attempts, clock);

  TEST_ASSERT_TRUE(wifi.connectWiFi(1000));
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)attempts.calls());
}

// begin() with maxAttempts=3 against an always-failing seam: exactly three
// attempts, then false. No timeout involved — this is the count-bounded knob.
void test_begin_three_attempts_then_false(void) {
  ScriptedAttempt attempts;
  attempts.alwaysFails();
  StepClock clock;
  insight::InsightWifi wifi = makeClient(attempts, clock);

  TEST_ASSERT_FALSE(wifi.begin(3));
  TEST_ASSERT_EQUAL_UINT32(3, (uint32_t)attempts.calls());
  TEST_ASSERT_EQUAL_UINT32(3, (uint32_t)wifi.attempts());
}

// begin() succeeds as soon as an attempt connects, and reports the exact number
// of attempts it took.
void test_begin_succeeds_on_second_attempt(void) {
  ScriptedAttempt attempts;
  attempts.connectedFrom(2);  // fails once, then connects
  StepClock clock;
  insight::InsightWifi wifi = makeClient(attempts, clock);

  TEST_ASSERT_TRUE(wifi.begin(3));
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)attempts.calls());
}

// A single-attempt budget is a plain single-shot connect: one attempt, no
// retry, regardless of outcome.
void test_begin_single_attempt_budget(void) {
  ScriptedAttempt attempts;
  attempts.alwaysFails();
  StepClock clock;
  insight::InsightWifi wifi = makeClient(attempts, clock);

  TEST_ASSERT_FALSE(wifi.begin(1));
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)attempts.calls());
}

// Unbounded (0) is opt-in and exercised deliberately here. With maxAttempts=0
// the seam is free to fail many times before it finally connects, and begin()
// must keep going — returning true on the attempt that succeeds, not before.
// A bounded budget of 3 would have given up after three.
void test_begin_zero_is_unbounded_until_success(void) {
  ScriptedAttempt attempts;
  attempts.connectedFrom(5);
  StepClock clock;
  insight::InsightWifi wifi = makeClient(attempts, clock);

  TEST_ASSERT_TRUE(wifi.begin(0));
  TEST_ASSERT_EQUAL_UINT32(5, (uint32_t)attempts.calls());
}

// An absent connect seam models a radio that is not there: bounded requests
// still terminate (with false) rather than dereferencing null. The attempt is
// still counted, because the loop still ran — it just could not connect.
void test_missing_seam_fails_without_crashing(void) {
  StepClock clock;
  clock.step = 10;
  g_clock = &clock;
  insight::InsightWifi wifi(0, &stepClockRead);  // no connectAttempt installed

  TEST_ASSERT_FALSE(wifi.connectWiFi(50));
  TEST_ASSERT_EQUAL_UINT32(5, (uint32_t)wifi.attempts());
  // begin() resets the counter, so this is a fresh count of 3.
  TEST_ASSERT_FALSE(wifi.begin(3));
  TEST_ASSERT_EQUAL_UINT32(3, (uint32_t)wifi.attempts());
}

// A null clock freezes time at zero, which pairs with an unbounded request:
// the caller gets "retry until success" without a time source. Two attempts
// here, and the call returns as soon as the seam connects.
void test_null_clock_with_unbounded_request(void) {
  ScriptedAttempt attempts;
  attempts.connectedFrom(2);
  attempts.bind();
  insight::InsightWifi wifi(&scriptedAttempt, 0);  // no clock installed

  TEST_ASSERT_TRUE(wifi.connectWiFi(0));  // 0 => unbounded
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)attempts.calls());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_timeout_gives_up_after_deadline);
  RUN_TEST(test_frozen_clock_still_terminates);
  RUN_TEST(test_deadline_shorter_than_attempt_cost);
  RUN_TEST(test_connect_on_first_attempt);
  RUN_TEST(test_begin_three_attempts_then_false);
  RUN_TEST(test_begin_succeeds_on_second_attempt);
  RUN_TEST(test_begin_single_attempt_budget);
  RUN_TEST(test_begin_zero_is_unbounded_until_success);
  RUN_TEST(test_missing_seam_fails_without_crashing);
  RUN_TEST(test_null_clock_with_unbounded_request);
  return UNITY_END();
}
