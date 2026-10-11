// Unit tests for insight::InsightWatchdog — periodic feeding with an explicit
// pause window.
//
// The watchdog owns no hardware and no clock of its own: both are injected.
// That is what makes the schedule testable at all. A `feed` seam performs one
// watchdog feed (here: it counts), and a `clock` seam returns the current
// millisecond reading (here: a variable the test drives by hand, so "advance
// time by exactly one interval" is expressed directly and no assertion depends
// on how fast the host runs).
//
// The seams forward to a fixture installed by the running case. One watchdog is
// live at a time, so the fixture pointer is always the one just installed.
//
// The properties locked down here, in the order the suite builds them:
//
//   * DISABLED by default: a fresh watchdog never feeds, however far the clock
//     is pushed. Enabling requires an explicit positive interval.
//   * ENABLED: the first feed is immediate (armed at boot), then one feed per
//     interval, and the count grows with the clock. Feeding is never
//     duplicated inside one interval, and elapsed exactly equal to the
//     interval already counts as due.
//   * PAUSED: advance the clock as far as you like and the feed count does not
//     move. This is the OTA-safety property — flash/OTA writes must not be
//     interrupted by a feed, and must not be re-armed by one either.
//   * RESUME: feeding comes back and the window restarts from the resume, so
//     the first poll feeds immediately rather than dumping the time spent
//     paused onto the schedule.
//   * pause()/resume() idempotent, and safe (no crash, no feed) when disabled;
//     a null feed seam and a frozen clock behave as documented.

#include <unity.h>

#include "InsightWatchdog.h"

namespace {

const unsigned long kInterval = 1000;

// Fixture installed by each case before a watchdog is wired up. The seam
// trampolines below forward to it; a pointer keeps the seam signatures free of
// any per-case type.
struct Fixture {
  unsigned long calls = 0;
  unsigned long now = 0;
};

Fixture* g_fixture = 0;

void watchdogTestFeed() { ++g_fixture->calls; }

unsigned long watchdogTestClock() { return g_fixture->now; }

insight::InsightWatchdog makeWatchdog(Fixture* f) {
  g_fixture = f;
  return insight::InsightWatchdog(0, &watchdogTestFeed, &watchdogTestClock);
}

}  // namespace

void setUp(void) {}
void tearDown(void) {}

// A default-constructed watchdog is DISABLED: interval 0, so no amount of time
// passing — not a tick, not a millennium — can produce a feed. Feeding is
// opt-in.
void test_default_is_disabled_and_never_feeds(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);

  TEST_ASSERT_FALSE(wd.enabled());
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)wd.interval());
  TEST_ASSERT_FALSE(wd.poll());

  // Push the clock far past any sane interval; a disabled watchdog ignores it.
  f.now = 1000000;
  TEST_ASSERT_FALSE(wd.poll());
  f.now = 4000000000u;  // near a 32-bit millis() rollover
  TEST_ASSERT_FALSE(wd.poll());

  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)f.calls);
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)wd.feeds());
}

// Enabling installs the schedule: armed at t=0, the first poll feeds right
// away (boot is the moment nothing has been fed yet).
void test_enable_feeds_immediately(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);

  wd.enable(kInterval);
  TEST_ASSERT_TRUE(wd.enabled());
  TEST_ASSERT_EQUAL_UINT32(kInterval, (uint32_t)wd.interval());

  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)wd.feeds());
}

// On schedule: the count grows with the clock, one feed per interval, and never
// more — polling in a tight loop between intervals must not add feeds.
void test_enabled_feeds_once_per_interval(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);
  wd.enable(kInterval);

  TEST_ASSERT_TRUE(wd.poll());  // immediate feed at t=0
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);

  // Hammering poll() while time stands still must not feed again.
  for (int i = 0; i < 100; ++i) {
    TEST_ASSERT_FALSE(wd.poll());
  }
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);

  // One millisecond short of the interval: still not due.
  f.now = kInterval - 1;
  TEST_ASSERT_FALSE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);

  // Elapsed exactly equal to the interval is due (inclusive window).
  f.now = kInterval;
  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)f.calls);

  // The next feed is due a full interval after THAT feed, not after t=0.
  f.now = 2 * kInterval - 1;
  TEST_ASSERT_FALSE(wd.poll());
  f.now = 2 * kInterval;
  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(3, (uint32_t)f.calls);

  // A single late poll collapses the missed intervals into one feed: poll()
  // latches, so a stalled loop catches up with one feed, not a burst.
  f.now = 12 * kInterval;
  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(4, (uint32_t)f.calls);
  TEST_ASSERT_EQUAL_UINT32(4, (uint32_t)wd.feeds());
}

// Disabling stops the feeding: re-disarm and the clock no longer matters.
void test_disable_stops_feeding(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);
  wd.enable(kInterval);
  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);

  wd.disable();
  TEST_ASSERT_FALSE(wd.enabled());
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)wd.interval());
  f.now = 50000;
  TEST_ASSERT_FALSE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);
}

// THE OTA-SAFETY PROPERTY: while paused, feeding does not advance even as the
// clock advances — including across many intervals and past a millis()
// rollover. A flash write that stalls the main loop for a long time must be
// able to rely on the feed simply not happening.
void test_paused_never_feeds_however_far_the_clock_advances(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);
  wd.enable(kInterval);
  TEST_ASSERT_TRUE(wd.poll());  // feed once, then bracket the "write"
  const unsigned long before = f.calls;

  wd.pause();
  TEST_ASSERT_TRUE(wd.paused());
  TEST_ASSERT_FALSE(wd.poll());  // even though a feed would have been due

  // A long write: many intervals, sampled often and rarely.
  for (unsigned long step = 1; step <= 100; ++step) {
    f.now = step * kInterval;
    TEST_ASSERT_FALSE(wd.poll());
  }
  f.now = 5000 * kInterval;
  TEST_ASSERT_FALSE(wd.poll());

  TEST_ASSERT_EQUAL_UINT32(before, (uint32_t)f.calls);
  TEST_ASSERT_EQUAL_UINT32(before, (uint32_t)wd.feeds());
}

// The clock wraps while paused; the pause still holds (the paused flag, not
// unsigned arithmetic, is what decides this).
void test_paused_survives_clock_rollover(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);
  f.now = 0xFFFFFF00u;
  wd.enable(kInterval);
  TEST_ASSERT_TRUE(wd.poll());
  wd.pause();

  f.now = 10u;  // rolled over past 2^32
  TEST_ASSERT_FALSE(wd.poll());
  f.now = 100 * kInterval;
  TEST_ASSERT_FALSE(wd.poll());

  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);
}

// Resume puts feeding back on the schedule, and the window restarts from the
// resume moment: the first poll after resume feeds immediately, then the next
// one is a full interval later. The time spent paused is discarded.
void test_resume_restarts_feeding_schedule(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);
  wd.enable(kInterval);
  TEST_ASSERT_TRUE(wd.poll());

  wd.pause();
  f.now = 100 * kInterval;
  TEST_ASSERT_FALSE(wd.poll());

  wd.resume();
  TEST_ASSERT_FALSE(wd.paused());
  TEST_ASSERT_TRUE(wd.poll());  // feeds right away, re-arming from here
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)f.calls);

  TEST_ASSERT_FALSE(wd.poll());
  f.now = 100 * kInterval + kInterval - 1;
  TEST_ASSERT_FALSE(wd.poll());
  f.now = 100 * kInterval + kInterval;
  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(3, (uint32_t)f.calls);
}

// Idempotence: pausing twice is pausing once; resuming twice is resuming once;
// and pause()/resume() never feed anything by themselves.
void test_pause_and_resume_are_idempotent(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);
  wd.enable(kInterval);

  wd.pause();
  wd.pause();
  wd.pause();
  f.now = 10 * kInterval;
  TEST_ASSERT_FALSE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)f.calls);

  wd.resume();
  wd.resume();
  TEST_ASSERT_FALSE(wd.paused());
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)f.calls);  // resume does not feed

  f.now = 11 * kInterval;
  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);

  // A redundant resume() on a running watchdog leaves it running: exactly one
  // immediate feed, the same as if only one resume had happened.
  wd.resume();
  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)f.calls);
}

// Safe when disabled: pause/resume in any order never feeds, and resuming a
// disabled watchdog arms nothing — it stays disabled until an explicit
// enable(). The pause flag is still honoured once enabled.
void test_pause_resume_safe_when_disabled(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);

  // Default: disabled and not paused. Pausing it is harmless.
  TEST_ASSERT_FALSE(wd.enabled());
  wd.pause();
  f.now = 100 * kInterval;
  TEST_ASSERT_FALSE(wd.poll());

  // Enabling while paused must NOT feed: the pause vetoes the immediate first
  // feed too.
  wd.enable(kInterval);
  TEST_ASSERT_TRUE(wd.enabled());
  TEST_ASSERT_TRUE(wd.paused());
  TEST_ASSERT_FALSE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(0, (uint32_t)f.calls);

  // Resume arms the schedule; the first poll then feeds as usual.
  wd.resume();
  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);

  // Disable, then resume: still disabled, still no feed.
  wd.disable();
  wd.resume();
  f.now = 200 * kInterval;
  TEST_ASSERT_FALSE(wd.enabled());
  TEST_ASSERT_FALSE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);
}

// A null feed seam models a board with no watchdog: the schedule and the feed
// counter still advance (the poll ran), but nothing is called through a null
// pointer and nothing crashes.
void test_null_feed_seam_is_safe(void) {
  Fixture f;
  g_fixture = &f;
  insight::InsightWatchdog wd(0, 0, &watchdogTestClock);
  wd.enable(kInterval);

  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)wd.feeds());
  f.now = kInterval;
  TEST_ASSERT_TRUE(wd.poll());
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)wd.feeds());
}

// A null clock freezes time at zero, which pairs with the immediate first
// feed: an enabled watchdog feeds exactly once and then never again, because
// the frozen clock can never reach the interval.
void test_null_clock_feeds_once_then_holds(void) {
  Fixture f;
  g_fixture = &f;
  insight::InsightWatchdog wd(0, &watchdogTestFeed, 0);  // no clock installed
  wd.enable(kInterval);

  TEST_ASSERT_TRUE(wd.poll());
  for (int i = 0; i < 10; ++i) {
    TEST_ASSERT_FALSE(wd.poll());
  }
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);
}

// The three-argument constructor arms the watchdog when the interval is
// positive, and starts the window at construction time: poll() feeds
// immediately. An interval of 0 leaves it disabled, like the default
// constructor.
void test_constructor_arms_when_interval_positive(void) {
  Fixture f;
  g_fixture = &f;

  insight::InsightWatchdog armed(kInterval, &watchdogTestFeed, &watchdogTestClock);
  TEST_ASSERT_TRUE(armed.enabled());
  TEST_ASSERT_TRUE(armed.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);

  insight::InsightWatchdog off(0, &watchdogTestFeed, &watchdogTestClock);
  TEST_ASSERT_FALSE(off.enabled());
  f.now = 1000 * kInterval;
  TEST_ASSERT_FALSE(off.poll());
  TEST_ASSERT_EQUAL_UINT32(1, (uint32_t)f.calls);
}

// poll() is non-blocking and latches: repeated calls inside one interval never
// double-feed, so a caller may poll as often as its loop runs. It is also a
// no-op (returning false) for every disabled/paused combination.
void test_poll_is_cheap_and_total(void) {
  Fixture f;
  insight::InsightWatchdog wd = makeWatchdog(&f);

  TEST_ASSERT_FALSE(wd.poll());  // disabled
  wd.pause();
  TEST_ASSERT_FALSE(wd.poll());  // disabled + paused
  wd.enable(kInterval);
  TEST_ASSERT_FALSE(wd.poll());  // enabled + paused
  wd.resume();
  TEST_ASSERT_TRUE(wd.poll());  // enabled + resumed

  f.now = 7 * kInterval;
  for (int i = 0; i < 50; ++i) {
    wd.poll();
  }
  TEST_ASSERT_EQUAL_UINT32(2, (uint32_t)f.calls);  // 50 polls, 1 more feed
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_default_is_disabled_and_never_feeds);
  RUN_TEST(test_enable_feeds_immediately);
  RUN_TEST(test_enabled_feeds_once_per_interval);
  RUN_TEST(test_disable_stops_feeding);
  RUN_TEST(test_paused_never_feeds_however_far_the_clock_advances);
  RUN_TEST(test_paused_survives_clock_rollover);
  RUN_TEST(test_resume_restarts_feeding_schedule);
  RUN_TEST(test_pause_and_resume_are_idempotent);
  RUN_TEST(test_pause_resume_safe_when_disabled);
  RUN_TEST(test_null_feed_seam_is_safe);
  RUN_TEST(test_null_clock_feeds_once_then_holds);
  RUN_TEST(test_constructor_arms_when_interval_positive);
  RUN_TEST(test_poll_is_cheap_and_total);
  return UNITY_END();
}
