// Two-phase OTA boot/confirm runner tests (insight::InsightOtaRunner).
//
// These pin ST-O4 / INV-O4 — what happens to a freshly flashed image that is
// never confirmed:
//
//   * no confirm() within N seconds on ESP32  -> rolledBack, markValid NOT called
//   * confirm() within N seconds              -> confirmed, markValid called once,
//                                                no rollback
//   * no confirm() within N seconds on ESP8266 -> reattemptRequired (NOT
//                                                rolledBack): the platform
//                                                asymmetry, stated explicitly
//   * the boundary (exactly N) is deterministic under the injected clock
//
// The three things that would make this untestable on a host — the platform,
// the clock and the two bootloader calls — are all injected seams, so every
// claim here is OBSERVED rather than asserted in a comment:
//
//   * the clock is a fixture variable the test advances by hand, so "N seconds
//     later" is an exact, reproducible instant (no sleeps, no wall-clock races);
//   * `markValid` and `rollback` are recorder trampolines counting their calls,
//     so "markValid was NOT called" and "rollback was called exactly once" are
//     directly observable facts;
//   * the platform is a parameter, so ESP32 and ESP8266 are both exercised from
//     the same binary and their divergent outcomes are compared side by side.
//
// The runner is non-blocking by construction (poll() reads the clock, it does
// not wait on it), so these tests would themselves hang against a blocking
// implementation — they double as the "never delay()" check.

#include <unity.h>

#include "InsightOtaRunner.h"

namespace {

using insight::InsightOtaRunner;

// A manually driven millisecond clock. The whole point of the injected clock
// seam: the test owns "now", so the confirmation window is exact and the
// boundary case (elapsed == timeout) can be hit to the millisecond.
unsigned long g_now = 0;

unsigned long clockRead() { return g_now; }

void advance(unsigned long deltaMillis) { g_now += deltaMillis; }

// --- seam recorders --------------------------------------------------------

// Counts markValid() calls and remembers whether it was ever called, so a test
// can prove the "NOT called on timeout" property without inspecting state.
int g_markValidCalls = 0;
bool g_markValidResult = true;

bool markValidRecorded() {
  ++g_markValidCalls;
  return g_markValidResult;
}

// Counts rollback() calls. `rollbackCalls == 0` is the assertion that the
// ESP8266 path never attempted the impossible rollback.
int g_rollbackCalls = 0;
bool g_rollbackResult = true;

bool rollbackRecorded() {
  ++g_rollbackCalls;
  return g_rollbackResult;
}

// Reset every piece of fixture state. Called from setUp() so no test can leak
// a clock reading or a call count into the next one.
void resetFixture() {
  g_now = 1000;  // start somewhere non-zero so a "clock never read" bug shows
  g_markValidCalls = 0;
  g_markValidResult = true;
  g_rollbackCalls = 0;
  g_rollbackResult = true;
}

// A runner wired to all three seams with a known confirmation window.
InsightOtaRunner makeRunner(InsightOtaRunner::Platform platform,
                            unsigned long timeoutMillis) {
  InsightOtaRunner runner;
  runner.setPlatform(platform);
  runner.setConfirmTimeout(timeoutMillis);
  runner.setClock(&clockRead);
  runner.setMarkValid(&markValidRecorded);
  runner.setRollback(&rollbackRecorded);
  return runner;
}

const unsigned long kTimeout = 5000UL;  // the "N seconds" of the criteria

}  // namespace

void setUp(void) { resetFixture(); }

void tearDown(void) {}

// ---------------------------------------------------------------------------
// Phase 1: arming after a flash
// ---------------------------------------------------------------------------

// A fresh trial starts unconfirmed: arming marks NOTHING valid (only confirm()
// can) and opens a deadline one window after the clock reading at arm time.
void test_arm_starts_trial_without_marking_valid(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Idle, runner.state());

  runner.arm();

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());
  TEST_ASSERT_TRUE(runner.isTrial());
  TEST_ASSERT_EQUAL_UINT32(1000UL, runner.armedAtMillis());
  TEST_ASSERT_EQUAL_UINT32(1000UL + kTimeout, runner.deadlineMillis());

  // Arming is not confirming: the bootloader flag is untouched and no rollback
  // has happened. The image is on probation, exactly as the criteria require.
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
  TEST_ASSERT_EQUAL_UINT32(0UL, runner.markValidCalls());
}

// Re-arming (a second flash) restarts the window from the new clock reading
// rather than stacking or inheriting the old deadline.
void test_rearm_restarts_the_window(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);

  runner.arm();
  advance(4000);
  runner.arm();  // re-flash

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());
  TEST_ASSERT_EQUAL_UINT32(5000UL, runner.armedAtMillis());
  TEST_ASSERT_EQUAL_UINT32(5000UL + kTimeout, runner.deadlineMillis());
}

// ---------------------------------------------------------------------------
// Acceptance: no confirmation within N seconds -> ESP32 rolledBack
// ---------------------------------------------------------------------------

// THE headline case. A trial armed on ESP32 that is never confirmed, and whose
// window is allowed to close, must roll back to the previous image — and it
// must reach that state WITHOUT ever marking the trial valid. A device that
// marked a timed-out trial valid would have cancelled the very rollback the
// timeout exists to perform.
void test_esp32_no_confirm_within_timeout_rolls_back_without_markvalid(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();

  // Before the deadline: still on probation, nothing has happened.
  advance(kTimeout - 1);
  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());

  // At/past the deadline with no confirm(): the trial expires.
  advance(1);
  TEST_ASSERT_TRUE(runner.poll());

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, runner.state());
  TEST_ASSERT_TRUE(runner.isRolledBack());
  TEST_ASSERT_TRUE(runner.isExpired());

  // The two load-bearing negative/positive facts, both observed through the
  // injected seams rather than inferred from state.
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);  // never marked valid
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);   // rolled back exactly once
  TEST_ASSERT_EQUAL_UINT32(0UL, runner.markValidCalls());
  TEST_ASSERT_EQUAL_UINT32(1UL, runner.rollbackCalls());
}

// A poll that hits the deadline with a confirm() that arrived in time is NOT
// an expiry: confirming first wins, and the later poll does nothing. This is
// the ordering guarantee — confirmation is checked by state, not by clock.
void test_confirm_before_deadline_prevents_expiry(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();
  advance(kTimeout - 1);

  TEST_ASSERT_TRUE(runner.confirm());

  // Well past the deadline now; the trial is already over and must not expire.
  advance(kTimeout * 10);
  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Confirmed, runner.state());
}

// ---------------------------------------------------------------------------
// Acceptance: confirmation in time -> confirmed, markValid once, no rollback
// ---------------------------------------------------------------------------

// The success path: confirm() within the window calls markValid() EXACTLY once
// (cancelling the bootloader's pending rollback) and lands in `confirmed`. No
// rollback may ever follow a confirm, however far the clock later advances.
void test_confirm_in_time_marks_valid_once_and_no_rollback(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();

  advance(kTimeout / 2);  // comfortably inside the window
  TEST_ASSERT_TRUE(runner.confirm());

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Confirmed, runner.state());
  TEST_ASSERT_TRUE(runner.isConfirmed());
  TEST_ASSERT_FALSE(runner.isExpired());
  TEST_ASSERT_EQUAL_INT(1, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);

  // Confirm is idempotent and terminal: re-confirming and polling past the
  // deadline change nothing and never re-invoke a seam.
  advance(kTimeout * 4);
  TEST_ASSERT_FALSE(runner.confirm());
  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Confirmed, runner.state());
  TEST_ASSERT_EQUAL_INT(1, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// A markValid() that FAILS (the bootloader flag was not set) must NOT land the
// trial in the terminal `confirmed` state: the state contract says an observer
// never sees `confirmed` for a flag that was not actually set. confirm() reports
// false, the runner stays in `Trial`, and a later retry can still succeed.
void test_confirm_with_failing_markvalid_stays_trial(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();
  advance(1);

  g_markValidResult = false;
  TEST_ASSERT_FALSE(runner.confirm());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());
  TEST_ASSERT_FALSE(runner.isConfirmed());
  TEST_ASSERT_EQUAL_INT(1, g_markValidCalls);  // the attempt was made

  // The window is still open and the trial is still pending: a retry can win.
  g_markValidResult = true;
  TEST_ASSERT_TRUE(runner.confirm());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Confirmed, runner.state());
  TEST_ASSERT_EQUAL_INT(2, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// The same property on ESP8266: a confirmed trial is confirmed there too. The
// platform only changes what an EXPIRY does; confirmation is identical.
void test_esp8266_confirm_in_time_marks_valid_once(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP8266, kTimeout);
  runner.arm();
  advance(1);

  TEST_ASSERT_TRUE(runner.confirm());

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Confirmed, runner.state());
  TEST_ASSERT_EQUAL_INT(1, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// A null markValid seam means "there is no bootloader flag to set": confirming
// still succeeds and still reaches `confirmed` — the state machine is not made
// hostage to an optional seam.
void test_confirm_with_null_markvalid_still_confirms(void) {
  InsightOtaRunner runner;
  runner.setPlatform(InsightOtaRunner::ESP32);
  runner.setClock(&clockRead);
  runner.setConfirmTimeout(kTimeout);
  // markValid deliberately left null.
  runner.arm();

  TEST_ASSERT_TRUE(runner.confirm());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Confirmed, runner.state());
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
}

// ---------------------------------------------------------------------------
// Acceptance: ESP8266 + no confirmation -> reattemptRequired (NOT rolledBack)
// ---------------------------------------------------------------------------

// THE asymmetry case, asserted explicitly. ESP8266 has no second slot and no
// bootloader rollback, so an expired trial cannot be undone. The runner must
// NOT report `rolledBack` (there is no "back") and must NOT call the rollback
// seam (there is nothing to call) — it reports `reattemptRequired`, the honest
// "the update could not be confirmed and must be tried again" outcome.
//
// This test asserts the difference DIRECTLY: the ESP8266 outcome is checked to
// be `reattemptRequired` and, in the same test, explicitly not `rolledBack`,
// with the rollback seam count at zero.
void test_esp8266_no_confirm_requires_reattempt_not_rollback(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP8266, kTimeout);
  runner.arm();

  advance(kTimeout - 1);
  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());

  advance(1);
  TEST_ASSERT_TRUE(runner.poll());

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::ReattemptRequired, runner.state());
  TEST_ASSERT_TRUE(runner.isReattemptRequired());

  // The platform asymmetry, stated as three independent assertions: NOT the
  // ESP32 outcome, no rollback attempted, and no valid-marking either.
  TEST_ASSERT_TRUE(InsightOtaRunner::ReattemptRequired !=
                   InsightOtaRunner::RolledBack);
  TEST_ASSERT_NOT_EQUAL(InsightOtaRunner::RolledBack, runner.state());
  TEST_ASSERT_FALSE(runner.isRolledBack());
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);

  // Both platforms agree the trial is over (expired), yet they disagree on HOW
  // — which is exactly the distinction the enum encodes.
  TEST_ASSERT_TRUE(runner.isExpired());
}

// The two platforms, driven identically, must reach DIFFERENT states. Running
// them side by side is the clearest possible statement of INV-O4: same clock,
// same window, same absence of confirmation, different outcome by platform.
void test_platform_asymmetry_side_by_side(void) {
  InsightOtaRunner esp32 = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  InsightOtaRunner esp8266 = makeRunner(InsightOtaRunner::ESP8266, kTimeout);

  esp32.arm();
  esp8266.arm();
  advance(kTimeout);
  esp32.poll();
  esp8266.poll();

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, esp32.state());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::ReattemptRequired, esp8266.state());
  TEST_ASSERT_NOT_EQUAL(esp32.state(), esp8266.state());

  // Exactly one rollback across both, and it was the ESP32 one.
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
  TEST_ASSERT_EQUAL_UINT32(1UL, esp32.rollbackCalls());
  TEST_ASSERT_EQUAL_UINT32(0UL, esp8266.rollbackCalls());
}

// An expired ESP8266 trial cannot be rescued by a late confirm(): there is no
// running trial to confirm, and `reattemptRequired` is a distinct outcome, not
// a softer spelling of `confirmed`.
void test_esp8266_late_confirm_is_refused(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP8266, kTimeout);
  runner.arm();
  advance(kTimeout);
  runner.poll();

  TEST_ASSERT_FALSE(runner.confirm());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::ReattemptRequired, runner.state());
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
}

// A late confirm on ESP32 is refused too — a rolled-back trial is terminal.
void test_esp32_late_confirm_is_refused(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();
  advance(kTimeout);
  runner.poll();

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, runner.state());
  TEST_ASSERT_FALSE(runner.confirm());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, runner.state());
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
}

// ---------------------------------------------------------------------------
// Acceptance: the boundary (exactly N) is deterministic
// ---------------------------------------------------------------------------

// Exactly N milliseconds after arming IS expired: the comparison is inclusive
// (elapsed >= timeout), so the boundary is a definite instant rather than a
// coin flip. This is asserted down to the millisecond: N-1 must not expire,
// N must.
void test_boundary_exactly_n_expires_on_esp32(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();

  advance(kTimeout - 1);
  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());
  TEST_ASSERT_EQUAL_UINT32(kTimeout - 1, runner.elapsedMillis());
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);

  advance(1);  // elapsed == kTimeout, exactly the boundary
  TEST_ASSERT_EQUAL_UINT32(kTimeout, runner.elapsedMillis());
  TEST_ASSERT_TRUE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, runner.state());
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
}

// The same inclusive boundary on ESP8266: exactly N expires into
// reattemptRequired (and, again, never rolledBack).
void test_boundary_exactly_n_expires_on_esp8266(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP8266, kTimeout);
  runner.arm();

  advance(kTimeout - 1);
  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());

  advance(1);  // exactly N
  TEST_ASSERT_TRUE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::ReattemptRequired, runner.state());
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// The boundary outcome must not depend on WHEN the clock is observed: polling
// repeatedly (as loop() does) or in one jump lands on the same state at the
// same instant. Determinism is the property, so it is asserted both ways.
void test_boundary_is_independent_of_poll_cadence(void) {
  // One jump straight to N.
  InsightOtaRunner jumped = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  jumped.arm();
  advance(kTimeout);
  jumped.poll();

  // Polled every millisecond up to N.
  resetFixture();
  InsightOtaRunner polled = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  polled.arm();
  bool expiredMidway = false;
  for (unsigned long i = 0; i < kTimeout; ++i) {
    advance(1);
    if (polled.poll()) {
      expiredMidway = true;
      break;
    }
  }

  TEST_ASSERT_TRUE(expiredMidway);
  TEST_ASSERT_EQUAL_INT(jumped.state(), polled.state());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, polled.state());
  TEST_ASSERT_EQUAL_UINT32(jumped.deadlineMillis(), polled.deadlineMillis());
  // Exactly one rollback even though the expiry was observed many polls later
  // in the polling variant: the transition latches.
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
}

// A confirm() right AT the boundary (elapsed == N, before any poll) still wins:
// the deadline has been reached but not yet acted upon, and confirm() is the
// higher-priority outcome. Only a poll can perform the expiry transition.
void test_confirm_at_exact_boundary_before_poll_wins(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();
  advance(kTimeout);  // exactly N, no poll yet

  TEST_ASSERT_TRUE(runner.confirm());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Confirmed, runner.state());
  TEST_ASSERT_EQUAL_INT(1, g_markValidCalls);

  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// A one-millisecond window is the degenerate case: the trial expires at the
// very next tick. It must still take the right branch per platform — a short
// window is a legal configuration, not a special case that skips the platform
// decision.
void test_one_millisecond_timeout_expires_per_platform(void) {
  InsightOtaRunner esp32;
  esp32.setPlatform(InsightOtaRunner::ESP32);
  esp32.setClock(&clockRead);
  esp32.setMarkValid(&markValidRecorded);
  esp32.setRollback(&rollbackRecorded);
  esp32.setConfirmTimeout(1);
  esp32.arm();
  advance(1);
  TEST_ASSERT_TRUE(esp32.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, esp32.state());

  resetFixture();
  InsightOtaRunner esp8266;
  esp8266.setPlatform(InsightOtaRunner::ESP8266);
  esp8266.setClock(&clockRead);
  esp8266.setMarkValid(&markValidRecorded);
  esp8266.setRollback(&rollbackRecorded);
  esp8266.setConfirmTimeout(1);
  esp8266.arm();
  advance(1);
  TEST_ASSERT_TRUE(esp8266.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::ReattemptRequired, esp8266.state());
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// ---------------------------------------------------------------------------
// The rollback path never panics: absent / failing seams stay safe
// ---------------------------------------------------------------------------

// An ESP32 expiry with NO rollback seam installed must still reach a defined
// state without calling through a null pointer. This is the "never panics on
// the rollback path" guarantee: the absent seam is simply not called, and
// nothing is dereferenced.
//
// The state is `RollbackFailed`, NOT `RolledBack`. This test previously
// expected `RolledBack` for an absent seam — behavior that (with a null seam)
// claimed a recovery that could not have happened. `RolledBack` now means a
// rollback that RAN AND SUCCEEDED, so an absent seam must not report it; the
// honest answer is "recovery did not happen; reattempt".
void test_esp32_expiry_with_null_rollback_is_safe(void) {
  InsightOtaRunner runner;
  runner.setPlatform(InsightOtaRunner::ESP32);
  runner.setClock(&clockRead);
  runner.setConfirmTimeout(kTimeout);
  // rollback deliberately left null.
  runner.arm();
  advance(kTimeout);

  TEST_ASSERT_TRUE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RollbackFailed, runner.state());
  TEST_ASSERT_TRUE(runner.isRollbackFailed());
  TEST_ASSERT_FALSE(runner.isRolledBack());   // no phantom recovery
  TEST_ASSERT_TRUE(runner.needsReattempt());  // the caller must retry
  TEST_ASSERT_TRUE(runner.isExpired());       // but the trial is over
  TEST_ASSERT_EQUAL_UINT32(0UL, runner.rollbackCalls());
}

// A rollback seam that itself FAILS (returns false) must not be escalated into
// a panic or a crash: the runner records the true outcome, and does not call the
// seam again.
//
// The state is `RollbackFailed`, NOT `RolledBack`. This test previously
// expected `RolledBack` after a FAILED rollback — i.e. it pinned the
// false-recovery bug: a caller would read `RolledBack` ("we are back on the old
// image") after the bootloader explicitly said the rollback did not take. The
// state now reflects what happened; the failure is still not retried.
void test_failing_rollback_does_not_panic_and_is_not_retried(void) {
  g_rollbackResult = false;
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();
  advance(kTimeout);

  TEST_ASSERT_TRUE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RollbackFailed, runner.state());
  TEST_ASSERT_FALSE(runner.isRolledBack());  // the rollback did NOT succeed
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);

  // Further polls do not re-drive the seam.
  advance(kTimeout);
  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
  TEST_ASSERT_EQUAL_UINT32(1UL, runner.expireCount());
}

// A null clock reads as a frozen zero: the trial never expires, so the runner
// stays on probation rather than acting on a time it cannot observe. Safe (no
// dereference) and, importantly, it does not spuriously roll back.
void test_null_clock_never_expires(void) {
  InsightOtaRunner runner;
  runner.setPlatform(InsightOtaRunner::ESP32);
  runner.setRollback(&rollbackRecorded);
  runner.setConfirmTimeout(kTimeout);
  // clock deliberately left null.
  runner.arm();

  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// poll() before arming is a total no-op on both platforms, and its return value
// reflects that nothing happened (so a loop() caller cannot misread "no trial"
// as "expired").
void test_poll_before_arm_is_noop(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  advance(kTimeout * 10);

  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Idle, runner.state());
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
}

// pollAt() samples no live clock: the same instant yields the same decision,
// and the boundary is exact with no reference to the fixture clock at all.
void test_poll_at_uses_the_given_instant(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();  // armedAt == 1000

  TEST_ASSERT_FALSE(runner.pollAt(1000 + kTimeout - 1));
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());

  TEST_ASSERT_TRUE(runner.pollAt(1000 + kTimeout));
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, runner.state());
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
}

// The window survives a millis() rollover: elapsed is an unsigned subtraction,
// so a trial armed just before the wrap still expires exactly one window later,
// after the counter has wrapped through zero.
void test_deadline_survives_clock_rollover(void) {
  // Arm 1000 ms before the wrap so the deadline lands 4000 ms after it.
  g_now = 0xFFFFFFFFUL - 1000UL;
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();

  // Step up to the last pre-wrap millisecond: elapsed 1000, one short of the
  // 5000 ms window, so no expiry despite the near-wrap reading.
  advance(1000);
  TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFUL, g_now);
  TEST_ASSERT_FALSE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Trial, runner.state());

  // Cross the wrap and continue to exactly the deadline (elapsed == kTimeout).
  advance(1 + (kTimeout - 1001));  // wrap to 0, then on to elapsed == kTimeout
  TEST_ASSERT_EQUAL_UINT32(kTimeout, runner.elapsedMillis());
  TEST_ASSERT_TRUE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, runner.state());
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
}

// ---------------------------------------------------------------------------
// A representative boot sequence, end to end
// ---------------------------------------------------------------------------

// The full life of a good update: flash -> arm -> boot -> confirm within the
// window. markValid once, no rollback, terminal `confirmed`.
void test_boot_sequence_successful_update(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);

  runner.arm();               // phase 1: the flash landed
  advance(250);               // the device boots into the new image
  TEST_ASSERT_TRUE(runner.poll() == false);  // still on probation, no expiry
  TEST_ASSERT_TRUE(runner.confirm());        // phase 2: it came up healthy

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::Confirmed, runner.state());
  TEST_ASSERT_EQUAL_INT(1, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// The full life of a BAD update: flash -> arm -> the new image never confirms
// -> the window closes -> ESP32 falls back to the old image.
void test_boot_sequence_bad_update_rolls_back(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);

  runner.arm();
  advance(kTimeout + 5000);  // boot-loops / hangs; never confirms
  TEST_ASSERT_TRUE(runner.poll());

  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, runner.state());
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
}

// A rollback that SUCCEEDS is the only path to `RolledBack`; the state is now a
// truthful record. This is the positive control for the RollbackFailed state
// above: same platform, same window, only the seam's return differs.
void test_rollback_success_reaches_rolled_back(void) {
  g_rollbackResult = true;
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();
  advance(kTimeout);

  TEST_ASSERT_TRUE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, runner.state());
  TEST_ASSERT_TRUE(runner.isRolledBack());
  TEST_ASSERT_FALSE(runner.isRollbackFailed());
  TEST_ASSERT_FALSE(runner.needsReattempt());  // recovery DID happen
  TEST_ASSERT_TRUE(runner.isExpired());
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
}

// The three terminal-after-expiry states stay mutually distinct: `rolledBack`
// (recovered), `reattemptRequired` (no slot), `rollbackFailed` (tried, failed).
// A caller can tell them apart, which is the whole point of not collapsing them
// into one "trial over" boolean.
void test_expiry_states_are_mutually_distinct(void) {
  // rolledBack: ESP32, rollback succeeds.
  g_rollbackResult = true;
  InsightOtaRunner ok = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  ok.arm();
  advance(kTimeout);
  ok.poll();
  TEST_ASSERT_TRUE(ok.isRolledBack());
  TEST_ASSERT_FALSE(ok.isReattemptRequired());
  TEST_ASSERT_FALSE(ok.isRollbackFailed());

  // rollbackFailed: ESP32, rollback fails.
  resetFixture();
  g_rollbackResult = false;
  InsightOtaRunner failed = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  failed.arm();
  advance(kTimeout);
  failed.poll();
  TEST_ASSERT_FALSE(failed.isRolledBack());
  TEST_ASSERT_FALSE(failed.isReattemptRequired());
  TEST_ASSERT_TRUE(failed.isRollbackFailed());

  // reattemptRequired: ESP8266, no slot at all.
  resetFixture();
  InsightOtaRunner noSlot = makeRunner(InsightOtaRunner::ESP8266, kTimeout);
  noSlot.arm();
  advance(kTimeout);
  noSlot.poll();
  TEST_ASSERT_FALSE(noSlot.isRolledBack());
  TEST_ASSERT_TRUE(noSlot.isReattemptRequired());
  TEST_ASSERT_FALSE(noSlot.isRollbackFailed());

  // All three are "expired" (the trial is over) but not the same state.
  TEST_ASSERT_TRUE(ok.isExpired());
  TEST_ASSERT_TRUE(failed.isExpired());
  TEST_ASSERT_TRUE(noSlot.isExpired());
}

// deadlineMillis() wraps WITH the clock rather than saturating: armed 1000 ms
// before the wrap with a 5000 ms window, the deadline is a wrapped reading that
// still agrees with the modular `elapsedMillis()` the runner uses. A saturated
// deadline would sit above the wrapped clock and never be reached, so the trial
// could never expire — this pins the in-domain (modular) answer.
void test_deadline_wraps_with_the_clock(void) {
  g_now = 0xFFFFFFFFUL - 1000UL;
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32, kTimeout);
  runner.arm();

  // 0xFFFFFFFF-1000 + 5000, modulo 2^32 — the same value elapsed() measures
  // against. It is NOT saturated, so it wraps through zero.
  const unsigned long expected = (0xFFFFFFFFUL - 1000UL) + kTimeout;
  TEST_ASSERT_EQUAL_UINT32(expected, runner.deadlineMillis());
  TEST_ASSERT_TRUE(expected < runner.armedAtMillis());  // it wrapped

  // And the trial does expire: crossing the wrap reaches the deadline.
  advance(kTimeout);
  TEST_ASSERT_TRUE(runner.poll());
  TEST_ASSERT_EQUAL_INT(InsightOtaRunner::RolledBack, runner.state());
}

int main(int, char**) {
  UNITY_BEGIN();

  // Phase 1: arming after a flash
  RUN_TEST(test_arm_starts_trial_without_marking_valid);
  RUN_TEST(test_rearm_restarts_the_window);

  // No confirmation within N: ESP32 rolls back, without marking valid
  RUN_TEST(test_esp32_no_confirm_within_timeout_rolls_back_without_markvalid);
  RUN_TEST(test_confirm_before_deadline_prevents_expiry);

  // Confirmation in time: confirmed, markValid once, no rollback
  RUN_TEST(test_confirm_in_time_marks_valid_once_and_no_rollback);
  RUN_TEST(test_confirm_with_failing_markvalid_stays_trial);
  RUN_TEST(test_esp8266_confirm_in_time_marks_valid_once);
  RUN_TEST(test_confirm_with_null_markvalid_still_confirms);

  // ESP8266 + no confirmation: reattemptRequired, NOT rolledBack
  RUN_TEST(test_esp8266_no_confirm_requires_reattempt_not_rollback);
  RUN_TEST(test_platform_asymmetry_side_by_side);
  RUN_TEST(test_esp8266_late_confirm_is_refused);
  RUN_TEST(test_esp32_late_confirm_is_refused);

  // The boundary (exactly N) is deterministic
  RUN_TEST(test_boundary_exactly_n_expires_on_esp32);
  RUN_TEST(test_boundary_exactly_n_expires_on_esp8266);
  RUN_TEST(test_boundary_is_independent_of_poll_cadence);
  RUN_TEST(test_confirm_at_exact_boundary_before_poll_wins);
  RUN_TEST(test_one_millisecond_timeout_expires_per_platform);

  // The rollback path never panics
  RUN_TEST(test_esp32_expiry_with_null_rollback_is_safe);
  RUN_TEST(test_failing_rollback_does_not_panic_and_is_not_retried);
  RUN_TEST(test_null_clock_never_expires);
  RUN_TEST(test_poll_before_arm_is_noop);
  RUN_TEST(test_poll_at_uses_the_given_instant);
  RUN_TEST(test_deadline_survives_clock_rollover);

  // Representative boot sequences
  RUN_TEST(test_boot_sequence_successful_update);
  RUN_TEST(test_boot_sequence_bad_update_rolls_back);

  // Rollback outcome integrity (the RollbackFailed state)
  RUN_TEST(test_rollback_success_reaches_rolled_back);
  RUN_TEST(test_expiry_states_are_mutually_distinct);
  RUN_TEST(test_deadline_wraps_with_the_clock);

  return UNITY_END();
}
