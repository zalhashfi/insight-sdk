// OTA health-check rollback + signed images (insight::HealthCheckRollback,
// insight::SignedOtaPolicy, the InsightOta signature seam).
//
// Ticket B14 — FR-OTA-06 (rollback driven by a post-update health-check
// `reconcile`), FR-OTA-07 (optional signed images), NFR-SEC-03 (verify before
// flash). The acceptance is three sentences, and each is proven through an
// injected SEAM rather than asserted in a comment:
//
//   1. health-check FAIL  -> rollback (on the ESP32 path)
//   2. health-check OK    -> keep
//   3. wrong signature    -> NO flash;  correct signature -> flash
//
// The whole reason this is testable on a host is that nothing here touches a
// network, a clock or a crypto library directly:
//
//   * the post-update health-check is a `HealthReport` function pointer (the
//     `reconcile` the SDK performs against the server), so "the health-check
//     failed" is a fixture VALUE a test sets, not a network event;
//   * the boot/confirm state machine is `InsightOtaRunner`, whose clock,
//     platform, markValid and rollback are all injected — so ESP32 and ESP8266
//     are both exercised in one binary and their divergence is compared;
//   * the signature verifier is a `SignatureVerifier` function pointer, so the
//     POLICY ("wrong signature -> no flash") is proven with a FAKE verifier and
//     no crypto, exactly as the ticket requires.
//
// "No flash" is proven, not asserted: the flash sink is injected and counts its
// calls, so any byte reaching the partition is an observable fact.

#include <unity.h>

#include <cstring>

#include "InsightOta.h"
#include "InsightOtaRunner.h"
#include "InsightOtaSigned.h"
#include "InsightTransport.h"

namespace {

using insight::HealthCheck;
using insight::HealthCheckRollback;
using insight::InsightOta;
using insight::InsightOtaRunner;
using insight::OtaOffer;
using insight::OtaResult;
using insight::RollbackOutcome;
using insight::SignedOtaPolicy;

// ---------------------------------------------------------------------------
// A manually driven millisecond clock (the runner's clock seam). The test owns
// "now", so a trial's deadline is an exact, reproducible instant.
// ---------------------------------------------------------------------------
unsigned long g_now = 0;
unsigned long clockRead() { return g_now; }
void advance(unsigned long deltaMillis) { g_now += deltaMillis; }

// ---------------------------------------------------------------------------
// The runner's bootloader seams, as recorders: a call count of zero proves "did
// not happen" without inspecting state.
// ---------------------------------------------------------------------------
int g_markValidCalls = 0;
bool g_markValidResult = true;
bool markValidRecorded() {
  ++g_markValidCalls;
  return g_markValidResult;
}

int g_rollbackCalls = 0;
bool g_rollbackResult = true;
bool rollbackRecorded() {
  ++g_rollbackCalls;
  return g_rollbackResult;
}

// ---------------------------------------------------------------------------
// The health-check seam (the `reconcile`). The test sets the verdict the
// device's next reconcile would return; the seam counts how many were made.
// ---------------------------------------------------------------------------
HealthCheck g_healthToReport = HealthCheck::unknown();
int g_healthCalls = 0;
bool g_healthReportReady = false;

HealthCheck healthReport() {
  ++g_healthCalls;
  return g_healthToReport;
}

void resetFixture() {
  g_now = 1000;
  g_markValidCalls = 0;
  g_markValidResult = true;
  g_rollbackCalls = 0;
  g_rollbackResult = true;
  g_healthToReport = HealthCheck::unknown();
  g_healthCalls = 0;
  g_healthReportReady = true;
}

const unsigned long kTimeout = 5000UL;

// A runner wired to every seam, with a known platform and window.
InsightOtaRunner makeRunner(InsightOtaRunner::Platform platform) {
  InsightOtaRunner runner;
  runner.setPlatform(platform);
  runner.setConfirmTimeout(kTimeout);
  runner.setClock(&clockRead);
  runner.setMarkValid(&markValidRecorded);
  runner.setRollback(&rollbackRecorded);
  return runner;
}

// A roller over a fresh runner, with the health seam installed.
struct Rig {
  InsightOtaRunner runner;
  HealthCheckRollback roller;
};

Rig makeRig(InsightOtaRunner::Platform platform) {
  Rig rig;
  rig.runner = makeRunner(platform);
  rig.roller.setRunner(&rig.runner);
  rig.roller.setHealthReport(&healthReport);
  return rig;
}

// ---------------------------------------------------------------------------
// A scripted transport for the signature-policy tests (offer GET + image GET).
// ---------------------------------------------------------------------------
class ScriptedTransport : public insight::InsightTransport {
 public:
  const uint8_t* image = 0;
  size_t imageLen = 0;
  insight::HttpOutcome imageOutcome = insight::HttpOutcome::ok(200);
  int imageCount = 0;

  insight::HttpOutcome postJson(const char*, const char*) override {
    return insight::HttpOutcome::error();
  }

  insight::HttpOutcome get(const char* path, char* buffer, size_t bufferLen,
                           size_t* contentLength) override {
    if (contentLength != 0) *contentLength = 0;
    if (std::strcmp(path, insight::otaImagePath()) != 0) {
      return insight::HttpOutcome::error();  // signature suite uses runWithOffer
    }
    ++imageCount;
    if (imageOutcome.kind == insight::HttpOutcome::Ok && buffer != 0) {
      const size_t copyLen = imageLen < bufferLen ? imageLen : bufferLen;
      for (size_t i = 0; i < copyLen; ++i) {
        buffer[i] = static_cast<char>(image[i]);
      }
      if (copyLen < bufferLen) buffer[copyLen] = '\0';
      if (contentLength != 0) *contentLength = copyLen;
    }
    return imageOutcome;
  }
};

// Records flash writes: the count is the proof that nothing (or something)
// reached the partition; the bytes prove WHAT was flashed.
class FlashRecorder {
 public:
  int calls = 0;
  size_t lastLen = 0;
  uint8_t last[512];

  static FlashRecorder* active() { return active_; }
  void bind() { active_ = this; }

  bool write(const uint8_t* image, size_t len) {
    ++calls;
    lastLen = len;
    for (size_t i = 0; i < len && i < sizeof(last); ++i) last[i] = image[i];
    return true;
  }

  static bool trampoline(const uint8_t* image, size_t len) {
    return active_->write(image, len);
  }

 private:
  static FlashRecorder* active_;
};
FlashRecorder* FlashRecorder::active_ = nullptr;

// ---------------------------------------------------------------------------
// The FAKE signature verifier (no crypto). It models a verifier that accepts a
// signature only when it equals the one "signature" the trusted key produces
// for the exact image it was handed. `g_verifierCalls` proves the verifier ran
// (so "accepted" is not confused with "never checked").
// ---------------------------------------------------------------------------
const char* kGoodSignature = "deadbeefcafef00d";   // the one the key accepts
const char* kBadSignature = "0000000000000000";    // anything else: rejected
const char* kGoodKeyId = "ab12";

int g_verifierCalls = 0;
size_t g_verifierLastLen = 0;
uint8_t g_verifierLastHash = 0;

bool fakeVerifier(const uint8_t* image, size_t len, const char* signatureHex,
                  const char* pubkeyIdHex) {
  ++g_verifierCalls;
  g_verifierLastLen = len;
  // Fold the image so the verifier really depends on the BYTES, not just on the
  // signature string: a policy that called it with the wrong buffer would fail.
  uint8_t sum = 0;
  for (size_t i = 0; i < len; ++i) sum = static_cast<uint8_t>(sum + image[i]);
  g_verifierLastHash = sum;
  // A key id, when supplied, must be the one we trust; absent is fine for a
  // single-key device.
  if (pubkeyIdHex != 0 && pubkeyIdHex[0] != '\0' &&
      std::strcmp(pubkeyIdHex, kGoodKeyId) != 0) {
    return false;
  }
  return signatureHex != 0 && std::strcmp(signatureHex, kGoodSignature) == 0;
}

// A verifier that accepts nothing — models a device holding the WRONG key.
bool denyAllVerifier(const uint8_t*, size_t, const char*, const char*) {
  ++g_verifierCalls;
  return false;
}

// ---------------------------------------------------------------------------
// Image + offer helpers
// ---------------------------------------------------------------------------
const size_t kImageLen = 256;
uint8_t g_image[kImageLen];
const char* kImageSha =
    "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880";

void initImage() {
  for (size_t i = 0; i < kImageLen; ++i) g_image[i] = static_cast<uint8_t>(i);
}

// Assemble a valid offer. `signature`/`signatureHex` may be empty strings to
// omit the field entirely.
void buildOffer(char* out, size_t outLen, const char* version, uint32_t size,
                const char* sha, const char* url, const char* signatureHex,
                const char* pubkeyIdHex) {
  std::memset(out, 0, outLen);
  // A small append helper so the assembler stays readable.
  struct App {
    static void s(char* dst, size_t cap, const char* text) {
      size_t n = std::strlen(dst);
      for (const char* p = text; *p && n + 1 < cap; ++p) dst[n++] = *p;
      dst[n] = '\0';
    }
  };
  char digits[12];
  size_t dn = 0;
  if (size == 0) {
    digits[dn++] = '0';
  } else {
    uint32_t v = size;
    while (v > 0) {
      digits[dn++] = static_cast<char>('0' + (v % 10));
      v /= 10;
    }
  }
  char sizeStr[12];
  size_t sn = 0;
  while (dn > 0) sizeStr[sn++] = digits[--dn];
  sizeStr[sn] = '\0';

  App::s(out, outLen, "{\"update\":{\"version\":\"");
  App::s(out, outLen, version);
  App::s(out, outLen, "\",\"size\":");
  App::s(out, outLen, sizeStr);
  App::s(out, outLen, ",\"sha256\":\"");
  App::s(out, outLen, sha);
  App::s(out, outLen, "\",\"url\":\"");
  App::s(out, outLen, url);
  App::s(out, outLen, "\"");
  if (signatureHex != 0 && signatureHex[0] != '\0') {    App::s(out, outLen, ",\"signature\":\"");
    App::s(out, outLen, signatureHex);
    App::s(out, outLen, "\"");
    if (pubkeyIdHex != 0 && pubkeyIdHex[0] != '\0') {
      App::s(out, outLen, ",\"pubkey_id\":\"");
      App::s(out, outLen, pubkeyIdHex);
      App::s(out, outLen, "\"");
    }
  }
  App::s(out, outLen, "}}");
}

// Build an OTA wired to the scripted transport and the flash recorder.
void wireOta(InsightOta* ota, ScriptedTransport* transport,
             FlashRecorder* flash) {
  flash->bind();
  transport->image = g_image;
  transport->imageLen = kImageLen;
  ota->setTransport(transport);
  ota->setFlashSink(&FlashRecorder::trampoline);
}

}  // namespace

void setUp(void) { resetFixture(); }

void tearDown(void) {}

// ===========================================================================
// Acceptance 1: health-check FAILS -> rollback (ESP32 path)
// ===========================================================================

// THE headline case of FR-OTA-06 on ESP32. A flashed trial is checked against
// the post-update reconcile; the reconcile reports the device did NOT come up
// on the expected image; the runner rolls back to the previous image — and it
// did so WITHOUT the failed image ever being marked valid.
void test_esp32_health_check_fail_rolls_back(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  rig.runner.arm();  // a flash landed; the new image is on probation

  g_healthToReport =
      HealthCheck::unhealthy("1.0.0", "2.0.0");  // still on the old version

  RollbackOutcome out = rig.roller.check();

  TEST_ASSERT_EQUAL_INT(RollbackOutcome::RolledBack, out.decision);
  TEST_ASSERT_TRUE(out.rolledBack);
  TEST_ASSERT_FALSE(out.reattemptRequired);
  TEST_ASSERT_EQUAL_INT(insight::HealthUnhealthy, out.verdict);

  TEST_ASSERT_TRUE(rig.runner.isRolledBack());
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);  // rolled back exactly once
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls); // and NEVER marked valid
  TEST_ASSERT_EQUAL_INT(1, g_healthCalls);    // one reconcile was performed
}

// The rollback decision is driven by the RUNNER's platform rule, not by a
// second copy of it here. On ESP32 the rollback seam is invoked; on ESP8266 it
// is NOT, and the outcome is the distinct `reattemptRequired`. Running both
// over the SAME failed health-check is the clearest statement of INV-O4.
void test_platform_asymmetry_on_failed_health_check(void) {
  // ESP32: rollback happens.
  {
    Rig rig = makeRig(InsightOtaRunner::ESP32);
    rig.runner.arm();
    g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");
    RollbackOutcome out = rig.roller.check();
    TEST_ASSERT_EQUAL_INT(RollbackOutcome::RolledBack, out.decision);
    TEST_ASSERT_TRUE(out.rolledBack);
    TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
  }

  // ESP8266: no rollback is possible; the honest outcome is reattemptRequired.
  {
    resetFixture();
    Rig rig = makeRig(InsightOtaRunner::ESP8266);
    rig.runner.arm();
    g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");
    RollbackOutcome out = rig.roller.check();

    TEST_ASSERT_EQUAL_INT(RollbackOutcome::ReattemptRequired, out.decision);
    TEST_ASSERT_FALSE(out.rolledBack);  // NOT a rollback...
    TEST_ASSERT_TRUE(out.reattemptRequired);
    TEST_ASSERT_TRUE(rig.runner.isReattemptRequired());
    TEST_ASSERT_FALSE(rig.runner.isRolledBack());
    TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);  // ...and no rollback was tried
    TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
  }
}

// A failed health-check must NEVER mark the image valid: marking valid would
// cancel the very rollback the failure is asking for.
void test_failed_health_check_never_marks_valid(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  rig.runner.arm();
  g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");
  rig.roller.check();

  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
}

// ===========================================================================
// Acceptance 2: health-check OK -> keep
// ===========================================================================

// A healthy reconcile confirms the trial: the update is kept, markValid() is
// called exactly once, and no rollback ever happens — even if the clock later
// runs past the deadline.
void test_health_check_ok_keeps_the_update(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  rig.runner.arm();

  g_healthToReport = HealthCheck::healthy("2.0.0", "2.0.0");

  RollbackOutcome out = rig.roller.check();

  TEST_ASSERT_EQUAL_INT(RollbackOutcome::Kept, out.decision);
  TEST_ASSERT_FALSE(out.rolledBack);
  TEST_ASSERT_FALSE(out.reattemptRequired);
  TEST_ASSERT_EQUAL_INT(insight::HealthHealthy, out.verdict);

  TEST_ASSERT_TRUE(rig.runner.isConfirmed());
  TEST_ASSERT_EQUAL_INT(1, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);

  // Late clock: the confirmed trial is terminal and can never roll back.
  advance(kTimeout * 10);
  TEST_ASSERT_FALSE(rig.runner.poll());
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
  TEST_ASSERT_TRUE(rig.runner.isConfirmed());
}

// The same on ESP8266: a healthy device is healthy on both platforms — the
// platform only changes what a FAILED check does.
void test_health_check_ok_keeps_on_esp8266_too(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP8266);
  rig.runner.arm();
  g_healthToReport = HealthCheck::healthy("2.0.0", "2.0.0");

  RollbackOutcome out = rig.roller.check();

  TEST_ASSERT_EQUAL_INT(RollbackOutcome::Kept, out.decision);
  TEST_ASSERT_TRUE(rig.runner.isConfirmed());
  TEST_ASSERT_EQUAL_INT(1, g_markValidCalls);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// ===========================================================================
// The health-check that could not be completed: neither rollback nor confirm
// ===========================================================================

// An unreachable server (Unknown) is NOT evidence of a bad image: the trial
// stays on probation and the caller retries. Crucially, nothing is flashed
// back, marked valid, or rolled back on the strength of a check that did not
// happen.
void test_unknown_health_check_neither_rolls_back_nor_confirms(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  rig.runner.arm();

  g_healthToReport = HealthCheck::unknown();
  RollbackOutcome out = rig.roller.check();

  TEST_ASSERT_EQUAL_INT(RollbackOutcome::KeepTrial, out.decision);
  TEST_ASSERT_FALSE(out.rolledBack);
  TEST_ASSERT_TRUE(rig.runner.isTrial());  // still on probation
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
}

// With no health seam installed at all, the check is Unknown — and still never
// rolls back. The policy must not treat "no way to check" as "unhealthy".
void test_missing_health_seam_is_unknown_and_safe(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32);
  HealthCheckRollback roller;  // no report_ installed
  roller.setRunner(&runner);
  runner.arm();

  RollbackOutcome out = roller.check();

  TEST_ASSERT_EQUAL_INT(RollbackOutcome::KeepTrial, out.decision);
  TEST_ASSERT_TRUE(runner.isTrial());
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// After an Unknown, a later Healthy check still confirms; and after a Healthy,
// a later Unhealthy is a no-op (a confirmed trial cannot be un-confirmed). This
// is the "retry the check" loop the caller runs, and its terminal behaviour.
void test_unknown_then_healthy_confirms(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  rig.runner.arm();

  g_healthToReport = HealthCheck::unknown();
  TEST_ASSERT_EQUAL_INT(RollbackOutcome::KeepTrial, rig.roller.check().decision);

  g_healthToReport = HealthCheck::healthy("2.0.0", "2.0.0");
  TEST_ASSERT_EQUAL_INT(RollbackOutcome::Kept, rig.roller.check().decision);
  TEST_ASSERT_TRUE(rig.runner.isConfirmed());

  // A late Unhealthy on a confirmed trial decides nothing and touches no seam.
  g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");
  RollbackOutcome after = rig.roller.check();
  TEST_ASSERT_EQUAL_INT(RollbackOutcome::NoTrial, after.decision);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
}

// A check with no trial pending is a total no-op, so a caller can drive it
// unconditionally from loop() without arming anything by accident.
void test_check_without_trial_is_noop(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");

  RollbackOutcome out = rig.roller.check();
  TEST_ASSERT_EQUAL_INT(RollbackOutcome::NoTrial, out.decision);
  TEST_ASSERT_EQUAL_INT(0, g_healthCalls);    // no reconcile was even made
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
  TEST_ASSERT_FALSE(rig.roller.isTrialPending());
}

// A null runner must be safe: the roller is inert, never crashes.
void test_null_runner_is_safe(void) {
  HealthCheckRollback roller;
  roller.setHealthReport(&healthReport);
  TEST_ASSERT_FALSE(roller.isTrialPending());
  RollbackOutcome out = roller.check();
  TEST_ASSERT_EQUAL_INT(RollbackOutcome::NoTrial, out.decision);
  TEST_ASSERT_EQUAL_INT(0, g_healthCalls);
}

// The failure path must be idempotent: replaying the check after the rollback
// does not roll back twice or re-drive any seam.
void test_failed_check_is_not_reapplied(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  rig.runner.arm();
  g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");
  rig.roller.check();
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);

  RollbackOutcome again = rig.roller.check();
  TEST_ASSERT_EQUAL_INT(RollbackOutcome::NoTrial, again.decision);
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
}

// A boot-sequence integration: flash -> arm -> reconcile says healthy -> keep;
// and the failing variant -> rollback. Both are the same code path the
// firmware's loop() drives, expressed end to end.
void test_boot_sequence_healthy_vs_unhealthy(void) {
  // Good update: the reconcile confirms it.
  {
    Rig rig = makeRig(InsightOtaRunner::ESP32);
    rig.runner.arm();
    advance(250);  // the device boots into the new image
    g_healthToReport = HealthCheck::healthy("2.0.0", "2.0.0");
    TEST_ASSERT_EQUAL_INT(RollbackOutcome::Kept, rig.roller.check().decision);
    TEST_ASSERT_EQUAL_INT(1, g_markValidCalls);
    TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);
  }
  // Bad update: the reconcile never sees the new version -> rollback.
  {
    resetFixture();
    Rig rig = makeRig(InsightOtaRunner::ESP32);
    rig.runner.arm();
    advance(250);
    g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");
    TEST_ASSERT_EQUAL_INT(RollbackOutcome::RolledBack,
                          rig.roller.check().decision);
    TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);
    TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
  }
}

// An ESP32 rollback that FAILS surfaces as RollbackFailed, NOT RolledBack, and
// does not claim a recovery. Previously a failed rollback was reported as
// RolledBack — the false-recovery the RollbackFailed state exists to remove.
// The decision carries retryRecommended so the caller knows to reattempt without
// ever reading `rolledBack == true`.
void test_esp32_failed_rollback_is_not_reported_as_recovered(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  rig.runner.arm();
  g_rollbackResult = false;  // the bootloader refuses to roll back
  g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");

  RollbackOutcome out = rig.roller.check();

  TEST_ASSERT_EQUAL_INT(RollbackOutcome::RollbackFailed, out.decision);
  TEST_ASSERT_FALSE(out.rolledBack);        // NOT a successful recovery
  TEST_ASSERT_FALSE(out.reattemptRequired); // distinct from the ESP8266 case
  TEST_ASSERT_TRUE(out.retryRecommended);   // the caller must reattempt
  TEST_ASSERT_TRUE(rig.runner.isRollbackFailed());
  TEST_ASSERT_FALSE(rig.runner.isRolledBack());
  TEST_ASSERT_EQUAL_INT(1, g_rollbackCalls);
  TEST_ASSERT_EQUAL_INT(0, g_markValidCalls);

  // The roller latches the same fact.
  TEST_ASSERT_TRUE(rig.roller.lastRollbackFailed());
  TEST_ASSERT_FALSE(rig.roller.lastRolledBack());
}

// A successful ESP32 rollback still reports RolledBack and NOT retry — the
// positive control for the failed-rollback case above.
void test_esp32_successful_rollback_reports_recovered(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  rig.runner.arm();
  g_rollbackResult = true;
  g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");

  RollbackOutcome out = rig.roller.check();

  TEST_ASSERT_EQUAL_INT(RollbackOutcome::RolledBack, out.decision);
  TEST_ASSERT_TRUE(out.rolledBack);
  TEST_ASSERT_FALSE(out.retryRecommended);
  TEST_ASSERT_TRUE(rig.runner.isRolledBack());
  TEST_ASSERT_FALSE(rig.roller.lastRollbackFailed());
}

// An ESP8266 unhealthy check reports ReattemptRequired with retryRecommended but
// NOT rolledBack — and, crucially, is a DIFFERENT decision from RollbackFailed
// (ESP32's tried-and-failed). The two are kept apart so an operator can tell a
// chip with no rollback from a rollback that did not take.
void test_esp8266_reattempt_is_distinct_from_rollback_failed(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP8266);
  rig.runner.arm();
  g_healthToReport = HealthCheck::unhealthy("1.0.0", "2.0.0");

  RollbackOutcome out = rig.roller.check();

  TEST_ASSERT_EQUAL_INT(RollbackOutcome::ReattemptRequired, out.decision);
  TEST_ASSERT_TRUE(out.reattemptRequired);
  TEST_ASSERT_FALSE(out.rolledBack);
  TEST_ASSERT_TRUE(out.retryRecommended);
  TEST_ASSERT_EQUAL_INT(0, g_rollbackCalls);  // no rollback attempted
  TEST_ASSERT_TRUE(RollbackOutcome::ReattemptRequired !=
                   RollbackOutcome::RollbackFailed);
}

// An Unknown verdict schedules a bounded backoff: the caller must NOT re-check
// immediately (which would hammer an already-failing server). The schedule is
// read through isReady()/nextAllowedMillis(); as the outage continues the streak
// grows and — with the shared bounded backoff — the delay never shrinks below
// the first step. A healthy verdict clears the schedule.
void test_unknown_verdict_backs_off_before_rechecking(void) {
  Rig rig = makeRig(InsightOtaRunner::ESP32);
  rig.runner.arm();

  g_healthToReport = HealthCheck::unknown();
  RollbackOutcome first = rig.roller.check();
  TEST_ASSERT_EQUAL_INT(RollbackOutcome::KeepTrial, first.decision);
  TEST_ASSERT_TRUE(rig.runner.isTrial());

  // A schedule was recorded, and the roller is NOT ready at the instant of the
  // verdict.
  const uint32_t scheduled = rig.roller.nextAllowedMillis();
  TEST_ASSERT_TRUE(scheduled != 0);
  TEST_ASSERT_GREATER_THAN_UINT32(static_cast<uint32_t>(g_now), scheduled);
  TEST_ASSERT_FALSE(rig.roller.isReady(static_cast<uint32_t>(g_now)));
  TEST_ASSERT_TRUE(rig.roller.isReady(scheduled));
  TEST_ASSERT_EQUAL_UINT32(1u, rig.roller.unknownStreak());
  TEST_ASSERT_GREATER_THAN_UINT32(0u, rig.roller.lastBackoffMillis());

  // A healthy verdict after the outage clears the schedule and confirms.
  advance(scheduled - static_cast<uint32_t>(g_now));
  g_healthToReport = HealthCheck::healthy("2.0.0", "2.0.0");
  TEST_ASSERT_EQUAL_INT(RollbackOutcome::Kept, rig.roller.check().decision);
  TEST_ASSERT_EQUAL_UINT32(0u, rig.roller.nextAllowedMillis());  // cleared
  TEST_ASSERT_TRUE(rig.roller.isReady(static_cast<uint32_t>(g_now)));
  TEST_ASSERT_EQUAL_UINT32(0u, rig.roller.unknownStreak());
}

// The missing-health-seam case is Unknown too, and therefore also backed off —
// "there is no way to check" must not become a busy loop any more than a live
// outage does.
void test_missing_health_seam_also_backs_off(void) {
  InsightOtaRunner runner = makeRunner(InsightOtaRunner::ESP32);
  HealthCheckRollback roller;  // no report_ installed
  roller.setRunner(&runner);
  runner.arm();

  TEST_ASSERT_EQUAL_INT(RollbackOutcome::KeepTrial, roller.check().decision);
  TEST_ASSERT_TRUE(roller.nextAllowedMillis() != 0);
  TEST_ASSERT_FALSE(roller.isReady(static_cast<uint32_t>(g_now)));
}

// ===========================================================================
// Acceptance 3: wrong signature -> NO flash;  correct signature -> flash
// ===========================================================================

// The offered signature is parsed out of the offer, normalised to lowercase,
// and the key id is carried alongside it. This is the data the verifier is
// handed; if it were dropped, the policy below would be checking nothing.
void test_offer_parses_signature_and_key_id(void) {
  OtaOffer offer;
  const char* json =
      "{\"update\":{\"version\":\"2.0.0\",\"size\":256,"
      "\"sha256\":\"40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266"
      "bf944880\",\"url\":\"/v1/ota/image\","
      "\"signature\":\"DEADBEEFCAFEF00D\",\"pubkey_id\":\"AB12\"}}";

  TEST_ASSERT_TRUE(InsightOta::parseOffer(json, &offer));
  TEST_ASSERT_TRUE(offer.valid);
  TEST_ASSERT_TRUE(offer.hasUpdate);
  TEST_ASSERT_TRUE(offer.hasSignature);
  TEST_ASSERT_EQUAL_STRING("deadbeefcafef00d", offer.signature);  // lowercased
  TEST_ASSERT_EQUAL_STRING("ab12", offer.pubkeyId);
}

// An offer with NO signature fields stays valid and simply reports none — an
// unsigned server must not be a parse failure.
void test_offer_without_signature_is_valid_unsigned(void) {
  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), "", "");
  OtaOffer parsed;
  TEST_ASSERT_TRUE(InsightOta::parseOffer(offer, &parsed));
  TEST_ASSERT_TRUE(parsed.valid);
  TEST_ASSERT_FALSE(parsed.hasSignature);
  TEST_ASSERT_EQUAL_STRING("", parsed.signature);
}

// A signature field that is present but not hex is a MALFORMED OFFER, not a
// silent downgrade to "unsigned": a security field the parser cannot read must
// fail loudly.
void test_malformed_signature_field_rejects_offer(void) {
  OtaOffer offer;
  const char* json =
      "{\"update\":{\"version\":\"2.0.0\",\"size\":256,"
      "\"sha256\":\"40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266"
      "bf944880\",\"url\":\"/v1/ota/image\",\"signature\":\"not-hex!\"}}";
  TEST_ASSERT_FALSE(InsightOta::parseOffer(json, &offer));
  TEST_ASSERT_FALSE(offer.valid);
  TEST_ASSERT_FALSE(offer.hasSignature);
}

// THE headline case of FR-OTA-07. A verifier that rejects (the signature is
// wrong / signed by a key we do not trust) means the image is NOT flashed — not
// one byte, and the verifier really was consulted.
void test_wrong_signature_does_not_flash(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  g_verifierCalls = 0;
  ota.setSignatureVerifier(&fakeVerifier);
  ota.setRequireSignature(false);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), kBadSignature, kGoodKeyId);

  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::SignatureMismatch, result.kind);
  TEST_ASSERT_FALSE(result.retry);       // a bad signature is not retry-worthy
  TEST_ASSERT_EQUAL_INT(0, flash.calls); // NOT ONE BYTE reached the partition
  TEST_ASSERT_EQUAL_INT(1, g_verifierCalls);
  TEST_ASSERT_TRUE(ota.lastSignatureChecked());
  TEST_ASSERT_FALSE(ota.lastSignatureOk());
  TEST_ASSERT_FALSE(ota.lastVerification().flashed);
  TEST_ASSERT_EQUAL_INT(OtaResult::SignatureMismatch,
                        ota.lastVerification().result);
}

// A verifier holding the WRONG key rejects even the "good" signature string —
// the rejection is the verifier's verdict, not a string comparison the policy
// happens to make.
void test_wrong_key_rejects_a_well_formed_signature(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  g_verifierCalls = 0;
  ota.setSignatureVerifier(&denyAllVerifier);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), kGoodSignature, kGoodKeyId);

  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::SignatureMismatch, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  TEST_ASSERT_EQUAL_INT(1, g_verifierCalls);
}

// A CORRECT signature flashes exactly once, with the whole verified image — the
// positive half of the acceptance.
void test_correct_signature_flashes_exactly_once(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  g_verifierCalls = 0;
  ota.setSignatureVerifier(&fakeVerifier);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), kGoodSignature, kGoodKeyId);

  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::Flashed, result.kind);
  TEST_ASSERT_EQUAL_INT(1, flash.calls);  // EXACTLY once
  TEST_ASSERT_EQUAL_UINT32(kImageLen, static_cast<uint32_t>(flash.lastLen));
  TEST_ASSERT_EQUAL_INT(0, std::memcmp(flash.last, g_image, kImageLen));
  TEST_ASSERT_EQUAL_INT(1, g_verifierCalls);
  TEST_ASSERT_TRUE(ota.lastSignatureChecked());
  TEST_ASSERT_TRUE(ota.lastSignatureOk());

  insight::ImageVerification v = ota.lastVerification();
  TEST_ASSERT_TRUE(v.flashed);
  TEST_ASSERT_TRUE(v.signatureChecked);
  TEST_ASSERT_TRUE(v.signatureOk);
  TEST_ASSERT_EQUAL_STRING(kGoodSignature, v.signature);
  TEST_ASSERT_EQUAL_STRING(kGoodKeyId, v.pubkeyId);
  TEST_ASSERT_EQUAL_STRING("2.0.0", v.version);
  TEST_ASSERT_EQUAL_STRING(kImageSha, v.sha256);
}

// The verifier must see EXACTLY the bytes that will be flashed. Feeding it a
// different buffer (or the wrong length) would let a signature over the WRONG
// data pass — the classic signing bug this seam exists to prevent.
void test_verifier_sees_the_whole_image_bytes(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  g_verifierCalls = 0;
  g_verifierLastLen = 0;
  g_verifierLastHash = 0;
  ota.setSignatureVerifier(&fakeVerifier);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), kGoodSignature, kGoodKeyId);
  ota.runWithOffer(offer);

  // Expected checksum of the image 0..255: the same one the verifier computed.
  uint8_t expected = 0;
  for (size_t i = 0; i < kImageLen; ++i) expected = static_cast<uint8_t>(expected + i);

  TEST_ASSERT_EQUAL_UINT32(kImageLen, static_cast<uint32_t>(g_verifierLastLen));
  TEST_ASSERT_EQUAL_UINT8(expected, g_verifierLastHash);
  TEST_ASSERT_EQUAL_INT(1, g_verifierCalls);
}

// The gate order: the signature is checked only AFTER size and digest match, so
// a corrupt transfer is reported as HashMismatch (not SignatureMismatch) and the
// verifier is never even called on bytes that are not the offered image.
void test_hash_mismatch_wins_over_signature_and_skips_verifier(void) {
  initImage();
  g_image[kImageLen - 1] = 0x00;  // alter the last byte -> digest mismatch
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  g_verifierCalls = 0;
  ota.setSignatureVerifier(&fakeVerifier);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), kGoodSignature, kGoodKeyId);
  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::HashMismatch, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  TEST_ASSERT_EQUAL_INT(0, g_verifierCalls);  // never consulted on bad bytes
}

// Opting OUT (no verifier installed) preserves the pre-B14 behaviour: an offer
// that happens to carry a signature is still flashed on SHA-256 alone, because
// the device has no key. This is the deliberate, documented downgrade.
void test_no_verifier_ignores_the_signature_field(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  g_verifierCalls = 0;
  ota.setSignatureVerifier(0);
  ota.setRequireSignature(false);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), kBadSignature, kGoodKeyId);
  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::Flashed, result.kind);
  TEST_ASSERT_EQUAL_INT(1, flash.calls);
  TEST_ASSERT_FALSE(ota.lastSignatureChecked());  // NOT checked — say so
  TEST_ASSERT_EQUAL_INT(0, g_verifierCalls);
}

// FAIL CLOSED: a device told to REQUIRE signing must refuse an unsigned image
// rather than accepting it because no verifier was wired.
void test_require_signature_without_a_verifier_fails_closed(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  ota.setSignatureVerifier(0);        // no key...
  ota.setRequireSignature(true);      // ...but signing is mandatory

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), "", "");
  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::SignatureMismatch, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
}

// And the same, with a real verifier installed: REQUIRED signing rejects an
// unsigned offer.
void test_require_signature_rejects_signed_capable_device_on_unsigned_offer(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  g_verifierCalls = 0;
  ota.setSignatureVerifier(&fakeVerifier);
  ota.setRequireSignature(true);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), "", "");
  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::SignatureMismatch, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  TEST_ASSERT_EQUAL_INT(0, g_verifierCalls);  // nothing to verify
}

// A signed offer + REQUIRED signing + a correct signature still flashes.
void test_require_signature_accepts_a_correctly_signed_image(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  g_verifierCalls = 0;
  ota.setSignatureVerifier(&fakeVerifier);
  ota.setRequireSignature(true);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), kGoodSignature, kGoodKeyId);
  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::Flashed, result.kind);
  TEST_ASSERT_EQUAL_INT(1, flash.calls);
  TEST_ASSERT_EQUAL_INT(1, g_verifierCalls);
}

// ===========================================================================
// The signed-image POLICY spine
// ===========================================================================

// makeFailClosedPolicy() really requires signing, and applying it to an OTA
// configures both the verifier and the requirement in one call — so a caller
// cannot half-wire "must be signed" while forgetting the requirement.
void test_fail_closed_policy_applies_both_settings(void) {
  SignedOtaPolicy policy = insight::makeFailClosedPolicy(&fakeVerifier);
  TEST_ASSERT_TRUE(policy.requireSignature);
  TEST_ASSERT_TRUE(policy.verifier == &fakeVerifier);

  InsightOta ota;
  policy.applyTo(&ota);
  TEST_ASSERT_TRUE(ota.requireSignature());
  TEST_ASSERT_TRUE(ota.signatureVerifier() == &fakeVerifier);
}

// makeOpportunisticPolicy() preserves the shipped behaviour: verify if present,
// but do not require.
void test_opportunistic_policy_does_not_require(void) {
  SignedOtaPolicy policy = insight::makeOpportunisticPolicy(&fakeVerifier);
  TEST_ASSERT_FALSE(policy.requireSignature);

  InsightOta ota;
  policy.applyTo(&ota);
  TEST_ASSERT_FALSE(ota.requireSignature());
  TEST_ASSERT_TRUE(ota.signatureVerifier() == &fakeVerifier);
}

// A fail-closed policy with NO verifier is still safe: it fails closed at check
// time (an unsigned image is refused), which is exactly what a device that
// cannot roll back needs before its key backend is wired.
void test_fail_closed_policy_with_null_verifier_still_refuses(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);

  insight::makeFailClosedPolicy(0).applyTo(&ota);
  TEST_ASSERT_TRUE(ota.requireSignature());
  TEST_ASSERT_TRUE(ota.signatureVerifier() == 0);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), "", "");
  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::SignatureMismatch, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
}

// The named predicates agree with the raw enum, so a caller never re-spells the
// comparison and drifts from OtaResult.
void test_was_flashed_and_was_signature_rejected_predicates(void) {
  OtaResult flashed;
  flashed.kind = OtaResult::Flashed;
  TEST_ASSERT_TRUE(insight::wasFlashed(flashed));
  TEST_ASSERT_FALSE(insight::wasSignatureRejected(flashed));

  OtaResult sig;
  sig.kind = OtaResult::SignatureMismatch;
  TEST_ASSERT_FALSE(insight::wasFlashed(sig));
  TEST_ASSERT_TRUE(insight::wasSignatureRejected(sig));
}

// makeVerification() derives `flashed` from the result kind alone, so a record
// can never claim a flash the policy did not perform.
void test_make_verification_derives_flashed(void) {
  OtaResult flashed;
  flashed.kind = OtaResult::Flashed;
  flashed.received = kImageLen;
  std::strncpy(flashed.computedSha256, kImageSha,
               sizeof(flashed.computedSha256) - 1);
  insight::ImageVerification v = InsightOta::makeVerification(flashed);
  TEST_ASSERT_TRUE(v.flashed);
  TEST_ASSERT_EQUAL_STRING(kImageSha, v.sha256);
  TEST_ASSERT_EQUAL_UINT32(kImageLen, v.received);

  OtaResult bad;
  bad.kind = OtaResult::SignatureMismatch;
  insight::ImageVerification v2 = InsightOta::makeVerification(bad);
  TEST_ASSERT_FALSE(v2.flashed);
}

// The ImageVerification record defaults to "nothing happened", so a
// default-constructed record can never be mistaken for a successful flash.
void test_verification_default_is_inert(void) {
  insight::ImageVerification v;
  TEST_ASSERT_FALSE(v.flashed);
  TEST_ASSERT_FALSE(v.signatureChecked);
  TEST_ASSERT_FALSE(v.signatureOk);
  TEST_ASSERT_EQUAL_STRING("", v.sha256);
  TEST_ASSERT_EQUAL_STRING("", v.signature);
}

// The last-pass signature state is reset every run: a rejection must not leak
// into a subsequent ACCEPTED pass (or vice versa).
void test_signature_state_resets_between_passes(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);
  ota.setSignatureVerifier(&fakeVerifier);

  char badOffer[512];
  buildOffer(badOffer, sizeof(badOffer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), kBadSignature, kGoodKeyId);
  TEST_ASSERT_EQUAL_INT(OtaResult::SignatureMismatch,
                        ota.runWithOffer(badOffer).kind);
  TEST_ASSERT_TRUE(ota.lastSignatureChecked());
  TEST_ASSERT_FALSE(ota.lastSignatureOk());

  char goodOffer[512];
  buildOffer(goodOffer, sizeof(goodOffer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath(), kGoodSignature, kGoodKeyId);
  TEST_ASSERT_EQUAL_INT(OtaResult::Flashed, ota.runWithOffer(goodOffer).kind);
  TEST_ASSERT_TRUE(ota.lastSignatureOk());

  // A no-update pass clears the signature state entirely.
  TEST_ASSERT_EQUAL_INT(OtaResult::NoUpdate,
                        ota.runWithOffer("{\"update\":null}").kind);
  TEST_ASSERT_FALSE(ota.lastSignatureChecked());
  TEST_ASSERT_FALSE(ota.lastSignatureOk());
  TEST_ASSERT_EQUAL_INT(1, flash.calls);  // only the good pass ever flashed
}

// An oversized offer is refused before download, so the signature is never even
// a question — the size ceiling keeps its place as the first gate.
void test_oversized_offer_with_signature_is_refused_before_download(void) {
  ScriptedTransport transport;
  FlashRecorder flash;
  InsightOta ota;
  wireOta(&ota, &transport, &flash);
  ota.setSignatureVerifier(&fakeVerifier);
  ota.setMaxImageSize(512);

  g_verifierCalls = 0;
  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", 4096, kImageSha,
             insight::otaImagePath(), kGoodSignature, kGoodKeyId);
  OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(OtaResult::UnsupportedSize, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  TEST_ASSERT_EQUAL_INT(0, transport.imageCount);
  TEST_ASSERT_EQUAL_INT(0, g_verifierCalls);
}

// ===========================================================================
// The signatures' string seam is a plain function pointer: prove it is
// installable/removable, and that a null detaches it (back to the unsigned
// default), which is what makes it a seam and not a hard dependency.
// ===========================================================================
void test_signature_verifier_is_a_detachable_seam(void) {
  InsightOta ota;
  TEST_ASSERT_TRUE(ota.signatureVerifier() == 0);  // unsigned by default
  TEST_ASSERT_FALSE(ota.requireSignature());

  ota.setSignatureVerifier(&fakeVerifier);
  TEST_ASSERT_TRUE(ota.signatureVerifier() == &fakeVerifier);

  ota.setSignatureVerifier(0);
  TEST_ASSERT_TRUE(ota.signatureVerifier() == 0);
}

int main(int, char**) {
  initImage();

  UNITY_BEGIN();

  // Acceptance 1: failed health-check -> rollback (ESP32)
  RUN_TEST(test_esp32_health_check_fail_rolls_back);
  RUN_TEST(test_platform_asymmetry_on_failed_health_check);
  RUN_TEST(test_failed_health_check_never_marks_valid);

  // Acceptance 2: ok health-check -> keep
  RUN_TEST(test_health_check_ok_keeps_the_update);
  RUN_TEST(test_health_check_ok_keeps_on_esp8266_too);

  // The check that could not be completed
  RUN_TEST(test_unknown_health_check_neither_rolls_back_nor_confirms);
  RUN_TEST(test_missing_health_seam_is_unknown_and_safe);
  RUN_TEST(test_unknown_then_healthy_confirms);
  RUN_TEST(test_check_without_trial_is_noop);
  RUN_TEST(test_null_runner_is_safe);
  RUN_TEST(test_failed_check_is_not_reapplied);
  RUN_TEST(test_boot_sequence_healthy_vs_unhealthy);

  // Rollback outcome integrity + Unknown backoff (B14 hardening)
  RUN_TEST(test_esp32_failed_rollback_is_not_reported_as_recovered);
  RUN_TEST(test_esp32_successful_rollback_reports_recovered);
  RUN_TEST(test_esp8266_reattempt_is_distinct_from_rollback_failed);
  RUN_TEST(test_unknown_verdict_backs_off_before_rechecking);
  RUN_TEST(test_missing_health_seam_also_backs_off);

  // Acceptance 3: wrong signature -> no flash; correct -> flash
  RUN_TEST(test_offer_parses_signature_and_key_id);
  RUN_TEST(test_offer_without_signature_is_valid_unsigned);
  RUN_TEST(test_malformed_signature_field_rejects_offer);
  RUN_TEST(test_wrong_signature_does_not_flash);
  RUN_TEST(test_wrong_key_rejects_a_well_formed_signature);
  RUN_TEST(test_correct_signature_flashes_exactly_once);
  RUN_TEST(test_verifier_sees_the_whole_image_bytes);
  RUN_TEST(test_hash_mismatch_wins_over_signature_and_skips_verifier);
  RUN_TEST(test_no_verifier_ignores_the_signature_field);
  RUN_TEST(test_require_signature_without_a_verifier_fails_closed);
  RUN_TEST(test_require_signature_rejects_signed_capable_device_on_unsigned_offer);
  RUN_TEST(test_require_signature_accepts_a_correctly_signed_image);

  // The signed-image policy spine
  RUN_TEST(test_fail_closed_policy_applies_both_settings);
  RUN_TEST(test_opportunistic_policy_does_not_require);
  RUN_TEST(test_fail_closed_policy_with_null_verifier_still_refuses);
  RUN_TEST(test_was_flashed_and_was_signature_rejected_predicates);
  RUN_TEST(test_make_verification_derives_flashed);
  RUN_TEST(test_verification_default_is_inert);
  RUN_TEST(test_signature_state_resets_between_passes);
  RUN_TEST(test_oversized_offer_with_signature_is_refused_before_download);
  RUN_TEST(test_signature_verifier_is_a_detachable_seam);

  return UNITY_END();
}
