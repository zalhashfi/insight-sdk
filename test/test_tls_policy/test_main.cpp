#include <unity.h>

#include "InsightTls.h"

// Tests for the TLS certificate-verification policy (src/InsightTls.h).
//
// The policy depends on two injected facts — whether the build is production
// and whether SNTP time has synced — so the whole thing is decided on the host
// with no network, no TLS stack and no clock. These tests pin the three
// guarantees from the assignment:
//
//   * production refuses the insecure opt-out; the mode stays secure;
//   * the insecure opt-out is a debug-only escape hatch;
//   * certificate validation is gated on SNTP time, with no silent downgrade.

void setUp(void) {}

void tearDown(void) {}

// A production build may stay secure — and must be able to say so.
void test_production_secure_is_allowed(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/true);

  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());

  // Re-selecting secure is always fine and idempotent.
  TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::Ok, policy.setSecure());
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());
}

// Production refuses to enable insecure: the request is reported as an error
// and the mode does not move.
void test_production_refuses_insecure_opt_out(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/true);

  const insight::TlsPolicyResult result = policy.setInsecure();

  TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::RejectedInProduction, result);
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());
}

// The refusal is not a one-shot fluke: repeated attempts keep failing and keep
// the mode secure, so no retry loop can sneak a shipped device into insecure.
void test_production_refusal_is_sticky(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/true);

  for (int i = 0; i < 5; ++i) {
    TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::RejectedInProduction,
                          policy.setInsecure());
    TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());
  }
}

// The debug escape hatch: a non-production build may explicitly opt out, and
// the call reports success while actually changing the mode.
void test_debug_insecure_opt_out_is_allowed(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/false);

  const insight::TlsPolicyResult result = policy.setInsecure();

  TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::Ok, result);
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Insecure, policy.mode());
}

// The escape hatch is reversible: a debug build can always go back to secure.
void test_debug_can_return_to_secure(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/false);

  TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::Ok, policy.setInsecure());
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Insecure, policy.mode());

  TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::Ok, policy.setSecure());
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());
}

// A default-constructed policy is the safe one: secure mode, and gated until
// time is reported. A policy that cannot tell where it runs must behave as
// production, so the escape hatch is refused by default too.
void test_default_policy_is_secure_and_gated(void) {
  insight::InsightTlsPolicy policy;

  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());
  TEST_ASSERT_FALSE(policy.canValidateTls());
  TEST_ASSERT_FALSE(policy.shouldVerifyCertificate());

  TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::RejectedInProduction,
                        policy.setInsecure());
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());
}

// Ordering gate, half one: before SNTP has synced, validation is not allowed.
void test_cannot_validate_before_sntp_sync(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/true);

  TEST_ASSERT_FALSE(policy.canValidateTls());
  TEST_ASSERT_FALSE(policy.shouldVerifyCertificate());
}

// Ordering gate, half two: after SNTP reports a sync, validation is allowed.
void test_can_validate_after_sntp_sync(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/true);

  policy.setTimeSynced(true);

  TEST_ASSERT_TRUE(policy.canValidateTls());
  TEST_ASSERT_TRUE(policy.shouldVerifyCertificate());
}

// The gate tracks the sync flag in both directions: losing the sync re-closes
// it, so validation is permitted only while synced.
void test_gate_tracks_sync_flag_both_ways(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/true);

  TEST_ASSERT_FALSE(policy.canValidateTls());

  policy.setTimeSynced(true);
  TEST_ASSERT_TRUE(policy.canValidateTls());

  policy.setTimeSynced(false);
  TEST_ASSERT_FALSE(policy.canValidateTls());
  TEST_ASSERT_FALSE(policy.shouldVerifyCertificate());
}

// No silent downgrade #1: an unsynced clock never yields a VALIDATED TLS
// decision — the gate is closed even in the secure mode, and the answer is a
// plain "do not validate", never a claim that validation happened.
void test_unsynced_clock_never_validates_secure_mode(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/true);

  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());
  TEST_ASSERT_FALSE(policy.canValidateTls());
  TEST_ASSERT_FALSE(policy.shouldVerifyCertificate());

  // Reporting a sync is the only thing that opens the gate; there is no
  // "unsynced but pretend" path.
  policy.setTimeSynced(true);
  TEST_ASSERT_TRUE(policy.shouldVerifyCertificate());
}

// No silent downgrade #2: time being unsynced is a time problem, and it never
// makes a production build silently insecure. The mode stays secure and the
// insecure request is still refused, synced or not.
void test_unsynced_time_does_not_downgrade_production(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/true);

  // Unsynced: still secure, still gated.
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());
  TEST_ASSERT_FALSE(policy.canValidateTls());
  TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::RejectedInProduction,
                        policy.setInsecure());
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());

  // Synced: the gate opens, the mode never moved through the refusal.
  policy.setTimeSynced(true);
  TEST_ASSERT_TRUE(policy.canValidateTls());
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Secure, policy.mode());
  TEST_ASSERT_TRUE(policy.shouldVerifyCertificate());
}

// In debug the mode and the ordering gate are independent: an insecure opt-out
// does not fake a validated decision. Verification is still reported as not
// performed, and it stays that way until the caller explicitly goes secure
// AND time is synced.
void test_insecure_mode_is_not_a_validated_decision(void) {
  insight::InsightTlsPolicy policy(/*isProduction=*/false);

  TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::Ok, policy.setInsecure());
  TEST_ASSERT_EQUAL_INT(insight::TlsMode::Insecure, policy.mode());

  // Syncing time opens the gate but must not silently turn insecure into a
  // verified connection.
  policy.setTimeSynced(true);
  TEST_ASSERT_TRUE(policy.canValidateTls());
  TEST_ASSERT_FALSE(policy.shouldVerifyCertificate());

  // Only an explicit return to secure, with the gate open, yields verification.
  policy.setSecure();
  TEST_ASSERT_TRUE(policy.shouldVerifyCertificate());
}

// Verification requires BOTH conditions together — it is not enough to be
// synced, nor enough to be secure. Table-driven over the four combinations.
void test_verification_requires_synced_and_secure(void) {
  const bool timeValues[] = {false, true};
  const insight::TlsMode modeValues[] = {insight::TlsMode::Secure,
                                         insight::TlsMode::Insecure};

  for (int t = 0; t < 2; ++t) {
    for (int m = 0; m < 2; ++m) {
      insight::InsightTlsPolicy policy(/*isProduction=*/false);
      policy.setTimeSynced(timeValues[t]);
      if (modeValues[m] == insight::TlsMode::Insecure) {
        TEST_ASSERT_EQUAL_INT(insight::TlsPolicyResult::Ok, policy.setInsecure());
      }

      const bool expected = timeValues[t] && (modeValues[m] == insight::TlsMode::Secure);
      TEST_ASSERT_EQUAL_INT(expected ? 1 : 0,
                            policy.shouldVerifyCertificate() ? 1 : 0);
    }
  }
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_production_secure_is_allowed);
  RUN_TEST(test_production_refuses_insecure_opt_out);
  RUN_TEST(test_production_refusal_is_sticky);
  RUN_TEST(test_debug_insecure_opt_out_is_allowed);
  RUN_TEST(test_debug_can_return_to_secure);
  RUN_TEST(test_default_policy_is_secure_and_gated);
  RUN_TEST(test_cannot_validate_before_sntp_sync);
  RUN_TEST(test_can_validate_after_sntp_sync);
  RUN_TEST(test_gate_tracks_sync_flag_both_ways);
  RUN_TEST(test_unsynced_clock_never_validates_secure_mode);
  RUN_TEST(test_unsynced_time_does_not_downgrade_production);
  RUN_TEST(test_insecure_mode_is_not_a_validated_decision);
  RUN_TEST(test_verification_requires_synced_and_secure);
  return UNITY_END();
}
