// Unit tests for insight::readSensor() and insight::InsightDiagnostics —
// "a flaky sensor must not become a fabricated number" and "diagnostics are
// opt-in" (plan B10; FR-SDK-09/10, FR-SDK-11).
//
// Both classes are seams-only, so everything here is decided on the host with
// no hardware, no clock, and no network:
//
//   * readSensor() takes a ReadFn (one real read) and a ValueFn (the finite
//     test). A scripted ReadFn replays "fails, fails, then succeeds" or
//     "always NaN", and the tests assert both the returned reading AND that a
//     failure never wrote anything into the output slot.
//   * InsightDiagnostics takes a payload buffer; the tests assert the RSSI and
//     uptime members are present exactly when enabled and absent otherwise.
//
// The buffer's own finite rule is cross-checked against the sensor helper's,
// so "readSensor accepted it" and "the buffer would accept it" cannot drift.

#include <unity.h>

#include <cmath>
#include <cstring>
#include <limits>

#include "InsightBuffer.h"
#include "InsightDiagnostics.h"
#include "InsightSensor.h"

namespace {

const float kNaN = std::numeric_limits<float>::quiet_NaN();
const float kInf = std::numeric_limits<float>::infinity();

// Scripted read seam: replays a fixed sequence of outcomes, one per call, and
// then repeats the last outcome for any further call. Counting calls lets a
// test assert the exact ATTEMPT COUNT, not just the eventual value — which is
// what distinguishes "retried" from "got lucky on a longer loop".
class ScriptedRead {
 public:
  struct Step {
    bool ok;     // did the read itself succeed?
    float value; // the raw value it produced (may be NaN/Inf even when ok)
  };

  explicit ScriptedRead(const Step* steps, int len)
      : len_(len > kMaxSteps ? kMaxSteps : len), calls_(0) {
    for (int i = 0; i < len_; ++i) steps_[i] = steps[i];
  }

  int calls() const { return calls_; }

  // One read: pop the next scripted step and write its value. Once the script
  // is exhausted (or empty) every further call FAILS, so "the sensor had
  // nothing more to give" is modelled by the script simply running out.
  bool operator()(float* out) {
    const int idx = calls_;
    ++calls_;
    if (idx >= len_) return false;  // no step left => the read fails
    if (out != 0) *out = steps_[idx].value;
    return steps_[idx].ok;
  }

 private:
  static const int kMaxSteps = 16;
  Step steps_[kMaxSteps];
  int len_;
  int calls_;
};

// Thunks: readSensor() takes a plain C function pointer, so a stateful fixture
// is reached through a pointer the test installs first.
ScriptedRead* g_read = 0;
bool readTrampoline(float* out) { return (*g_read)(out); }

// A predicate that only accepts a value equal to a fixed "good" number, so a
// test can control the finite rule independently of the sensor's own output.
float g_wanted = 0.0f;
bool wantedTrampoline(float value) { return value == g_wanted; }

// Build INLINE JSON through the diagnostics object, exactly as a payload
// writer would: the buffer already holds "{", then the diagnostic members,
// then the caller's "}" is appended. Returns the buffer for assertions.
const char* renderWithDiagnostics(const insight::InsightDiagnostics& diag,
                                  char* buffer, size_t capacity) {
  size_t n = 0;
  buffer[n++] = '{';
  size_t len = n;
  diag.appendJsonTo(buffer, capacity, &len);
  n = len;
  buffer[n++] = '}';
  buffer[n] = '\0';
  return buffer;
}

// The same renderer with diagnostics off: "{" + "}". Used to prove the off
// path leaves the payload byte-for-byte unchanged.
const char* renderDisabled(char* buffer, size_t capacity) {
  (void)capacity;
  buffer[0] = '{';
  buffer[1] = '}';
  buffer[2] = '\0';
  return buffer;
}

}  // namespace

void setUp(void) {}

void tearDown(void) {}

// ---------------------------------------------------------------------------
// readSensor(): retry, skip NaN/Inf, never fabricate
// ---------------------------------------------------------------------------

// The acceptance case: a read that FAILS once, then succeeds, yields the good
// value — the failure was retried, not returned.
void test_read_succeeds_after_one_failure(void) {
  const ScriptedRead::Step steps[] = {{false, 0.0f}, {true, 24.5f}};
  ScriptedRead reader(steps, 2);
  g_read = &reader;

  float value = 0.0f;
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::Ok),
      static_cast<int>(insight::readSensor(&readTrampoline, 3, &value)));
  TEST_ASSERT_EQUAL_FLOAT(24.5f, value);
  TEST_ASSERT_EQUAL_INT(2, reader.calls());  // exactly one retry, no more
}

// A read that succeeds but returns NaN ONCE, then a real value, is retried the
// same way: a non-finite sample is a miss, not a reading.
void test_read_retries_and_skips_nan_then_succeeds(void) {
  const ScriptedRead::Step steps[] = {{true, kNaN}, {true, 7.25f}};
  ScriptedRead reader(steps, 2);
  g_read = &reader;

  float value = 0.0f;
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::Ok),
      static_cast<int>(insight::readSensor(&readTrampoline, 3, &value)));
  TEST_ASSERT_EQUAL_FLOAT(7.25f, value);
  TEST_ASSERT_EQUAL_INT(2, reader.calls());
}

// The first attempt may already be good: readSensor() returns at once and does
// not consult the remaining attempts.
void test_read_returns_immediately_on_first_good_value(void) {
  const ScriptedRead::Step steps[] = {{true, 3.5f}, {true, 99.0f}};
  ScriptedRead reader(steps, 2);
  g_read = &reader;

  float value = 0.0f;
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::Ok),
      static_cast<int>(insight::readSensor(&readTrampoline, 5, &value)));
  TEST_ASSERT_EQUAL_FLOAT(3.5f, value);
  TEST_ASSERT_EQUAL_INT(1, reader.calls());
}

// A sensor that ALWAYS answers with NaN/Inf reports failure and never a bogus
// value: the result is InvalidValue ("answered, never with a number") and the
// output slot keeps whatever the caller put there.
void test_always_nan_reports_failure_never_a_bogus_value(void) {
  const ScriptedRead::Step steps[] = {
      {true, kNaN}, {true, kNaN}, {true, kNaN}, {true, kNaN}};
  ScriptedRead reader(steps, 4);
  g_read = &reader;

  float value = 123.0f;  // a caller-supplied slot; must NOT be overwritten
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::InvalidValue),
      static_cast<int>(insight::readSensor(&readTrampoline, 3, &value)));
  TEST_ASSERT_EQUAL_FLOAT(123.0f, value);  // untouched: no fabricated reading
  TEST_ASSERT_EQUAL_INT(3, reader.calls());  // exactly maxAttempts attempts
}

// +Inf and -Inf are skipped just like NaN; if they are all the sensor ever
// offers, the read fails rather than passing a non-finite number through.
void test_always_inf_reports_failure(void) {
  const ScriptedRead::Step steps[] = {
      {true, kInf}, {true, -kInf}, {true, kInf}, {true, -kInf}};
  ScriptedRead reader(steps, 4);
  g_read = &reader;

  float value = -5.0f;
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::InvalidValue),
      static_cast<int>(insight::readSensor(&readTrampoline, 2, &value)));
  TEST_ASSERT_EQUAL_FLOAT(-5.0f, value);
  TEST_ASSERT_EQUAL_INT(2, reader.calls());
}

// A read that fails on every attempt (no reply at all) is a plain Failed, and
// again nothing is written to the output slot.
void test_always_failing_read_reports_failed(void) {
  const ScriptedRead::Step steps[] = {{false, 0.0f}, {false, 0.0f}, {false, 0.0f}};
  ScriptedRead reader(steps, 3);
  g_read = &reader;

  float value = 42.0f;
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::Failed),
      static_cast<int>(insight::readSensor(&readTrampoline, 3, &value)));
  TEST_ASSERT_EQUAL_FLOAT(42.0f, value);
  TEST_ASSERT_EQUAL_INT(3, reader.calls());
}

// The attempt bound is honoured exactly: a sensor that would only answer with
// a good value on its 5th try fails at maxAttempts == 3, having made exactly 3
// tries — the 4th and 5th are never reached.
void test_attempt_bound_is_exact(void) {
  const ScriptedRead::Step steps[] = {
      {true, kNaN}, {true, kNaN}, {true, kInf}, {true, kNaN}, {true, 12.0f}};
  ScriptedRead reader(steps, 5);
  g_read = &reader;

  float value = 0.0f;
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::InvalidValue),
      static_cast<int>(insight::readSensor(&readTrampoline, 3, &value)));
  TEST_ASSERT_EQUAL_INT(3, reader.calls());  // the 5th, good step never runs
}

// maxAttempts <= 0 is clamped to a single attempt, so "retry" can never be a
// way to make zero reads while claiming to have tried.
void test_nonpositive_attempts_clamped_to_one(void) {
  const ScriptedRead::Step steps[] = {{true, 9.0f}};
  ScriptedRead reader(steps, 1);
  g_read = &reader;

  float value = 0.0f;
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::Ok),
      static_cast<int>(insight::readSensor(&readTrampoline, 0, &value)));
  TEST_ASSERT_EQUAL_INT(1, reader.calls());
}

// A null read seam models an absent sensor: Failed, with no call through null.
void test_null_read_seam_fails_cleanly(void) {
  float value = 1.0f;
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::Failed),
      static_cast<int>(insight::readSensor(
          static_cast<insight::ReadFn>(0), 3, &value)));
  TEST_ASSERT_EQUAL_FLOAT(1.0f, value);
}

// The finite rule is injected, and readSensor applies it rather than trusting
// the raw value: a sensor answering a value the rule rejects is retried.
void test_custom_finite_rule_is_applied(void) {
  const ScriptedRead::Step steps[] = {{true, 1.0f}, {true, 2.0f}, {true, 3.0f}};
  ScriptedRead reader(steps, 3);
  g_read = &reader;
  g_wanted = 3.0f;  // only 3.0 is acceptable to this rule

  float value = 0.0f;
  TEST_ASSERT_EQUAL_INT(
      static_cast<int>(insight::SensorReadResult::Ok),
      static_cast<int>(insight::readSensor(&readTrampoline, 3, &value,
                                           &wantedTrampoline)));
  TEST_ASSERT_EQUAL_FLOAT(3.0f, value);
  TEST_ASSERT_EQUAL_INT(3, reader.calls());
}

// The helper's default finite rule agrees with the buffer's push() validation
// on the whole edge set, so a reading readSensor() accepts is one the buffer
// will accept — the two "good value" definitions cannot drift apart.
void test_default_rule_matches_buffer_validation(void) {
  const float samples[] = {0.0f, 21.5f, -40.0f,
                           std::numeric_limits<float>::max(), kNaN, kInf, -kInf};
  for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
    const float v = samples[i];
    const bool sensorSays = insight::isFiniteSensorValue(v);

    insight::InsightBuffer buffer;
    const bool bufferSays = buffer.push("probe", v);

    TEST_ASSERT_EQUAL_INT(sensorSays ? 1 : 0, bufferSays ? 1 : 0);
  }
}

// End to end through the buffer seam: a retried-good reading is pushed as a
// NUMBER, and an always-NaN sensor is reported as null — never a fabricated
// value. This is the "no fake data" property seen from the ingest side.
void test_retried_reading_pushes_as_number_and_nan_pushes_null(void) {
  insight::InsightBuffer buffer;

  // Good path: fail once, then a real reading -> a numeric metric.
  const ScriptedRead::Step goodSteps[] = {{false, 0.0f}, {true, 18.75f}};
  ScriptedRead goodReader(goodSteps, 2);
  g_read = &goodReader;
  float value = 0.0f;
  TEST_ASSERT_TRUE(insight::isSensorReading(
      insight::readSensor(&readTrampoline, 3, &value)));
  TEST_ASSERT_TRUE(buffer.push("temp", value));

  // Bad path: the sensor never returns a number -> the honest report is null.
  const ScriptedRead::Step badSteps[] = {{true, kNaN}, {true, kNaN}};
  ScriptedRead badReader(badSteps, 2);
  g_read = &badReader;
  const insight::SensorReadResult failed =
      insight::readSensor(&readTrampoline, 2, &value);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(insight::SensorReadResult::InvalidValue),
                        static_cast<int>(failed));
  TEST_ASSERT_TRUE(buffer.push("humidity", insight::MetricValue::null()));

  insight::MetricValue temp;
  TEST_ASSERT_TRUE(buffer.get("temp", &temp));
  TEST_ASSERT_TRUE(temp.hasValue);
  TEST_ASSERT_EQUAL_FLOAT(18.75f, temp.value);

  insight::MetricValue humidity;
  TEST_ASSERT_TRUE(buffer.get("humidity", &humidity));
  TEST_ASSERT_FALSE(humidity.hasValue);  // null, not a substituted number
}

// ---------------------------------------------------------------------------
// InsightDiagnostics: opt-in RSSI + uptime
// ---------------------------------------------------------------------------

// Disabled by default: an untouched object contributes nothing, so the payload
// is exactly the empty object a caller would have sent anyway.
void test_diagnostics_disabled_by_default(void) {
  insight::InsightDiagnostics diag;
  TEST_ASSERT_FALSE(diag.enabled());
  TEST_ASSERT_FALSE(diag.hasAny());

  char buffer[insight::kDiagnosticsJsonMax];
  size_t len = 1;  // caller has already written "{"
  TEST_ASSERT_FALSE(diag.appendJsonTo(buffer, sizeof(buffer), &len));
  TEST_ASSERT_EQUAL_INT(1, static_cast<int>(len));  // nothing appended
}

// Enabled: the payload includes BOTH RSSI and uptime, at the flat keys.
void test_diagnostics_enabled_includes_rssi_and_uptime(void) {
  insight::InsightDiagnostics diag;
  diag.setEnabled(true);
  diag.setRssi(-62);
  diag.setRssiEnabled(true);
  diag.setUptimeMillis(123456);
  diag.setUptimeEnabled(true);

  char buffer[insight::kDiagnosticsJsonMax];
  const char* json = renderWithDiagnostics(diag, buffer, sizeof(buffer));

  TEST_ASSERT_TRUE(diag.hasAny());
  TEST_ASSERT_NOT_NULL(std::strstr(json, "\"rssi\":-62"));
  TEST_ASSERT_NOT_NULL(std::strstr(json, "\"uptime_ms\":123456"));
  // The two members are separated, producing a parseable object.
  TEST_ASSERT_NOT_NULL(std::strstr(json, "\"rssi\":-62,\"uptime_ms\":123456"));
}

// Disabled: the same values are NOT included — the off switch wins over any
// value that happens to be set.
void test_diagnostics_disabled_excludes_fields(void) {
  insight::InsightDiagnostics diag;
  diag.setRssi(-62);
  diag.setRssiEnabled(true);
  diag.setUptimeMillis(123456);
  diag.setUptimeEnabled(true);
  diag.setEnabled(false);  // master off

  char buffer[insight::kDiagnosticsJsonMax];
  const char* json = renderWithDiagnostics(diag, buffer, sizeof(buffer));

  TEST_ASSERT_NULL(std::strstr(json, "rssi"));
  TEST_ASSERT_NULL(std::strstr(json, "uptime"));
  TEST_ASSERT_EQUAL_STRING("{}", json);
}

// Disabling after enabling drops the fields back out entirely.
void test_diagnostics_toggle_off_removes_fields(void) {
  insight::InsightDiagnostics diag;
  diag.setEnabled(true);
  diag.setRssi(-70);
  diag.setRssiEnabled(true);
  diag.setUptimeMillis(500);
  diag.setUptimeEnabled(true);

  char buffer[insight::kDiagnosticsJsonMax];
  const char* on = renderWithDiagnostics(diag, buffer, sizeof(buffer));
  TEST_ASSERT_NOT_NULL(std::strstr(on, "\"rssi\":-70"));

  diag.setEnabled(false);
  const char* off = renderWithDiagnostics(diag, buffer, sizeof(buffer));
  TEST_ASSERT_EQUAL_STRING("{}", off);
}

// A field whose own flag is off is omitted even while diagnostics are on: the
// boot window (diagnostics enabled, RSSI not sampled) never emits a fake RSSI.
void test_diagnostics_partial_fields(void) {
  insight::InsightDiagnostics diag;
  diag.setEnabled(true);
  diag.setUptimeMillis(1);  // a real "just booted" uptime
  diag.setUptimeEnabled(true);
  // RSSI deliberately left off.
  diag.setRssi(0);

  char buffer[insight::kDiagnosticsJsonMax];
  const char* json = renderWithDiagnostics(diag, buffer, sizeof(buffer));

  TEST_ASSERT_NOT_NULL(std::strstr(json, "\"uptime_ms\":1"));
  TEST_ASSERT_NULL(std::strstr(json, "rssi"));

  // RSSI alone, uptime off, produces just the one member.
  diag.setUptimeEnabled(false);
  diag.setRssi(-55);
  diag.setRssiEnabled(true);
  const char* rssiOnly = renderWithDiagnostics(diag, buffer, sizeof(buffer));
  TEST_ASSERT_NOT_NULL(std::strstr(rssiOnly, "\"rssi\":-55"));
  TEST_ASSERT_NULL(std::strstr(rssiOnly, "uptime"));
}

// Uptime 0 is a legitimate value and is emitted when enabled; RSSI may be 0 or
// negative without being mistaken for "absent".
void test_diagnostics_zero_uptime_and_signed_rssi(void) {
  insight::InsightDiagnostics diag;
  diag.setEnabled(true);
  diag.setRssi(0);
  diag.setRssiEnabled(true);
  diag.setUptimeMillis(0);
  diag.setUptimeEnabled(true);

  char buffer[insight::kDiagnosticsJsonMax];
  const char* json = renderWithDiagnostics(diag, buffer, sizeof(buffer));
  TEST_ASSERT_NOT_NULL(std::strstr(json, "\"rssi\":0"));
  TEST_ASSERT_NOT_NULL(std::strstr(json, "\"uptime_ms\":0"));
}

// The keys are the frozen flat telemetry keys, shared as constants.
void test_diagnostics_keys_are_frozen(void) {
  TEST_ASSERT_EQUAL_STRING("rssi", insight::diagnosticsRssiKey());
  TEST_ASSERT_EQUAL_STRING("uptime_ms", insight::diagnosticsUptimeKey());
}

// Appending never overruns the buffer: an over-tight capacity truncates and
// stays NUL-terminated rather than writing past the end.
void test_diagnostics_truncates_safely(void) {
  insight::InsightDiagnostics diag;
  diag.setEnabled(true);
  diag.setRssi(-123);
  diag.setRssiEnabled(true);

  char small[8];
  for (size_t i = 0; i < sizeof(small); ++i) small[i] = 'x';
  size_t len = 1;
  diag.appendJsonTo(small, sizeof(small), &len);
  TEST_ASSERT_EQUAL_INT('\0', small[sizeof(small) - 1]);  // terminated
}

// The disabled renderer and the disabled diagnostics object agree: proving the
// "off" payload is what the caller would have produced with no object at all.
void test_disabled_matches_plain_payload(void) {
  insight::InsightDiagnostics diag;  // default: off

  char withDiag[insight::kDiagnosticsJsonMax];
  char plain[insight::kDiagnosticsJsonMax];
  TEST_ASSERT_EQUAL_STRING(renderDisabled(plain, sizeof(plain)),
                           renderWithDiagnostics(diag, withDiag, sizeof(withDiag)));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_read_succeeds_after_one_failure);
  RUN_TEST(test_read_retries_and_skips_nan_then_succeeds);
  RUN_TEST(test_read_returns_immediately_on_first_good_value);
  RUN_TEST(test_always_nan_reports_failure_never_a_bogus_value);
  RUN_TEST(test_always_inf_reports_failure);
  RUN_TEST(test_always_failing_read_reports_failed);
  RUN_TEST(test_attempt_bound_is_exact);
  RUN_TEST(test_nonpositive_attempts_clamped_to_one);
  RUN_TEST(test_null_read_seam_fails_cleanly);
  RUN_TEST(test_custom_finite_rule_is_applied);
  RUN_TEST(test_default_rule_matches_buffer_validation);
  RUN_TEST(test_retried_reading_pushes_as_number_and_nan_pushes_null);
  RUN_TEST(test_diagnostics_disabled_by_default);
  RUN_TEST(test_diagnostics_enabled_includes_rssi_and_uptime);
  RUN_TEST(test_diagnostics_disabled_excludes_fields);
  RUN_TEST(test_diagnostics_toggle_off_removes_fields);
  RUN_TEST(test_diagnostics_partial_fields);
  RUN_TEST(test_diagnostics_zero_uptime_and_signed_rssi);
  RUN_TEST(test_diagnostics_keys_are_frozen);
  RUN_TEST(test_diagnostics_truncates_safely);
  RUN_TEST(test_disabled_matches_plain_payload);
  return UNITY_END();
}
