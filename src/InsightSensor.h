#ifndef INSIGHT_SENSOR_H
#define INSIGHT_SENSOR_H

#include <cstddef>

namespace insight {

// ---------------------------------------------------------------------------
// Reading a flaky sensor: retry, but never invent a value
// ---------------------------------------------------------------------------
//
// I2C/one-wire sensor reads fail intermittently — a bus glitch, a device that
// is not ready yet, a CRC that does not match. The failure mode that must not
// survive into telemetry is the SILENT one: a read that "succeeded" but handed
// back garbage. Two kinds of garbage matter here:
//
//   * an outright failure the driver reports (no reply, bad CRC), and
//   * a read that returns but is not a usable number — NaN or +/-Inf.
//
// readSensor() attacks both the same way: it treats a failed read and a
// non-finite value as the SAME kind of miss, retries up to maxAttempts, and
// returns the first finite reading it gets. It NEVER fabricates a value. If
// every attempt misses, it reports failure — so the caller can decide to send
// nothing, or send an explicit null (the honest "sensor is down" report the
// ingress contract accepts), rather than queueing a made-up number.
//
// The two things that make this untestable on a host — the actual read and the
// validity rule — are injected, following the seam style used across the SDK:
//
//   * `ReadFn` performs ONE read. It writes the raw sensor value to `*out` and
//     reports whether the read itself succeeded (false = no reading: bus
//     error, CRC mismatch, device absent). A null ReadFn models an absent
//     sensor: every attempt fails.
//   * `ValueFn` is the FINITE test applied to a returned value, so the same
//     rule the buffer broadcasts ("a non-null value must be finite; NaN/Inf is
//     rejected") is what readSensor() retries on. The default is the buffer's
//     own rule; pass a bare `isFinite` for firmware, or any predicate a test
//     wants to script.

// One sensor read. Writes the raw value to `*out` and returns true when the
// read itself succeeded (the value may still be NaN/Inf — that is retried),
// false when there was no reading at all (bus error / CRC / absent device).
// A null `out` must not be dereferenced; readSensor() always passes a real one.
typedef bool (*ReadFn)(float* out);

// Validity rule applied to a returned value: true => finite and usable, false
// => NaN/Inf and to be retried. Plain C function pointer, as elsewhere in the
// SDK, so firmware passes `isFinite` and tests pass a scripted predicate.
typedef bool (*ValueFn)(float value);

// Default attempts when a caller does not name a bound: one try plus two
// retries, the common "flaky I2C" cadence.
const int kSensorDefaultAttempts = 3;

// The buffer's finiteness rule, re-expressed as a `ValueFn`. Identical verdict
// to InsightBuffer's push() validation, so a value readSensor() accepts is one
// the buffer would accept: NaN fails `v == v`; +/-Inf fails the magnitude
// bounds. Reaching for the same test is the point — a reading is not "good"
// here if the buffer would later reject it.
inline bool isFiniteSensorValue(float value) {
  if (value != value) return false;  // NaN
  const float maxFloat = 3.4028234663852886e+38f;
  return value <= maxFloat && value >= -maxFloat;  // Inf fails both bounds
}

// Outcome of readSensor(): a good reading, or one of two named failures. The
// split is deliberate — "sensor absent" and "sensor answered but never with a
// number" are different field problems, and neither is a value.
enum class SensorReadResult {
  Ok,           // `*out` holds a finite reading.
  Failed,       // No reading at all: the read failed on every attempt.
  InvalidValue  // The sensor answered, but only with NaN/Inf — never a number.
};

// Read a sensor with bounded retries, skipping NaN/Inf, or report failure.
//
//   readSensor(readFn, maxAttempts) -> SensorReadResult
//   readSensor(readFn, maxAttempts, isFinite) -> SensorReadResult
//
// On Ok, `*out` holds the first finite reading. On any failure `*out` is left
// UNTOUCHED (a caller that zeroes it first keeps its zero; a caller that does
// not is not handed a fabricated sample). The return value is the only signal.
//
//   * maxAttempts <= 0 is clamped to 1 — "no attempts" would be a way to
//     produce no reading while looking like it tried, so at least one read is
//     always made.
//   * A null readFn (absent sensor) or a null isFinite (no rule to trust)
//     fails: Failed and InvalidValue respectively, without a call through a
//     null pointer. A null isFinite is refused rather than defaulted, so a
//     caller cannot silently lose the NaN/Inf guard.
//
// The loop reads at most maxAttempts times and returns the moment a finite
// value appears; it never sleeps between attempts (transient-failure backoff,
// if any, belongs to the caller's scheduling, exactly as with the send/flush
// policy — no delay() lives on this path).
inline SensorReadResult readSensor(ReadFn readFn, int maxAttempts, float* out,
                                   ValueFn isFinite) {
  if (readFn == 0) return SensorReadResult::Failed;
  if (isFinite == 0) return SensorReadResult::InvalidValue;

  int attempts = maxAttempts < 1 ? 1 : maxAttempts;
  bool sawValue = false;  // the sensor answered at least once (value too big)
  for (int i = 0; i < attempts; ++i) {
    float sample = 0.0f;
    if (!readFn(&sample)) continue;  // no reading this time; retry
    sawValue = true;
    if (!isFinite(sample)) continue;  // NaN/Inf: not a number; retry
    if (out != 0) *out = sample;
    return SensorReadResult::Ok;
  }
  // No finite reading in any attempt. Distinguish "never answered" from
  // "answered only with NaN/Inf"; either way, nothing was written to `*out`.
  return sawValue ? SensorReadResult::InvalidValue : SensorReadResult::Failed;
}

// Default-rule overload: retry on the buffer's NaN/Inf rule.
inline SensorReadResult readSensor(ReadFn readFn, int maxAttempts, float* out) {
  return readSensor(readFn, maxAttempts, out, &isFiniteSensorValue);
}

// Convenience overload with both defaults applied.
inline SensorReadResult readSensor(ReadFn readFn, float* out) {
  return readSensor(readFn, kSensorDefaultAttempts, out, &isFiniteSensorValue);
}

// True when `result` carries a usable reading (the OK case). Lets a caller
// write `if (isSensorReading(r)) use(*out);` without enumerating the failures.
inline bool isSensorReading(SensorReadResult result) {
  return result == SensorReadResult::Ok;
}

}  // namespace insight

#endif  // INSIGHT_SENSOR_H
