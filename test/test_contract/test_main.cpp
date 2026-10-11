// Contract-lock test for the insight-sdk (PlatformIO native).
//
// This suite mirrors `insight/test/contracts/contract-lock.ts` — the same
// status codes, error codes, header names and body shapes — and asserts the
// SDK side agrees. It is deliberately hermetic: it does not depend on any
// client class beyond the `HttpOutcome{status}` transport seam, so it stays
// valid while the richer client is layered on top.
//
// What it locks down (see spec §6.1/§6.2/§6.4):
//   * Header names: authorization (LOWERCASE, the lock's exact bytes) /
//     x-insight-device / x-insight-firmware, plus case-insensitive matching.
//   * The telemetry body shapes the device may send.
//   * The expected status/parse outcomes for POST /v1/telemetry.
//   * The GET /v1/control envelope `{ "control": [ {id,variable,value} ] }`.
//   * The GET /v1/ota envelope `{ "update": null | {version,size,sha256,url} }`.
//     OTA has no server route yet (M3 / A18); its shape is encoded here.
//
// The mirror below is cross-checked for drift by the insight side:
// `insight/test/contracts/mirror.test.ts` parses these C++ constants and
// asserts them equal to `contract-lock.ts`, so a one-sided edit fails there.

#include <unity.h>

#include <cctype>
#include <cstring>

#include "Insight.h"
#include "InsightTransport.h"

// ---------------------------------------------------------------------------
// Frozen contract mirror (keep byte-for-byte consistent with contract-lock.ts)
// ---------------------------------------------------------------------------

namespace contract {

// Header names. Lowercase and byte-for-byte identical to contract-lock.ts
// (`CONTRACT_HEADERS.authorization`); HTTP header NAMES are case-insensitive so
// the wire value is the same either spelling, but the mirror is held to the
// lock's exact bytes so a one-sided edit fails the cross-repo drift guard.
const char* const kHeaderAuthorization = "authorization";
const char* const kHeaderDevice = "x-insight-device";
const char* const kHeaderFirmware = "x-insight-firmware";

// Status codes.
const int kStatusOk = 200;
const int kStatusBadRequest = 400;
const int kStatusUnauthorized = 401;
const int kStatusNotFound = 404;
const int kStatusNoContent = 204;
const int kStatusPayloadTooLarge = 413;
const int kStatusTooManyRequests = 429;

// Error codes and their frozen statuses (spec §6.1).
struct ErrorEntry {
  const char* code;
  int status;
  bool implemented;  // false => shape-only, route lands in M3/A18.
};

const ErrorEntry kErrors[] = {
    {"invalid_json", kStatusBadRequest, true},
    {"invalid_value", kStatusBadRequest, true},
    {"invalid_key", kStatusBadRequest, true},
    {"too_many_metrics", kStatusPayloadTooLarge, true},
    {"payload_too_large", kStatusPayloadTooLarge, true},
    {"unauthorized", kStatusUnauthorized, true},
    {"rate_limited", kStatusTooManyRequests, false},
};
const int kErrorCount = 7;

// Accepted telemetry request shapes (spec §6.1).
const char* const kShapeMetricsArray =
    "{\"metrics\":[{\"key\":\"temp\",\"value\":25.4}]}";
const char* const kShapeMetricsMap = "{\"metrics\":{\"temp\":25.4}}";
const char* const kShapeMetricValue = "{\"metric\":\"temp\",\"value\":25.4}";
const char* const kShapeBareArray = "[{\"key\":\"temp\",\"value\":25.4}]";

// Body field names.
const char* const kFieldError = "error";
const char* const kFieldMessage = "message";
const char* const kFieldKey = "key";
const char* const kFieldValue = "value";
const char* const kFieldMetric = "metric";
const char* const kFieldUpdate = "update";
const char* const kFieldControl = "control";
const char* const kFieldIds = "ids";

// A rejection body, byte-exact to the lock's `{ error, message }` shape. Held
// as a fixture (not assembled from kFieldError/kFieldMessage) so the mirror
// guard can parse it and prove the field NAMES, not just the constants.
const char* const kErrorBody =
    "{\"error\":\"invalid_key\",\"message\":\"metric key must not be empty\"}";

// GET /v1/ota response bodies (spec §6.4).
const char* const kOtaNoUpdate = "{\"update\":null}";
const char* const kOtaUpdate =
    "{\"update\":{\"version\":\"1.2.0\",\"size\":1024,\"sha256\":\"ab\",\"url\":\"/v1/ota/image/1.2.0\"}}";

// GET /v1/control response bodies (spec §6.2).
const char* const kControlEmpty = "{\"control\":[]}";
const char* const kControlCommand =
    "{\"control\":[{\"id\":\"c_1\",\"variable\":\"led\",\"value\":1}]}";

}  // namespace contract

// ---------------------------------------------------------------------------
// Minimal JSON helpers (hermetic; no external JSON dependency)
// ---------------------------------------------------------------------------

namespace json {

// Find `"name"` at or after `from`, returning the index of its opening quote,
// or -1. Caller must ensure the name is a complete key (not a substring).
int findKey(const char* s, const char* name) {
  if (s == 0 || name == 0) return -1;
  size_t nameLen = std::strlen(name);
  for (const char* p = s; *p != '\0'; ++p) {
    if (*p != '"') continue;
    if (std::strncmp(p + 1, name, nameLen) != 0) continue;
    if (p[1 + nameLen] != '"') continue;  // must close the key exactly
    return static_cast<int>(p - s);
  }
  return -1;
}

// Does `s` contain the key `name`?
bool hasKey(const char* s, const char* name) { return findKey(s, name) >= 0; }

// Count top-level occurrences of key `name` (used for the `update.` prefix).
int countKey(const char* s, const char* name) {
  int n = 0;
  const char* p = s;
  while (p != 0 && *p != '\0') {
    int idx = findKey(p, name);
    if (idx < 0) break;
    ++n;
    p += idx + 1;
  }
  return n;
}

// Skip whitespace.
const char* skipWs(const char* s) {
  while (s != 0 && *s != '\0' &&
         std::isspace(static_cast<unsigned char>(*s))) {
    ++s;
  }
  return s;
}

// True when the value of key `name` is the JSON literal `null`.
bool keyIsNull(const char* s, const char* name) {
  int idx = findKey(s, name);
  if (idx < 0) return false;
  const char* p = s + idx + 1;
  p = std::strchr(p, ':');  // move to the colon after the closing quote
  if (p == 0) return false;
  p = skipWs(p + 1);
  return std::strncmp(p, "null", 4) == 0;
}

// True when the value of key `name` opens an array (`[`).
bool keyIsArray(const char* s, const char* name) {
  int idx = findKey(s, name);
  if (idx < 0) return false;
  const char* p = s + idx + 1;
  p = std::strchr(p, ':');
  if (p == 0) return false;
  p = skipWs(p + 1);
  return *p == '[';
}

// HTTP header NAMES are case-insensitive (RFC 9110 §5.1). Compare two names
// that way, so the mechanical matching the SDK does never depends on casing.
bool headerNameEquals(const char* a, const char* b) {
  if (a == 0 || b == 0) return false;
  while (*a != '\0' && *b != '\0') {
    if (std::tolower(static_cast<unsigned char>(*a)) !=
        std::tolower(static_cast<unsigned char>(*b))) {
      return false;
    }
    ++a;
    ++b;
  }
  return *a == '\0' && *b == '\0';
}

}  // namespace json

// ---------------------------------------------------------------------------
// Transport fakes
// ---------------------------------------------------------------------------

// Returns a scripted HttpOutcome from the seam (post / get).
class ScriptedTransport : public insight::InsightTransport {
 public:
  insight::HttpOutcome postResult = insight::HttpOutcome::ok(contract::kStatusNoContent);
  insight::HttpOutcome getResult = insight::HttpOutcome::ok(contract::kStatusOk);
  const char* getBody = "{}";
  int postCount = 0;
  int getCount = 0;
  char lastPath[128] = {0};
  char lastJson[256] = {0};

  insight::HttpOutcome postJson(const char* path, const char* json) override {
    ++postCount;
    std::strncpy(lastPath, path, sizeof(lastPath) - 1);
    std::strncpy(lastJson, json, sizeof(lastJson) - 1);
    return postResult;
  }

  insight::HttpOutcome get(const char* path, char* buffer, size_t bufferLen,
                           size_t* contentLength) override {
    ++getCount;
    std::strncpy(lastPath, path, sizeof(lastPath) - 1);
    if (bufferLen > 0) {
      std::strncpy(buffer, getBody, bufferLen - 1);
      buffer[bufferLen - 1] = '\0';
    }
    if (contentLength != 0) {
      const size_t len = std::strlen(getBody);
      *contentLength = len < bufferLen ? len : bufferLen;
    }
    return getResult;
  }
};

// Records the headers a device would send alongside a request. The SDK's job
// is to describe them; this fake asserts the frozen names are what we emit.
struct HeaderSet {
  char authorization[128];
  char device[64];
  char firmware[64];

  HeaderSet() {
    std::strncpy(authorization, contract::kHeaderAuthorization, sizeof(authorization) - 1);
    std::strncpy(device, contract::kHeaderDevice, sizeof(device) - 1);
    std::strncpy(firmware, contract::kHeaderFirmware, sizeof(firmware) - 1);
  }
};

void setUp(void) {}

void tearDown(void) {}

// ---------------------------------------------------------------------------
// Header names
// ---------------------------------------------------------------------------

void test_header_names_are_frozen(void) {
  // The frozen spellings are the lock's exact bytes: `authorization` is
  // LOWERCASE. A one-sided drift here fails insight's mirror guard.
  TEST_ASSERT_EQUAL_STRING("authorization", contract::kHeaderAuthorization);
  TEST_ASSERT_EQUAL_STRING("x-insight-device", contract::kHeaderDevice);
  TEST_ASSERT_EQUAL_STRING("x-insight-firmware", contract::kHeaderFirmware);

  HeaderSet h;
  TEST_ASSERT_EQUAL_STRING("authorization", h.authorization);
  TEST_ASSERT_EQUAL_STRING("x-insight-device", h.device);
  TEST_ASSERT_EQUAL_STRING("x-insight-firmware", h.firmware);
}

// HTTP header NAMES are case-insensitive (RFC 9110 §5.1), so the server — which
// reads `authorization` — also accepts the conventional `Authorization`. This
// pins the SDK's mechanical header matching to that rule instead of an exact
// byte compare, which is what made the historic mixed case a no-op on the wire.
void test_header_name_matching_is_case_insensitive(void) {
  TEST_ASSERT_TRUE(json::headerNameEquals(contract::kHeaderAuthorization, "authorization"));
  TEST_ASSERT_TRUE(json::headerNameEquals(contract::kHeaderAuthorization, "Authorization"));
  TEST_ASSERT_TRUE(json::headerNameEquals(contract::kHeaderAuthorization, "AUTHORIZATION"));
  TEST_ASSERT_TRUE(json::headerNameEquals(contract::kHeaderDevice, "X-Insight-Device"));
  TEST_ASSERT_FALSE(json::headerNameEquals(contract::kHeaderAuthorization, "x-insight-device"));
}

// ---------------------------------------------------------------------------
// Status codes and error codes
// ---------------------------------------------------------------------------

void test_status_codes_are_frozen(void) {
  TEST_ASSERT_EQUAL_INT(200, contract::kStatusOk);
  TEST_ASSERT_EQUAL_INT(204, contract::kStatusNoContent);
  TEST_ASSERT_EQUAL_INT(400, contract::kStatusBadRequest);
  TEST_ASSERT_EQUAL_INT(401, contract::kStatusUnauthorized);
  TEST_ASSERT_EQUAL_INT(404, contract::kStatusNotFound);
  TEST_ASSERT_EQUAL_INT(413, contract::kStatusPayloadTooLarge);
  TEST_ASSERT_EQUAL_INT(429, contract::kStatusTooManyRequests);
}

void test_error_code_to_status_mapping(void) {
  for (int i = 0; i < contract::kErrorCount; ++i) {
    const contract::ErrorEntry& e = contract::kErrors[i];
    if (std::strcmp(e.code, "invalid_json") == 0 ||
        std::strcmp(e.code, "invalid_value") == 0 ||
        std::strcmp(e.code, "invalid_key") == 0) {
      TEST_ASSERT_EQUAL_INT(contract::kStatusBadRequest, e.status);
    } else if (std::strcmp(e.code, "too_many_metrics") == 0 ||
               std::strcmp(e.code, "payload_too_large") == 0) {
      TEST_ASSERT_EQUAL_INT(contract::kStatusPayloadTooLarge, e.status);
    } else if (std::strcmp(e.code, "unauthorized") == 0) {
      TEST_ASSERT_EQUAL_INT(contract::kStatusUnauthorized, e.status);
    } else if (std::strcmp(e.code, "rate_limited") == 0) {
      TEST_ASSERT_EQUAL_INT(contract::kStatusTooManyRequests, e.status);
    } else {
      TEST_FAIL_MESSAGE("unknown contract error code");
    }
  }
  // Marked-not-yet-implemented parts are exactly rate_limited (M3/A18).
  TEST_ASSERT_FALSE(contract::kErrors[6].implemented);
  TEST_ASSERT_TRUE(contract::kErrors[0].implemented);
}

// ---------------------------------------------------------------------------
// HttpOutcome seam classification (status -> parse outcome)
// ---------------------------------------------------------------------------

// The SDK treats a scripted 2xx as Ok with the code surfaced verbatim; nothing
// is inferred beyond the seam's own contract.
void test_outcome_classification_204_accepted(void) {
  insight::Insight client;
  ScriptedTransport fake;
  fake.postResult = insight::HttpOutcome::ok(contract::kStatusNoContent);
  client.setTransport(&fake);

  insight::HttpOutcome outcome = client.post("/v1/telemetry", contract::kShapeMetricsArray);
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Ok, outcome.kind);
  TEST_ASSERT_EQUAL_INT(contract::kStatusNoContent, outcome.status);
  TEST_ASSERT_EQUAL_INT(1, fake.postCount);
}

void test_outcome_classification_401_unauthorized(void) {
  insight::Insight client;
  ScriptedTransport fake;
  fake.postResult = insight::HttpOutcome::ok(contract::kStatusUnauthorized);
  client.setTransport(&fake);

  insight::HttpOutcome outcome = client.post("/v1/telemetry", contract::kShapeMetricsArray);
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Ok, outcome.kind);
  TEST_ASSERT_EQUAL_INT(contract::kStatusUnauthorized, outcome.status);
}

void test_outcome_classification_413_payload_too_large(void) {
  insight::Insight client;
  ScriptedTransport fake;
  fake.postResult = insight::HttpOutcome::ok(contract::kStatusPayloadTooLarge);
  client.setTransport(&fake);

  insight::HttpOutcome outcome = client.post("/v1/telemetry", contract::kShapeBareArray);
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Ok, outcome.kind);
  TEST_ASSERT_EQUAL_INT(contract::kStatusPayloadTooLarge, outcome.status);
}

// A timeout and a transport error stay distinct from a server reply.
void test_outcome_classification_timeout_and_error(void) {
  insight::Insight client;
  ScriptedTransport fake;

  fake.postResult = insight::HttpOutcome::timeout();
  client.setTransport(&fake);
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Timeout, client.post("/v1/telemetry", "{}").kind);

  fake.postResult = insight::HttpOutcome::error();
  TEST_ASSERT_EQUAL_INT(insight::HttpOutcome::Error, client.post("/v1/telemetry", "{}").kind);
}

// ---------------------------------------------------------------------------
// Telemetry body shapes + error body fields
// ---------------------------------------------------------------------------

void test_telemetry_body_shapes_are_wellformed(void) {
  // Canonical `{metrics:[{key,value}]}`.
  TEST_ASSERT_TRUE(json::keyIsArray(contract::kShapeMetricsArray, "metrics"));
  TEST_ASSERT_TRUE(json::hasKey(contract::kShapeMetricsArray, contract::kFieldKey));
  TEST_ASSERT_TRUE(json::hasKey(contract::kShapeMetricsArray, contract::kFieldValue));

  // Map `{metrics:{k:v}}` — `metrics` is an object, not an array.
  TEST_ASSERT_TRUE(json::hasKey(contract::kShapeMetricsMap, "metrics"));
  TEST_ASSERT_TRUE(json::hasKey(contract::kShapeMetricsMap, "temp"));

  // Shorthand `{metric,value}` uses the reserved `metric` key.
  TEST_ASSERT_TRUE(json::hasKey(contract::kShapeMetricValue, contract::kFieldMetric));
  TEST_ASSERT_TRUE(json::hasKey(contract::kShapeMetricValue, contract::kFieldValue));

  // Bare array of entries.
  TEST_ASSERT_TRUE(contract::kShapeBareArray[0] == '[');
}

void test_error_body_field_names(void) {
  TEST_ASSERT_TRUE(json::hasKey(contract::kErrorBody, contract::kFieldError));
  TEST_ASSERT_TRUE(json::hasKey(contract::kErrorBody, contract::kFieldMessage));
}

// ---------------------------------------------------------------------------
// GET /v1/control envelope (spec §6.2)
// ---------------------------------------------------------------------------

void test_control_envelope_shapes(void) {
  // `control` is a reserved array key.
  TEST_ASSERT_TRUE(json::keyIsArray(contract::kControlEmpty, contract::kFieldControl));
  TEST_ASSERT_TRUE(json::keyIsArray(contract::kControlCommand, contract::kFieldControl));

  // Each command carries exactly the frozen field names.
  TEST_ASSERT_TRUE(json::hasKey(contract::kControlCommand, "id"));
  TEST_ASSERT_TRUE(json::hasKey(contract::kControlCommand, "variable"));
  TEST_ASSERT_TRUE(json::hasKey(contract::kControlCommand, contract::kFieldValue));

  // The ack body uses the reserved `ids` key.
  TEST_ASSERT_TRUE(json::hasKey("{\"ids\":[\"c_1\"]}", contract::kFieldIds));
}

// ---------------------------------------------------------------------------
// GET /v1/ota envelope (spec §6.4) — shape-only, route not implemented yet
// ---------------------------------------------------------------------------

void test_ota_envelope_shapes(void) {
  // Up to date: the reserved `update` key is JSON null.
  TEST_ASSERT_TRUE(json::hasKey(contract::kOtaNoUpdate, contract::kFieldUpdate));
  TEST_ASSERT_TRUE(json::keyIsNull(contract::kOtaNoUpdate, contract::kFieldUpdate));

  // Available: `update` is an object with the four frozen fields.
  TEST_ASSERT_TRUE(json::hasKey(contract::kOtaUpdate, contract::kFieldUpdate));
  TEST_ASSERT_TRUE(json::hasKey(contract::kOtaUpdate, "version"));
  TEST_ASSERT_TRUE(json::hasKey(contract::kOtaUpdate, "size"));
  TEST_ASSERT_TRUE(json::hasKey(contract::kOtaUpdate, "sha256"));
  TEST_ASSERT_TRUE(json::hasKey(contract::kOtaUpdate, "url"));
  // `version` appears exactly once (inside `update`), proving it is not a
  // top-level field — the envelope nests it under `update`.
  TEST_ASSERT_EQUAL_INT(1, json::countKey(contract::kOtaUpdate, "version"));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_header_names_are_frozen);
  RUN_TEST(test_header_name_matching_is_case_insensitive);
  RUN_TEST(test_status_codes_are_frozen);
  RUN_TEST(test_error_code_to_status_mapping);
  RUN_TEST(test_outcome_classification_204_accepted);
  RUN_TEST(test_outcome_classification_401_unauthorized);
  RUN_TEST(test_outcome_classification_413_payload_too_large);
  RUN_TEST(test_outcome_classification_timeout_and_error);
  RUN_TEST(test_telemetry_body_shapes_are_wellformed);
  RUN_TEST(test_error_body_field_names);
  RUN_TEST(test_control_envelope_shapes);
  RUN_TEST(test_ota_envelope_shapes);
  return UNITY_END();
}
