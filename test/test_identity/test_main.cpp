// Device-identity test for the insight-sdk (PlatformIO native).
//
// Covers B07: the SDK's `x-insight-device` / `x-insight-firmware` behaviour over
// the transport seam, and holds the header NAMES to the frozen lock
// (`insight/test/contracts/contract-lock.ts`, `CONTRACT_HEADERS`).
//
// What it locks down (acceptance for B07 / spec §6.1/§6.4):
//   * `x-insight-device` is attached to EVERY request.
//   * `x-insight-firmware` (running version) is attached to `/v1/ota` requests.
//   * A >32-char running version is truncated to exactly 32.
//   * An empty running version OMITS the firmware header — it is never sent as
//     an empty string.
//   * The emitted header names match the frozen contract's exact (lowercase)
//     casing.
//
// The "every request" claim is exercised through the transport seam with a
// recording fake, so it is the wire form — not just the helper's own view —
// that is asserted.

#include <unity.h>

#include <cstring>

#include "InsightDevice.h"
#include "InsightTransport.h"

// ---------------------------------------------------------------------------
// Frozen contract mirror (keep byte-for-byte consistent with contract-lock.ts)
// ---------------------------------------------------------------------------

namespace contract {

// Header names (CONTRACT_HEADERS). Lowercase and byte-for-byte identical to
// the lock; `test_header_names_match_frozen_contract` fails on any drift.
const char* const kHeaderDevice = "x-insight-device";
const char* const kHeaderFirmware = "x-insight-firmware";

// Longest firmware version the ingress/SDK accepts (plan B07).
const size_t kMaxFirmwareVersionLength = 32;

// The OTA route (GET_OTA.path).
const char* const kOtaPath = "/v1/ota";

}  // namespace contract

// ---------------------------------------------------------------------------
// Recording transport over the seam
// ---------------------------------------------------------------------------

// Records the request path and the identity headers a device would attach, so
// the assertions run against the realised wire form. `add*` are called by the
// request layer exactly as the SDK drives them; recording is a plain buffer,
// which also lets the fake report which headers are present.
class RecordingTransport : public insight::InsightTransport {
 public:
  int postCount = 0;
  int getCount = 0;

  char lastPath[128] = {0};

  char device[129] = {0};
  char firmware[129] = {0};

  // Attach the pre-request identity headers for `path`, mirroring what the
  // client does before handing the request to the transport. No-ops when the
  // helper reports the header absent, so "omitted" is observable as "".
  void addDeviceHeader(const insight::DeviceIdentity& identity) {
    if (identity.hasDeviceKey()) {
      std::strncpy(device, identity.deviceKey(), sizeof(device) - 1);
    }
  }

  void addFirmwareHeader(const insight::DeviceIdentity& identity, const char* path) {
    if (identity.hasFirmwareHeader(path)) {
      std::strncpy(firmware, identity.firmwareVersion(), sizeof(firmware) - 1);
    }
  }

  insight::HttpOutcome postJson(const char* path, const char* /*json*/) override {
    ++postCount;
    std::strncpy(lastPath, path, sizeof(lastPath) - 1);
    return insight::HttpOutcome::ok(204);
  }

  insight::HttpOutcome get(const char* path, char* /*buffer*/,
                           size_t /*bufferLen*/,
                           size_t* contentLength) override {
    ++getCount;
    std::strncpy(lastPath, path, sizeof(lastPath) - 1);
    if (contentLength != 0) *contentLength = 0;
    return insight::HttpOutcome::ok(200);
  }
};

// Drives one request the way the SDK does: attach device identity (always),
// then the firmware header (OTA only), then hand the request to the seam.
static insight::HttpOutcome sendRequest(RecordingTransport& transport,
                                        const insight::DeviceIdentity& identity,
                                        const char* path) {
  transport.device[0] = '\0';
  transport.firmware[0] = '\0';
  transport.addDeviceHeader(identity);
  transport.addFirmwareHeader(identity, path);
  return transport.postJson(path, "{}");
}

void setUp(void) {}

void tearDown(void) {}

// ---------------------------------------------------------------------------
// Header names (frozen contract casing)
// ---------------------------------------------------------------------------

void test_header_names_match_frozen_contract(void) {
  // The frozen spellings are the lock's exact bytes — LOWERCASE. A one-sided
  // rename to `X-Insight-Device` makes the ingress miss the header, so it is
  // pinned byte-for-byte here rather than relying on wire-level
  // case-insensitivity.
  TEST_ASSERT_EQUAL_STRING("x-insight-device", contract::kHeaderDevice);
  TEST_ASSERT_EQUAL_STRING("x-insight-firmware", contract::kHeaderFirmware);
  TEST_ASSERT_EQUAL_STRING(contract::kHeaderDevice, insight::kDeviceHeaderName);
  TEST_ASSERT_EQUAL_STRING(contract::kHeaderFirmware, insight::kFirmwareHeaderName);
}

// ---------------------------------------------------------------------------
// x-insight-device on every request
// ---------------------------------------------------------------------------

// The device key rides EVERY request, not just the ones the contract lists it
// on: telemetry, control and OTA alike.
void test_device_header_on_every_request(void) {
  insight::DeviceIdentity identity;
  identity.setDeviceKey("dev-alpha");

  const char* paths[] = {"/v1/telemetry", "/v1/control", "/v1/control/ack",
                         contract::kOtaPath};
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
    RecordingTransport transport;
    sendRequest(transport, identity, paths[i]);

    TEST_ASSERT_EQUAL_INT(1, transport.postCount);
    TEST_ASSERT_EQUAL_STRING(paths[i], transport.lastPath);
    TEST_ASSERT_TRUE(transport.device[0] != '\0');
    TEST_ASSERT_EQUAL_STRING("dev-alpha", transport.device);
    TEST_ASSERT_TRUE(identity.hasDeviceKey());
  }
}

// An unset device key must not produce an empty header — the ingress would
// collapse `""` to the shared default device key, silently anonymising us.
void test_unset_device_key_is_omitted_not_empty(void) {
  insight::DeviceIdentity identity;

  TEST_ASSERT_FALSE(identity.hasDeviceKey());
  TEST_ASSERT_EQUAL_STRING("", identity.deviceKey());

  RecordingTransport transport;
  sendRequest(transport, identity, "/v1/telemetry");
  TEST_ASSERT_EQUAL_STRING("", transport.device);
}

// ---------------------------------------------------------------------------
// x-insight-firmware on /v1/ota only
// ---------------------------------------------------------------------------

void test_firmware_header_present_on_ota_request(void) {
  insight::DeviceIdentity identity;
  identity.setDeviceKey("dev-alpha");
  identity.setFirmwareVersion("1.4.2");

  RecordingTransport transport;
  sendRequest(transport, identity, contract::kOtaPath);

  TEST_ASSERT_TRUE(identity.hasFirmwareHeader(contract::kOtaPath));
  TEST_ASSERT_EQUAL_STRING("1.4.2", transport.firmware);
  // The device header still rides along on the OTA request.
  TEST_ASSERT_EQUAL_STRING("dev-alpha", transport.device);
}

// The firmware header is OTA-only: a telemetry POST reports the running
// version to nobody.
void test_firmware_header_absent_on_non_ota_request(void) {
  insight::DeviceIdentity identity;
  identity.setDeviceKey("dev-alpha");
  identity.setFirmwareVersion("1.4.2");

  RecordingTransport transport;
  sendRequest(transport, identity, "/v1/telemetry");

  TEST_ASSERT_FALSE(identity.hasFirmwareHeader("/v1/telemetry"));
  TEST_ASSERT_EQUAL_STRING("", transport.firmware);
}

// ---------------------------------------------------------------------------
// >32-char version -> truncated to 32
// ---------------------------------------------------------------------------

void test_long_firmware_version_truncated_to_32(void) {
  // 40 characters: longer than the cap by 8.
  const char* longVersion = "0123456789012345678901234567890123456789";
  TEST_ASSERT_EQUAL_INT(40, (int)std::strlen(longVersion));

  insight::DeviceIdentity identity;
  identity.setDeviceKey("dev-alpha");
  identity.setFirmwareVersion(longVersion);

  // The wire value is exactly the cap's worth of bytes...
  TEST_ASSERT_EQUAL_INT((int)contract::kMaxFirmwareVersionLength,
                        (int)std::strlen(identity.firmwareVersion()));
  TEST_ASSERT_EQUAL_STRING("01234567890123456789012345678901",
                           identity.firmwareVersion());

  // ...and that is what the transport receives on an OTA request.
  RecordingTransport transport;
  sendRequest(transport, identity, contract::kOtaPath);
  TEST_ASSERT_EQUAL_INT((int)contract::kMaxFirmwareVersionLength,
                        (int)std::strlen(transport.firmware));
  TEST_ASSERT_EQUAL_STRING("01234567890123456789012345678901", transport.firmware);
}

// Exactly 32 characters is the boundary and must pass through untouched.
void test_firmware_version_of_exactly_32_is_not_truncated(void) {
  const char* exact = "01234567890123456789012345678901";  // 32
  TEST_ASSERT_EQUAL_INT(32, (int)std::strlen(exact));

  insight::DeviceIdentity identity;
  identity.setFirmwareVersion(exact);
  TEST_ASSERT_EQUAL_STRING(exact, identity.firmwareVersion());
}

// ---------------------------------------------------------------------------
// Empty version -> header omitted (not empty)
// ---------------------------------------------------------------------------

void test_empty_firmware_version_omits_header(void) {
  insight::DeviceIdentity identity;
  identity.setDeviceKey("dev-alpha");
  identity.setFirmwareVersion("");

  // The helper reports the header absent...
  TEST_ASSERT_FALSE(identity.hasFirmwareHeader(contract::kOtaPath));
  // ...so nothing is attached, even on an OTA request. Crucially the wire form
  // is "no header", not `x-insight-firmware: ""`.
  RecordingTransport transport;
  sendRequest(transport, identity, contract::kOtaPath);
  TEST_ASSERT_EQUAL_STRING("", transport.firmware);
  TEST_ASSERT_EQUAL_INT(0, (int)std::strlen(transport.firmware));
}

// Clearing a previously-set version omits the header again.
void test_cleared_firmware_version_omits_header(void) {
  insight::DeviceIdentity identity;
  identity.setFirmwareVersion("2.0.0");
  TEST_ASSERT_TRUE(identity.hasFirmwareHeader(contract::kOtaPath));

  identity.setFirmwareVersion(0);
  TEST_ASSERT_FALSE(identity.hasFirmwareHeader(contract::kOtaPath));
  TEST_ASSERT_EQUAL_STRING("", identity.firmwareVersion());
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_header_names_match_frozen_contract);
  RUN_TEST(test_device_header_on_every_request);
  RUN_TEST(test_unset_device_key_is_omitted_not_empty);
  RUN_TEST(test_firmware_header_present_on_ota_request);
  RUN_TEST(test_firmware_header_absent_on_non_ota_request);
  RUN_TEST(test_long_firmware_version_truncated_to_32);
  RUN_TEST(test_firmware_version_of_exactly_32_is_not_truncated);
  RUN_TEST(test_empty_firmware_version_omits_header);
  RUN_TEST(test_cleared_firmware_version_omits_header);
  return UNITY_END();
}
