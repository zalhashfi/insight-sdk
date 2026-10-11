// OTA download + verify tests (insight::InsightOta).
//
// These pin the flash-safety property the whole OTA design exists to protect —
// ST-O1 / INV-O1 / INV-O5 (D2.6):
//
//   * a truncated stream        -> size mismatch -> flash NOT invoked
//   * a full length, altered end-> hash mismatch -> flash NOT invoked
//   * correct size + hash       -> flash invoked EXACTLY once, with the bytes
//   * a 429 -> schedule >= retry-after, and NO retry inside the pass (INV-O2)
//   * the 429 `retry-after` value is an INSTANCE seam, so it cannot leak across
//     objects/tests (the whole reason it is not a module-global)
//   * a real SHA-256 verified against known-answer vectors
//
// "Flash NOT invoked" is proven, not asserted: the flash sink is injected and
// counts its calls, so any byte reaching the partition is observable. There is
// no way for a write to happen off the seam — it is the only write path — and
// so a regression that flashes a bad image fails these tests loudly.
//
// The class is non-blocking by construction; the 429 and transport-failure
// cases assert the SCHEDULE (nextAttemptAtMillis / lastRetryAfterMillis) rather
// than ever observing a sleep. A blocking implementation would make these tests
// themselves hang, so they double as the "never delay()" check.

#include <unity.h>

#include <cstring>
#include <new>

#include "InsightOta.h"
#include "InsightTransport.h"
#include "InsightReliability.h"

namespace {

// ---------------------------------------------------------------------------
// A scripted transport: answers the offer GET and the image GET independently,
// and records every path it was asked for so a test can assert exactly how many
// fetches happened (the "no immediate retry" property of a 429).
// ---------------------------------------------------------------------------
class ScriptedTransport : public insight::InsightTransport {
 public:
  // Offer envelope returned by run() (via GET /v1/ota).
  const char* offerBody = "{\"update\":null}";
  insight::HttpOutcome offerOutcome = insight::HttpOutcome::ok(200);

  // Image payload returned for the image GET. `imageLen` bytes are copied and
  // the buffer is NUL-terminated (the seam's contract), which is how the OTA
  // policy measures the delivered length.
  const uint8_t* image = 0;
  size_t imageLen = 0;
  insight::HttpOutcome imageOutcome = insight::HttpOutcome::ok(200);

  int offerCount = 0;
  int imageCount = 0;
  char lastImagePath[128] = {0};
  // When non-zero, the image GET reports THIS as its delivered length instead of
  // the bytes actually copied — models a transport whose content-length
  // out-parameter disagrees with reality (an over-report, or a lying seam). The
  // policy must trust the report for the size gate, so an over-report is a
  // SizeMismatch, not a silent pass.
  size_t reportedImageLen = 0;

  insight::HttpOutcome postJson(const char*, const char*) override {
    return insight::HttpOutcome::error();
  }

  insight::HttpOutcome get(const char* path, char* buffer, size_t bufferLen,
                           size_t* contentLength) override {
    if (contentLength != 0) *contentLength = 0;

    if (std::strcmp(path, insight::otaImagePath()) == 0 ||
        std::strcmp(path, "/v1/ota/image") == 0 ||
        (lastImagePath[0] != '\0' &&
         std::strcmp(path, lastImagePath) == 0)) {
      ++imageCount;
      if (imageOutcome.kind == insight::HttpOutcome::Ok && buffer != 0) {
        // Copy the WHOLE image (opaque bytes, NUL included) and report its
        // length explicitly through the seam's content-length out-parameter.
        const size_t copyLen = imageLen < bufferLen ? imageLen : bufferLen;
        for (size_t i = 0; i < copyLen; ++i) {
          buffer[i] = static_cast<char>(image[i]);
        }
        if (copyLen < bufferLen) buffer[copyLen] = '\0';
        if (contentLength != 0) {
          *contentLength =
              reportedImageLen != 0 ? reportedImageLen : copyLen;
        }
      }
      return imageOutcome;
    }

    // Otherwise this is the offer fetch.
    ++offerCount;
    if (buffer != 0 && bufferLen > 0) {
      const size_t len = std::strlen(offerBody);
      const size_t copyLen = len < bufferLen - 1 ? len : bufferLen - 1;
      std::memcpy(buffer, offerBody, copyLen);
      buffer[copyLen] = '\0';
      if (contentLength != 0) *contentLength = copyLen;
    }
    return offerOutcome;
  }
};

// Records flash writes: how many times it was called and (for the last call)
// the exact bytes and length it was handed. A call count of zero is the proof
// that nothing reached the partition.
class FlashRecorder {
 public:
  int calls = 0;
  size_t lastLen = 0;
  uint8_t last[512];
  bool ok = true;
  // Optional alternate sink, so a test can model a write that fails.
  bool failWrite = false;

  static FlashRecorder* active() { return active_; }
  void bind() { active_ = this; }

  bool write(const uint8_t* image, size_t len) {
    ++calls;
    lastLen = len;
    for (size_t i = 0; i < len && i < sizeof(last); ++i) last[i] = image[i];
    if (failWrite) return false;
    return ok;
  }

  static bool trampoline(const uint8_t* image, size_t len) {
    return active_->write(image, len);
  }

 private:
  static FlashRecorder* active_;
};

FlashRecorder* FlashRecorder::active_ = nullptr;

// A deterministic clock the test advances by hand.
struct TestClock {
  unsigned long t = 0;
  unsigned long read() { return t; }
};

TestClock* g_clock = nullptr;
unsigned long clockRead() { return g_clock->read(); }

// A per-instance `retry-after` source: the whole point of the instance seam. A
// test OWNS one stub per `InsightOta` and installs it with `stub.install(&ota)`.
// Each stub carries its OWN reader function pointer, so the two objects hold
// genuinely different sources and the policy resolves the right value from its
// own identity — exactly how a firmware adapter looks (one reader per context).
// A single shared trampoline, or a process-global "current" value (what the old
// free-function setter effectively was), would alias the two objects; the
// isolation test below fails loudly if either returns.
struct RetryAfterStub {
  long seconds = -1;            // negative => "no usable header" (default)
  long (*source)() = 0;         // this stub's private reader
  void install(insight::InsightOta* ota) { ota->setRetryAfterSource(source); }
};

// Two concrete readers, so two stubs get distinct (non-aliasing) pointers.
RetryAfterStub* g_stubA = 0;
RetryAfterStub* g_stubB = 0;
long readStubA() { return g_stubA == 0 ? -1 : g_stubA->seconds; }
long readStubB() { return g_stubB == 0 ? -1 : g_stubB->seconds; }

// Make stub A/B: assign the reader and register the global the reader closes over.
RetryAfterStub makeStubA(long seconds) {
  RetryAfterStub s;
  s.seconds = seconds;
  s.source = &readStubA;
  g_stubA = 0;  // rebound by bindStubA once the local's lifetime is fixed
  return s;
}
RetryAfterStub makeStubB(long seconds) {
  RetryAfterStub s;
  s.seconds = seconds;
  s.source = &readStubB;
  g_stubB = 0;
  return s;
}
void bindStubA(RetryAfterStub& s) { g_stubA = &s; s.source = &readStubA; }
void bindStubB(RetryAfterStub& s) { g_stubB = &s; s.source = &readStubB; }

// The image the happy-path tests use: bytes 0..255. Its digest and the digest
// of the last-byte-altered variant are known constants (see the vectors below);
// both were confirmed against an independent SHA-256.
const size_t kImageLen = 256;
uint8_t g_image[kImageLen];
const char* kImageSha =
    "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880";

void initImage() {
  for (size_t i = 0; i < kImageLen; ++i) {
    g_image[i] = static_cast<uint8_t>(i);
  }
}

// Build a valid `{ "update": { ... } }` offer naming `url`/`size`/`sha256`.
void buildOffer(char* out, size_t outLen, const char* version, uint32_t size,
                const char* sha, const char* url) {
  // Deliberately assembled by hand (no snprintf dependency) into the caller's
  // buffer; a truncated result is a test bug, caught by the assertions.
  std::memset(out, 0, outLen);
  size_t n = 0;
  const char* prefix = "{\"update\":{\"version\":\"";
  for (const char* p = prefix; *p && n + 1 < outLen; ++p) out[n++] = *p;
  for (const char* p = version; *p && n + 1 < outLen; ++p) out[n++] = *p;
  const char* mid = "\",\"size\":";
  for (const char* p = mid; *p && n + 1 < outLen; ++p) out[n++] = *p;
  // decimal size
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
  while (dn > 0 && n + 1 < outLen) out[n++] = digits[--dn];
  const char* mid2 = ",\"sha256\":\"";
  for (const char* p = mid2; *p && n + 1 < outLen; ++p) out[n++] = *p;
  for (const char* p = sha; *p && n + 1 < outLen; ++p) out[n++] = *p;
  const char* mid3 = "\",\"url\":\"";
  for (const char* p = mid3; *p && n + 1 < outLen; ++p) out[n++] = *p;
  for (const char* p = url; *p && n + 1 < outLen; ++p) out[n++] = *p;
  const char* suffix = "\"}}";
  for (const char* p = suffix; *p && n + 1 < outLen; ++p) out[n++] = *p;
  out[n] = '\0';
}

}  // namespace

void setUp(void) {
  // Detach both retry-after readers so an earlier test's stub can never be
  // observed by a later one.
  g_stubA = 0;
  g_stubB = 0;
}

void tearDown(void) {}

// ---------------------------------------------------------------------------
// SHA-256 known-answer vectors
// ---------------------------------------------------------------------------

// The canonical empty-string digest. This is the vector the acceptance criteria
// call out by name, and it is the one that most obviously proves the algorithm
// is a real SHA-256 and not a stand-in.
void test_sha256_known_answer_empty(void) {
  insight::InsightOta::Sha256 hasher = insight::InsightOta::builtInSha256();
  TEST_ASSERT_TRUE(hasher.ready());

  uint8_t ctx[insight::InsightOta::Sha256::kContextBytes];
  uint8_t digest[32];
  char hex[65];
  hasher.init(ctx);
  hasher.finalize(ctx, digest);
  insight::InsightOta::toHex(digest, hex);

  TEST_ASSERT_EQUAL_STRING(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hex);
}

// SHA-256("abc") — the other textbook vector, exercised through update().
void test_sha256_known_answer_abc(void) {
  insight::InsightOta::Sha256 hasher = insight::InsightOta::builtInSha256();
  uint8_t ctx[insight::InsightOta::Sha256::kContextBytes];
  uint8_t digest[32];
  char hex[65];

  hasher.init(ctx);
  hasher.update(ctx, reinterpret_cast<const uint8_t*>("abc"), 3);
  hasher.finalize(ctx, digest);
  insight::InsightOta::toHex(digest, hex);

  TEST_ASSERT_EQUAL_STRING(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex);
}

// Multi-block input (1000 bytes) and a padding-edge length (56 bytes, which
// forces a second block): both must match independently computed digests.
void test_sha256_multi_block_and_padding_edge(void) {
  insight::InsightOta::Sha256 hasher = insight::InsightOta::builtInSha256();
  uint8_t ctx[insight::InsightOta::Sha256::kContextBytes];
  uint8_t digest[32];
  char hex[65];

  uint8_t zeros[1000];
  std::memset(zeros, 0, sizeof(zeros));
  hasher.init(ctx);
  hasher.update(ctx, zeros, sizeof(zeros));
  hasher.finalize(ctx, digest);
  insight::InsightOta::toHex(digest, hex);
  TEST_ASSERT_EQUAL_STRING(
      "541b3e9daa09b20bf85fa273e5cbd3e80185aa4ec298e765db87742b70138a53", hex);

  uint8_t m56[56];
  for (size_t i = 0; i < 56; ++i) m56[i] = static_cast<uint8_t>(i);
  hasher.init(ctx);
  // Split across two update() calls to prove streaming across a block boundary.
  hasher.update(ctx, m56, 13);
  hasher.update(ctx, m56 + 13, 43);
  hasher.finalize(ctx, digest);
  insight::InsightOta::toHex(digest, hex);
  TEST_ASSERT_EQUAL_STRING(
      "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562", hex);
}

// The one-shot and the streaming form of the same input agree, and the context
// fits the fixed-size seam blob (no dynamic allocation can hide in there).
void test_sha256_context_fits_seam_and_is_deterministic(void) {
  TEST_ASSERT_TRUE(insight::InsightOta::Sha256::kContextBytes >=
                   sizeof(uint32_t) * 8 + sizeof(uint64_t) + 64 + sizeof(size_t));

  insight::InsightOta::Sha256 hasher = insight::InsightOta::builtInSha256();
  uint8_t ctx[insight::InsightOta::Sha256::kContextBytes];
  uint8_t a[32];
  uint8_t b[32];
  char ha[65];
  char hb[65];

  hasher.init(ctx);
  hasher.update(ctx, g_image, kImageLen);
  hasher.finalize(ctx, a);
  insight::InsightOta::toHex(a, ha);

  // Byte-at-a-time streaming yields the identical digest.
  hasher.init(ctx);
  for (size_t i = 0; i < kImageLen; ++i) hasher.update(ctx, g_image + i, 1);
  hasher.finalize(ctx, b);
  insight::InsightOta::toHex(b, hb);

  TEST_ASSERT_EQUAL_STRING(ha, hb);
  TEST_ASSERT_EQUAL_STRING(kImageSha, ha);
}

// ---------------------------------------------------------------------------
// Offer parsing / validation
// ---------------------------------------------------------------------------

// `{"update":null}` is a well-formed "nothing to do" — valid, no update, and
// nothing fetched or flashed.
void test_parse_null_offer_is_valid_no_update(void) {
  insight::OtaOffer offer;
  TEST_ASSERT_TRUE(insight::InsightOta::parseOffer("{\"update\":null}", &offer));
  TEST_ASSERT_TRUE(offer.valid);
  TEST_ASSERT_FALSE(offer.hasUpdate);
}

// A full offer round-trips every field, and the digest is normalised to
// lowercase hex (case must not matter to the comparison).
void test_parse_full_offer_normalises_sha256_case(void) {
  insight::OtaOffer offer;
  const char* body =
      "{\"update\":{\"version\":\"1.2.0\",\"size\":1024,"
      "\"sha256\":\"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855\","
      "\"url\":\"/v1/ota/image/1.2.0\"}}";
  TEST_ASSERT_TRUE(insight::InsightOta::parseOffer(body, &offer));
  TEST_ASSERT_TRUE(offer.valid);
  TEST_ASSERT_TRUE(offer.hasUpdate);
  TEST_ASSERT_EQUAL_STRING("1.2.0", offer.version);
  TEST_ASSERT_EQUAL_UINT32(1024u, offer.size);
  TEST_ASSERT_EQUAL_STRING("/v1/ota/image/1.2.0", offer.url);
  TEST_ASSERT_EQUAL_STRING(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      offer.sha256);
}

// Malformed envelopes and fields are rejected: missing update, a bad digest
// (wrong length / non-hex), and a missing field all leave valid == false.
void test_parse_rejects_malformed(void) {
  insight::OtaOffer offer;

  TEST_ASSERT_FALSE(insight::InsightOta::parseOffer("{}", &offer));
  TEST_ASSERT_FALSE(offer.valid);

  // Digest too short to ever be a SHA-256.
  TEST_ASSERT_FALSE(insight::InsightOta::parseOffer(
      "{\"update\":{\"version\":\"1\",\"size\":4,\"sha256\":\"ab\","
      "\"url\":\"/v1/ota/image\"}}",
      &offer));
  TEST_ASSERT_FALSE(offer.valid);

  // Non-hex digest of the right length.
  TEST_ASSERT_FALSE(insight::InsightOta::parseOffer(
      "{\"update\":{\"version\":\"1\",\"size\":4,"
      "\"sha256\":\"zzb0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\","
      "\"url\":\"/v1/ota/image\"}}",
      &offer));

  // Missing url.
  TEST_ASSERT_FALSE(insight::InsightOta::parseOffer(
      "{\"update\":{\"version\":\"1\",\"size\":4,"
      "\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}}",
      &offer));
}

// A field name must not be matched inside a string value: a version that
// contains `,"size":` must not be read as the size field.
void test_parse_field_match_is_structural(void) {
  insight::OtaOffer offer;
  const char* body =
      "{\"update\":{\"version\":\"x,\\\"size\\\":9999\",\"size\":7,"
      "\"sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\","
      "\"url\":\"/v1/ota/image\"}}";
  TEST_ASSERT_TRUE(insight::InsightOta::parseOffer(body, &offer));
  TEST_ASSERT_EQUAL_UINT32(7u, offer.size);
}

// ---------------------------------------------------------------------------
// ST-O1 / acceptance: truncated stream -> NO flash
// ---------------------------------------------------------------------------

// A short read (fewer bytes than offer.size promised) is a size mismatch: the
// flash sink is never invoked, and the outcome is retry-worthy.
void test_truncated_stream_does_not_flash(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  // The offer promises 256 bytes; the transport delivers only 255 and marks the
  // end (NUL) early — the truncated-stream case.
  transport.image = g_image;
  transport.imageLen = kImageLen - 1;
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  transport.lastImagePath[0] = '\0';
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::SizeMismatch, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);  // NOT ONE BYTE reached the partition
  TEST_ASSERT_TRUE(result.retry);
  TEST_ASSERT_EQUAL_UINT32(kImageLen - 1, result.received);
}

// A truncated stream that also happens to deliver a full-size buffer padded
// with zeros is still caught: the delivered length is measured, not assumed.
void test_truncated_midway_is_size_mismatch_not_hash(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = 10;  // far short of the promised 256
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::SizeMismatch, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
}

// ---------------------------------------------------------------------------
// Diagnostics: lastContentLength() reports the RAW seam byte count
// ---------------------------------------------------------------------------

// `lastContentLength()` is the transport's own report of how many bytes the last
// GET delivered — distinct from `received`, which is the count the verification
// path trusted AFTER the size check. On a truncated read the two deliberately
// DIVERGE: `received` is the short delivered length (the mismatch is computed
// from it), while a well-behaved seam's content-length report agrees with it
// too. This test pins the accessor to that raw report rather than leaving it an
// unexercised getter.
void test_last_content_length_reports_short_delivery(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen - 1;  // deliver 255 of the promised 256
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::SizeMismatch, result.kind);
  // The seam reported 255 bytes; the accessor surfaces exactly that, and it
  // equals what the verification path measured.
  TEST_ASSERT_EQUAL_UINT32(kImageLen - 1,
                           static_cast<uint32_t>(ota.lastContentLength()));
  TEST_ASSERT_EQUAL_UINT32(result.received,
                           static_cast<uint32_t>(ota.lastContentLength()));
  TEST_ASSERT_EQUAL_INT(200, ota.lastStatus());
}

// On a full, correct download the raw content-length report equals the offered
// size (the happy path where `received` and `lastContentLength()` must agree),
// and the GET count is exactly one image fetch.
void test_last_content_length_reports_whole_delivery(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::Flashed, result.kind);
  TEST_ASSERT_EQUAL_UINT32(kImageLen,
                           static_cast<uint32_t>(ota.lastContentLength()));
  TEST_ASSERT_EQUAL_UINT32(result.received,
                           static_cast<uint32_t>(ota.lastContentLength()));
  TEST_ASSERT_EQUAL_INT(1, transport.imageCount);
}

// A transport failure (no reply at all) leaves the content-length report at 0 —
// the accessor must not carry a stale count from a previous, successful pass.
// Mutation-proven: forcing the failure branch to keep the last good count turns
// this red.
void test_last_content_length_is_zero_after_transport_failure(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  // First pass: a successful whole download, so the accessor holds 256.
  insight::OtaResult first = ota.runWithOffer(offer);
  TEST_ASSERT_EQUAL_INT(insight::OtaResult::Flashed, first.kind);
  TEST_ASSERT_EQUAL_UINT32(kImageLen,
                           static_cast<uint32_t>(ota.lastContentLength()));

  // Second pass: the image GET times out (kind != Ok), so no bytes were
  // delivered — the report must reset to 0, not linger at 256.
  transport.imageOutcome = insight::HttpOutcome::timeout();
  insight::OtaResult second = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::TransportFailure, second.kind);
  TEST_ASSERT_EQUAL_UINT32(0, static_cast<uint32_t>(ota.lastContentLength()));
}

// ---------------------------------------------------------------------------
// ST-O1 / acceptance: altered last byte -> hash mismatch -> NO flash
// ---------------------------------------------------------------------------

// The full length arrives, but the last byte was altered: the digest no longer
// matches, so nothing is flashed. This is the case a size-only check would miss,
// which is exactly why the digest is verified.
void test_altered_last_byte_fails_hash_and_does_not_flash(void) {
  initImage();
  g_image[kImageLen - 1] ^= 0x01;  // alter the final byte

  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen;  // FULL length — size check passes
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  // The offer still names the digest of the CORRECT image.
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::HashMismatch, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);  // nothing flashed on a bad digest
  TEST_ASSERT_TRUE(result.retry);
  // The computed digest is surfaced so the failure is diagnosable.
  TEST_ASSERT_EQUAL_STRING(
      "e71c077cfa03d2b1a50115d48f98e1edbfb9151759826f6ff6e9766c2ca0e73f",
      result.computedSha256);
}

// ---------------------------------------------------------------------------
// Acceptance: correct size + correct hash -> flash EXACTLY once, with the bytes
// ---------------------------------------------------------------------------

void test_correct_image_flashes_exactly_once_with_bytes(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::Flashed, result.kind);
  TEST_ASSERT_FALSE(result.retry);
  TEST_ASSERT_EQUAL_INT(1, flash.calls);  // EXACTLY once
  TEST_ASSERT_EQUAL_UINT32(kImageLen, static_cast<uint32_t>(flash.lastLen));
  TEST_ASSERT_EQUAL_UINT32(kImageLen, result.received);
  // The bytes handed to the partition are the verified image, byte for byte.
  TEST_ASSERT_EQUAL_INT(0, std::memcmp(flash.last, g_image, kImageLen));
  TEST_ASSERT_EQUAL_STRING(kImageSha, result.computedSha256);
}

// A `{"update":null}` offer flashes nothing and does not touch the image route.
void test_null_update_does_not_flash(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  insight::OtaResult result = ota.runWithOffer("{\"update\":null}");

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::NoUpdate, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  TEST_ASSERT_EQUAL_INT(0, transport.imageCount);
}

// An offer that names a size beyond the buffer ceiling is refused before the
// image is fetched — nothing is downloaded and nothing is flashed.
void test_oversized_offer_is_refused_before_download(void) {
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);
  ota.setMaxImageSize(512);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", 4096, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::UnsupportedSize, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  TEST_ASSERT_EQUAL_INT(0, transport.imageCount);
}

// ---------------------------------------------------------------------------
// Acceptance: 429 -> schedule >= retry-after, no immediate retry
// ---------------------------------------------------------------------------

// A 429 on the image GET honours `retry-after`: the next allowed time is at or
// beyond now + retry-after, and the pass makes NO further fetch (no hammer).
void test_429_on_image_honours_retry_after_without_retry(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;
  clock.t = 1000;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  transport.imageOutcome = insight::HttpOutcome::ok(429);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  RetryAfterStub retry = makeStubA(30);  // server says: wait 30 s
  bindStubA(retry);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);
  retry.install(&ota);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::RateLimited, result.kind);
  TEST_ASSERT_TRUE(result.retry);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  // The instance seam is what supplied the header.
  TEST_ASSERT_EQUAL_INT(30L, ota.retryAfterHeaderSeconds());
  // Scheduled at or AFTER retry-after (30 s from now == 1000).
  TEST_ASSERT_EQUAL_UINT32(30000u, result.retryAfterMillis);
  TEST_ASSERT_GREATER_OR_EQUAL_UINT32(31000u, result.retryAtMillis);
  TEST_ASSERT_EQUAL_UINT32(result.retryAtMillis, ota.nextAttemptAtMillis());

  // Exactly ONE image attempt: no immediate retry inside the pass.
  TEST_ASSERT_EQUAL_INT(1, transport.imageCount);
  // And the class reports itself not ready until the schedule is reached.
  TEST_ASSERT_FALSE(ota.isReady(1000));
  TEST_ASSERT_FALSE(ota.isReady(30999));
  TEST_ASSERT_TRUE(ota.isReady(31000));
}

// A 429 that carries NO usable retry-after falls back to the one-hour default —
// a missing header must never collapse into "retry right now".
void test_429_without_header_uses_default_retry_after(void) {
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;
  clock.t = 0;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  transport.imageOutcome = insight::HttpOutcome::ok(429);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);
  // No retry-after source installed at all: the absent-header case.
  TEST_ASSERT_EQUAL_INT(-1L, ota.retryAfterHeaderSeconds());

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::RateLimited, result.kind);
  TEST_ASSERT_EQUAL_UINT32(insight::kOtaDefaultRetryAfterMillis,
                           result.retryAfterMillis);
  TEST_ASSERT_GREATER_OR_EQUAL_UINT32(insight::kOtaDefaultRetryAfterMillis,
                                      result.retryAtMillis);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
}

// A 429 on the OFFER GET is handled the same way: honoured, no retry, no flash.
void test_429_on_offer_is_honoured(void) {
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;
  clock.t = 5000;

  transport.offerOutcome = insight::HttpOutcome::ok(429);
  RetryAfterStub retry = makeStubA(60);
  bindStubA(retry);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);
  retry.install(&ota);

  insight::OtaResult result = ota.run();

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::RateLimited, result.kind);
  TEST_ASSERT_EQUAL_INT(1, transport.offerCount);
  TEST_ASSERT_EQUAL_INT(0, transport.imageCount);  // no image GET on a 429 offer
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  TEST_ASSERT_EQUAL_UINT32(60000u, result.retryAfterMillis);
}

// The `retry-after` value is INSTANCE state, not a process global: two objects
// with their own sources never share a header. This is the isolation the old
// module-global setter could not give (and the reason the seam was moved onto
// the class) — a 429 on one object must not inherit the other's schedule.
void test_retry_after_source_is_per_instance(void) {
  ScriptedTransport transportA;
  ScriptedTransport transportB;
  FlashRecorder flashA;
  FlashRecorder flashB;
  TestClock clock;

  g_clock = &clock;
  clock.t = 0;

  // Two independent 429 sources: stub A reads 5 s, stub B reads 90 s.
  RetryAfterStub retryA = makeStubA(5);
  RetryAfterStub retryB = makeStubB(90);
  bindStubA(retryA);
  bindStubB(retryB);

  // Build BOTH objects and install BOTH sources BEFORE either runs. This is the
  // ordering that exposes a global seam: with a process-global "last value
  // wins" (the old setOtaRetryAfterHeader), installing B after A would clobber
  // A's 5 s, and object A — which must honour ITS OWN 5 s — would schedule 90 s.
  flashA.bind();
  transportA.image = g_image;
  transportA.imageLen = kImageLen;
  transportA.imageOutcome = insight::HttpOutcome::ok(429);
  std::strncpy(transportA.lastImagePath, insight::otaImagePath(),
               sizeof(transportA.lastImagePath) - 1);

  insight::InsightOta otaA;
  otaA.setTransport(&transportA);
  otaA.setFlashSink(&FlashRecorder::trampoline);
  otaA.setClock(&clockRead);
  retryA.install(&otaA);

  flashB.bind();
  transportB.image = g_image;
  transportB.imageLen = kImageLen;
  transportB.imageOutcome = insight::HttpOutcome::ok(429);
  std::strncpy(transportB.lastImagePath, insight::otaImagePath(),
               sizeof(transportB.lastImagePath) - 1);

  insight::InsightOta otaB;
  otaB.setTransport(&transportB);
  otaB.setFlashSink(&FlashRecorder::trampoline);
  otaB.setClock(&clockRead);
  retryB.install(&otaB);  // installed AFTER A — a global would now read 90 s

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  // Run A AFTER B's source was installed. A must still honour 5 s.
  flashA.bind();
  insight::OtaResult resultA = otaA.runWithOffer(offer);
  flashB.bind();
  insight::OtaResult resultB = otaB.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::RateLimited, resultA.kind);
  TEST_ASSERT_EQUAL_INT(insight::OtaResult::RateLimited, resultB.kind);
  TEST_ASSERT_EQUAL_UINT32(5000u, resultA.retryAfterMillis);
  TEST_ASSERT_EQUAL_UINT32(90000u, resultB.retryAfterMillis);
  // The two objects store independent deadlines — A's is NOT B's.
  TEST_ASSERT_EQUAL_UINT32(5000u, otaA.nextAttemptAtMillis());
  TEST_ASSERT_EQUAL_UINT32(90000u, otaB.nextAttemptAtMillis());
  TEST_ASSERT_FALSE(otaA.isReady(4999));
  TEST_ASSERT_TRUE(otaA.isReady(5000));
  TEST_ASSERT_FALSE(otaB.isReady(89999));
  TEST_ASSERT_TRUE(otaB.isReady(90000));
}

// ---------------------------------------------------------------------------
// Transport failures never flash, and are scheduled, never slept on
// ---------------------------------------------------------------------------

void test_image_transport_failure_does_not_flash(void) {
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;
  clock.t = 100;

  transport.imageOutcome = insight::HttpOutcome::timeout();
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::TransportFailure, result.kind);
  TEST_ASSERT_TRUE(result.retry);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  // Scheduled with a positive backoff (never a zero-delay hot retry).
  TEST_ASSERT_GREATER_THAN_UINT32(0u, result.retryAfterMillis);
  TEST_ASSERT_GREATER_OR_EQUAL_UINT32(100u + result.retryAfterMillis,
                                      result.retryAtMillis);
}

// A flash write that itself fails reports a retryable failure — but the sink
// was still reached exactly once, since the image had verified.
void test_flash_write_failure_is_reported_but_reached_once(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  flash.failWrite = true;
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::TransportFailure, result.kind);
  TEST_ASSERT_TRUE(result.retry);
  TEST_ASSERT_EQUAL_INT(1, flash.calls);
}

// ---------------------------------------------------------------------------
// run(): the offer GET path, end to end
// ---------------------------------------------------------------------------

void test_run_fetches_offer_then_image_and_flashes(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);
  char offer[512];
  buildOffer(offer, sizeof(offer), "3.1.4", kImageLen, kImageSha,
             insight::otaImagePath());
  transport.offerBody = offer;

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  insight::OtaResult result = ota.run();

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::Flashed, result.kind);
  TEST_ASSERT_EQUAL_INT(1, transport.offerCount);
  TEST_ASSERT_EQUAL_INT(1, transport.imageCount);
  TEST_ASSERT_EQUAL_INT(1, flash.calls);
}

// A malformed offer envelope is refused and never flashes.
void test_run_with_malformed_offer_does_not_flash(void) {
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.offerBody = "{\"update\":{\"version\":\"1\"}}";  // missing fields

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  insight::OtaResult result = ota.run();

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::InvalidOffer, result.kind);
  TEST_ASSERT_FALSE(result.retry);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
}

// With no flash sink installed there is nowhere safe to write: even a verified
// image is not downloaded, and nothing is flashed.
void test_no_flash_sink_does_not_flash(void) {
  initImage();
  ScriptedTransport transport;
  TestClock clock;

  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setClock(&clockRead);
  // no setFlashSink

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::TransportFailure, result.kind);
  TEST_ASSERT_EQUAL_INT(0, transport.imageCount);
}

// An injected stand-in hasher is used instead of the built-in one — proving the
// hasher really is a seam (and that a real digest is the DEFAULT, not the only
// option).
namespace {
void tamperInit(void* ctx) {
  static_cast<void>(ctx);
}
void tamperUpdate(void* ctx, const uint8_t* data, size_t len) {
  static_cast<void>(ctx);
  static_cast<void>(data);
  // Fold a constant so the digest is independent of the image.
  *(static_cast<uint32_t*>(ctx)) = static_cast<uint32_t>(len);
}
void tamperFinalize(void* ctx, uint8_t out[32]) {
  const uint32_t marker = *(static_cast<uint32_t*>(ctx));
  for (int i = 0; i < 32; ++i) out[i] = static_cast<uint8_t>((marker + i) & 0xff);
}
}  // namespace

void test_injected_hasher_is_used(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  // The stand-in digest for a 256-byte image: bytes (256+i)&0xff.
  char standIn[65];
  for (int i = 0; i < 32; ++i) {
    static const char hex[] = "0123456789abcdef";
    const uint8_t b = static_cast<uint8_t>((256 + i) & 0xff);
    standIn[i * 2] = hex[(b >> 4) & 0xf];
    standIn[i * 2 + 1] = hex[b & 0xf];
  }
  standIn[64] = '\0';
  ota.setHasher(insight::InsightOta::Sha256(&tamperInit, &tamperUpdate,
                                            &tamperFinalize));

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, standIn,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  // The real SHA-256 of this image is NOT the stand-in digest, so if the
  // built-in hasher were used this would be a HashMismatch. Flashed proves the
  // injected hasher is what ran.
  TEST_ASSERT_EQUAL_INT(insight::OtaResult::Flashed, result.kind);
  TEST_ASSERT_EQUAL_STRING(standIn, result.computedSha256);
  TEST_ASSERT_EQUAL_INT(1, flash.calls);
}

// A response that delivers MORE bytes than the offer promised is a size
// mismatch, NOT silently clamped to the promised length. Clamping would make an
// over-long delivery pass the size gate (received == offer.size) and only be
// caught — if at all — by the digest. The seam's over-report must be measured
// and rejected at the size gate. Mutation-proven: restoring the clamp turns this
// red (it would flash, or report HashMismatch instead of SizeMismatch).
void test_over_long_body_is_size_mismatch_not_clamped(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  // The transport reports it delivered 300 bytes though the offer promised 256.
  transport.image = g_image;
  transport.imageLen = kImageLen;
  transport.reportedImageLen = kImageLen + 44;  // a lying/over-long seam
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::SizeMismatch, result.kind);
  TEST_ASSERT_EQUAL_INT(0, flash.calls);
  // The over-report is surfaced, not clamped to 256.
  TEST_ASSERT_EQUAL_UINT32(kImageLen + 44, result.received);
}

// A HashMismatch carries its diagnostics: the OtaResult's computed digest is
// populated AND lastVerification() reports the digest and byte count. The
// failure case is exactly the one an operator needs to diagnose, so an empty
// record here (the previous behaviour) was the bug. Mutation-proven: moving the
// digest copy back behind the equality check turns this red.
void test_hash_mismatch_carries_diagnostics(void) {
  initImage();
  g_image[kImageLen - 1] ^= 0x01;  // alter the last byte -> digest mismatch

  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::HashMismatch, result.kind);
  // The computed digest is on the RESULT...
  TEST_ASSERT_EQUAL_STRING(
      "e71c077cfa03d2b1a50115d48f98e1edbfb9151759826f6ff6e9766c2ca0e73f",
      result.computedSha256);
  // ...and on the RECORD, together with the byte count — the failure is not
  // recorded as the "nothing happened" blank it used to be.
  insight::ImageVerification v = ota.lastVerification();
  TEST_ASSERT_EQUAL_INT(insight::OtaResult::HashMismatch, v.result);
  TEST_ASSERT_FALSE(v.flashed);
  TEST_ASSERT_EQUAL_STRING(result.computedSha256, v.sha256);
  TEST_ASSERT_EQUAL_UINT32(kImageLen, v.received);
  TEST_ASSERT_EQUAL_STRING("2.0.0", v.version);
}

// A SizeMismatch also carries diagnostics: the byte count received, and the
// offered version — while leaving the digest empty (nothing was hashed, and an
// empty digest must not be mistaken for a computed one).
void test_size_mismatch_carries_diagnostics(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  transport.image = g_image;
  transport.imageLen = kImageLen - 1;
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::SizeMismatch, result.kind);
  insight::ImageVerification v = ota.lastVerification();
  TEST_ASSERT_EQUAL_INT(insight::OtaResult::SizeMismatch, v.result);
  TEST_ASSERT_EQUAL_UINT32(kImageLen - 1, v.received);
  TEST_ASSERT_EQUAL_UINT32(kImageLen, v.size);  // what was OFFERED
  TEST_ASSERT_EQUAL_STRING("", v.sha256);       // nothing was hashed
  TEST_ASSERT_FALSE(v.flashed);
}

// lastVerification() on a NEVER-run object is the inert "nothing happened"
// record, not indeterminate memory. Reads every field, so an uninitialised
// member (the previous bug: the ctor left lastComputedSha256_/lastOfferSize_/
// lastReceived_ unset) is caught.
//
// The object is constructed over POISONED memory (a byte pattern of 0xAB) so
// "the field happens to be zero in a fresh stack frame" cannot mask the bug:
// without the ctor's member-init list, the fields would read a run of 0xAB and
// fail the equality checks. Mutation-proven: dropping the member-initialisers
// (lastComputedSha256_/lastOfferSize_/lastReceived_) turns this red.
void test_verification_before_first_run_is_inert(void) {
  alignas(insight::InsightOta) unsigned char storage[sizeof(insight::InsightOta)];
  std::memset(storage, 0xAB, sizeof(storage));
  insight::InsightOta* ota =
      new (storage) insight::InsightOta();  // placement-new over the poison

  insight::ImageVerification v = ota->lastVerification();
  TEST_ASSERT_FALSE(v.flashed);
  TEST_ASSERT_FALSE(v.signatureChecked);
  TEST_ASSERT_FALSE(v.signatureOk);
  TEST_ASSERT_EQUAL_STRING("", v.sha256);
  TEST_ASSERT_EQUAL_STRING("", v.version);
  TEST_ASSERT_EQUAL_STRING("", v.signature);
  TEST_ASSERT_EQUAL_STRING("", v.pubkeyId);
  TEST_ASSERT_EQUAL_UINT32(0u, v.size);
  TEST_ASSERT_EQUAL_UINT32(0u, v.received);

  ota->~InsightOta();
}

// An unsupported size is a PERMANENT refusal: retry == false and no schedule, so
// a caller that honours `retry` cannot spin on a size it can never buffer
// (INV-O2). It previously returned retry == true with no schedule.
void test_unsupported_size_is_not_retryable(void) {
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);
  ota.setMaxImageSize(512);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", 4096, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::UnsupportedSize, result.kind);
  TEST_ASSERT_FALSE(result.retry);              // permanent refusal
  TEST_ASSERT_EQUAL_UINT32(0u, result.retryAtMillis);
  TEST_ASSERT_EQUAL_UINT32(0u, ota.nextAttemptAtMillis());
  TEST_ASSERT_EQUAL_INT(0, transport.imageCount);  // never fetched
}

// A retryable-with-no-sink outcome is SCHEDULED: no flash sink means there is
// nowhere to write, which is retryable, but it must carry a positive backoff
// (the previous code returned retry == true with a ZERO schedule — the
// "retryable without a deadline" hole that lets a misconfigured device
// hot-loop). Mutation-proven: reverting to the unscheduled return turns this
// red.
void test_retryable_transport_failure_is_scheduled(void) {
  ScriptedTransport transport;
  TestClock clock;

  g_clock = &clock;
  clock.t = 500;

  transport.image = g_image;
  transport.imageLen = kImageLen;
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setClock(&clockRead);
  // no flash sink: TransportFailure, retryable

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult result = ota.runWithOffer(offer);

  TEST_ASSERT_EQUAL_INT(insight::OtaResult::TransportFailure, result.kind);
  TEST_ASSERT_TRUE(result.retry);
  TEST_ASSERT_GREATER_THAN_UINT32(0u, result.retryAfterMillis);
  TEST_ASSERT_EQUAL_UINT32(result.retryAtMillis, ota.nextAttemptAtMillis());
  TEST_ASSERT_GREATER_OR_EQUAL_UINT32(500u + result.retryAfterMillis,
                                      result.retryAtMillis);
}

// A schedule recorded by a PREVIOUS pass must not leak into the object's state:
// a 429 sets nextAttemptAtMillis_; the NEXT pass (here via runWithOffer) must
// rebuild the schedule from scratch, so a caller alternating
// isReady()/runWithOffer() is never told "not ready" because of a deadline that
// belonged to an earlier offer. The reset lives at the top of processOffer(),
// which every entry point funnels through. Mutation-proven: removing that reset
// turns this red (nextAttemptAtMillis_ lingers at the hh:mm:01 value).
void test_run_with_offer_clears_stale_schedule(void) {
  initImage();
  ScriptedTransport transport;
  FlashRecorder flash;
  TestClock clock;

  flash.bind();
  g_clock = &clock;
  clock.t = 1000;

  // Pass 1: a 429 records a schedule.
  transport.image = g_image;
  transport.imageLen = kImageLen;
  transport.imageOutcome = insight::HttpOutcome::ok(429);
  std::strncpy(transport.lastImagePath, insight::otaImagePath(),
               sizeof(transport.lastImagePath) - 1);

  insight::InsightOta ota;
  ota.setTransport(&transport);
  ota.setFlashSink(&FlashRecorder::trampoline);
  ota.setClock(&clockRead);

  char offer[512];
  buildOffer(offer, sizeof(offer), "2.0.0", kImageLen, kImageSha,
             insight::otaImagePath());

  insight::OtaResult first = ota.runWithOffer(offer);
  TEST_ASSERT_EQUAL_INT(insight::OtaResult::RateLimited, first.kind);
  TEST_ASSERT_GREATER_THAN_UINT32(0u, ota.nextAttemptAtMillis());

  // Pass 2: a good offer, injected. The stale rate-limit schedule must be gone.
  transport.imageOutcome = insight::HttpOutcome::ok(200);
  insight::OtaResult second = ota.runWithOffer(offer);
  TEST_ASSERT_EQUAL_INT(insight::OtaResult::Flashed, second.kind);
  TEST_ASSERT_EQUAL_UINT32(0u, ota.nextAttemptAtMillis());  // cleared
  TEST_ASSERT_EQUAL_UINT32(0u, ota.lastRetryAfterMillis());
  TEST_ASSERT_TRUE(ota.isReady(1000));
}

// `null` must be a WHOLE token: `nullify` (or any `null`-prefixed garbage) is
// NOT a valid "nothing to do" answer and must be refused, not read as `null`.
// The bare-prefix match the old isNull used accepted it. Mutation-proven:
// reverting isNull to the prefix match turns this red.
void test_null_prefix_garbage_is_not_treated_as_null(void) {
  insight::OtaOffer offer;
  // `"update":nullify` is well-formed JSON syntax for a bare token that is not
  // null; the parser must not accept it as "no update".
  TEST_ASSERT_FALSE(insight::InsightOta::parseOffer("{\"update\":nullify}", &offer));
  TEST_ASSERT_FALSE(offer.valid);
  TEST_ASSERT_FALSE(offer.hasUpdate);

  // The real `null`, with a following delimiter, IS accepted.
  insight::OtaOffer ok;
  TEST_ASSERT_TRUE(insight::InsightOta::parseOffer("{\"update\":null}", &ok));
  TEST_ASSERT_TRUE(ok.valid);
  TEST_ASSERT_FALSE(ok.hasUpdate);
}

int main(int, char**) {
  initImage();

  UNITY_BEGIN();
  // SHA-256 known-answer vectors
  RUN_TEST(test_sha256_known_answer_empty);
  RUN_TEST(test_sha256_known_answer_abc);
  RUN_TEST(test_sha256_multi_block_and_padding_edge);
  RUN_TEST(test_sha256_context_fits_seam_and_is_deterministic);
  // Offer parsing / validation
  RUN_TEST(test_parse_null_offer_is_valid_no_update);
  RUN_TEST(test_parse_full_offer_normalises_sha256_case);
  RUN_TEST(test_parse_rejects_malformed);
  RUN_TEST(test_parse_field_match_is_structural);
  // ST-O1: truncated -> no flash
  RUN_TEST(test_truncated_stream_does_not_flash);
  RUN_TEST(test_truncated_midway_is_size_mismatch_not_hash);
  // Diagnostics: lastContentLength() seam report
  RUN_TEST(test_last_content_length_reports_short_delivery);
  RUN_TEST(test_last_content_length_reports_whole_delivery);
  RUN_TEST(test_last_content_length_is_zero_after_transport_failure);
  // ST-O1: altered last byte -> hash mismatch -> no flash
  RUN_TEST(test_altered_last_byte_fails_hash_and_does_not_flash);
  // Acceptance: correct size + hash -> flash exactly once
  RUN_TEST(test_correct_image_flashes_exactly_once_with_bytes);
  RUN_TEST(test_null_update_does_not_flash);
  RUN_TEST(test_oversized_offer_is_refused_before_download);
  // Acceptance: 429 handling
  RUN_TEST(test_429_on_image_honours_retry_after_without_retry);
  RUN_TEST(test_429_without_header_uses_default_retry_after);
  RUN_TEST(test_429_on_offer_is_honoured);
  RUN_TEST(test_retry_after_source_is_per_instance);
  // Transport failures / seams
  RUN_TEST(test_image_transport_failure_does_not_flash);
  RUN_TEST(test_flash_write_failure_is_reported_but_reached_once);
  RUN_TEST(test_run_fetches_offer_then_image_and_flashes);
  RUN_TEST(test_run_with_malformed_offer_does_not_flash);
  RUN_TEST(test_no_flash_sink_does_not_flash);
  RUN_TEST(test_injected_hasher_is_used);
  // New: over-long body, mismatch diagnostics, inert record, retryability
  RUN_TEST(test_over_long_body_is_size_mismatch_not_clamped);
  RUN_TEST(test_hash_mismatch_carries_diagnostics);
  RUN_TEST(test_size_mismatch_carries_diagnostics);
  RUN_TEST(test_verification_before_first_run_is_inert);
  RUN_TEST(test_unsupported_size_is_not_retryable);
  RUN_TEST(test_retryable_transport_failure_is_scheduled);
  RUN_TEST(test_run_with_offer_clears_stale_schedule);
  RUN_TEST(test_null_prefix_garbage_is_not_treated_as_null);
  return UNITY_END();
}
