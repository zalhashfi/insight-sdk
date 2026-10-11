#include "InsightOta.h"

#include <cstring>

namespace insight {

// ===========================================================================
// Self-contained SHA-256 (FIPS 180-4)
// ===========================================================================
//
// A small, dependency-free SHA-256 so the default digest is a REAL one — the
// acceptance criteria explicitly prefer "a small self-contained SHA-256 so a
// real digest is tested", and a real digest is also the only thing that makes
// the hash-mismatch case mean anything. It is covered by known-answer vectors
// in test/test_ota_verify (SHA-256("") = e3b0c442..., SHA-256("abc") = ba7816bf...,
// plus multi-block and padding-edge vectors).
//
// The state is a plain POD so it can flow through the injected Sha256 seam as
// an opaque byte blob with no dynamic allocation and no global mutable state
// (run() may therefore be re-entered from any task without a lock).

namespace {

// Round constants: first 32 bits of the fractional parts of the cube roots of
// the first 64 primes (FIPS 180-4 §4.2.2).
const uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

inline uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32u - n));
}

// SHA-256 context. Fits inside InsightOta::Sha256::kContextBytes (128) with
// room to spare: 32 (state) + 8 (bit count) + 64 (partial block) + 4 (length)
// = 108 bytes. A static_assert in the tests pins the fit.
struct Sha256Ctx {
  uint32_t state[8];
  uint64_t bitlen;
  uint8_t block[64];
  size_t blockLen;
};

static const size_t kSha256CtxBytes = sizeof(Sha256Ctx);

void sha256Init(void* ctx) {
  Sha256Ctx* c = static_cast<Sha256Ctx*>(ctx);
  // Initial hash value: first 32 bits of the fractional parts of the square
  // roots of the first 8 primes (FIPS 180-4 §5.3.3).
  c->state[0] = 0x6a09e667u;
  c->state[1] = 0xbb67ae85u;
  c->state[2] = 0x3c6ef372u;
  c->state[3] = 0xa54ff53au;
  c->state[4] = 0x510e527fu;
  c->state[5] = 0x9b05688cu;
  c->state[6] = 0x1f83d9abu;
  c->state[7] = 0x5be0cd19u;
  c->bitlen = 0;
  c->blockLen = 0;
}

// Absorb exactly one 64-byte block, updating the eight working variables.
void sha256Compress(Sha256Ctx* c, const uint8_t* block) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
           (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
           (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
           (static_cast<uint32_t>(block[i * 4 + 3]));
  }
  for (int i = 16; i < 64; ++i) {
    const uint32_t s0 =
        rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const uint32_t s1 =
        rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
  uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];

  for (int i = 0; i < 64; ++i) {
    const uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    const uint32_t ch = (e & f) ^ ((~e) & g);
    const uint32_t t1 = h + s1 + ch + kSha256K[i] + w[i];
    const uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    const uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
    const uint32_t t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = cc;
    cc = b;
    b = a;
    a = t1 + t2;
  }

  c->state[0] += a;
  c->state[1] += b;
  c->state[2] += cc;
  c->state[3] += d;
  c->state[4] += e;
  c->state[5] += f;
  c->state[6] += g;
  c->state[7] += h;
}

void sha256Update(void* ctx, const uint8_t* data, size_t len) {
  Sha256Ctx* c = static_cast<Sha256Ctx*>(ctx);
  c->bitlen += static_cast<uint64_t>(len) * 8u;
  size_t i = 0;
  while (i < len) {
    const size_t room = 64 - c->blockLen;
    const size_t take = (len - i < room) ? (len - i) : room;
    std::memcpy(c->block + c->blockLen, data + i, take);
    c->blockLen += take;
    i += take;
    if (c->blockLen == 64) {
      sha256Compress(c, c->block);
      c->blockLen = 0;
    }
  }
}

void sha256Finalize(void* ctx, uint8_t out[32]) {
  Sha256Ctx* c = static_cast<Sha256Ctx*>(ctx);
  const uint64_t bitlen = c->bitlen;

  // Padding: a single 0x80 byte, then zeros, then the 64-bit big-endian length,
  // arranged so the length lands in the final 8 bytes of a 64-byte block.
  c->block[c->blockLen++] = 0x80u;
  if (c->blockLen > 56) {
    while (c->blockLen < 64) c->block[c->blockLen++] = 0x00u;
    sha256Compress(c, c->block);
    c->blockLen = 0;
  }
  while (c->blockLen < 56) c->block[c->blockLen++] = 0x00u;
  for (int i = 7; i >= 0; --i) {
    c->block[c->blockLen++] = static_cast<uint8_t>((bitlen >> (i * 8)) & 0xffu);
  }
  sha256Compress(c, c->block);

  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<uint8_t>(c->state[i] >> 24);
    out[i * 4 + 1] = static_cast<uint8_t>(c->state[i] >> 16);
    out[i * 4 + 2] = static_cast<uint8_t>(c->state[i] >> 8);
    out[i * 4 + 3] = static_cast<uint8_t>(c->state[i]);
  }
}

}  // namespace

InsightOta::Sha256 InsightOta::builtInSha256() {
  return Sha256(&sha256Init, &sha256Update, &sha256Finalize);
}

void InsightOta::toHex(const uint8_t digest[32], char out[65]) {
  static const char kHex[] = "0123456789abcdef";
  for (int i = 0; i < 32; ++i) {
    out[i * 2] = kHex[(digest[i] >> 4) & 0x0fu];
    out[i * 2 + 1] = kHex[digest[i] & 0x0fu];
  }
  out[64] = '\0';
}

// ===========================================================================
// Offer parsing
// ===========================================================================

namespace {

// Skip ASCII whitespace (JSON's insignificant whitespace set).
const char* skipWs(const char* p) {
  while (p != 0 && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
    ++p;
  }
  return p;
}

// Find `"name"` as a complete key at or after `from`; returns a pointer just
// past the closing quote of the key, or 0. A key must be preceded by `{` or a
// `,` (after optional whitespace) so a field name can never be matched inside
// a string VALUE — e.g. the `"size"` inside a version string must not be read
// as the size field. This is deliberately a structural-lite scan, not a full
// JSON parser (the SDK carries no JSON library, by design).
const char* findField(const char* from, const char* name) {
  if (from == 0 || name == 0) return 0;
  const size_t nameLen = std::strlen(name);
  const char* p = from;
  while (*p != '\0') {
    if (*p == '{' || *p == ',') {
      const char* q = skipWs(p + 1);
      if (*q == '"' && std::strncmp(q + 1, name, nameLen) == 0 &&
          q[1 + nameLen] == '"') {
        const char* after = q + 1 + nameLen + 1;
        after = skipWs(after);
        if (*after == ':') return skipWs(after + 1);
      }
    }
    ++p;
  }
  return 0;
}

// True when `p` begins the literal `null`.
bool isNull(const char* p) { return p != 0 && std::strncmp(p, "null", 4) == 0; }

// Parse a JSON string starting at the opening quote into `out` (capacity
// `outLen`, always NUL-terminated). Handles the `\"` and `\\` escapes; other
// escapes are copied as the following byte (enough for versions/URLs/digests).
// Returns a pointer past the closing quote, or 0 on a malformed string.
const char* parseString(const char* p, char* out, size_t outLen) {
  if (p == 0 || *p != '"' || outLen == 0) return 0;
  ++p;
  size_t n = 0;
  while (*p != '\0' && *p != '"') {
    char ch = *p;
    if (ch == '\\') {
      const char next = *(p + 1);
      if (next == '\0') return 0;
      ch = (next == '"' || next == '\\' || next == '/') ? next : next;
      p += 2;
    } else {
      ++p;
    }
    if (n + 1 < outLen) out[n++] = ch;
  }
  if (*p != '"') return 0;
  out[n] = '\0';
  return p + 1;
}

// Parse a non-negative unsigned integer (no sign, no fraction). Returns a
// pointer past the digits, or 0 when there is no digit or the value would
// overflow a uint32_t (an image size that large is refused, not wrapped).
const char* parseUint(const char* p, uint32_t* out) {
  if (p == 0 || *p < '0' || *p > '9') return 0;
  uint32_t value = 0;
  while (*p >= '0' && *p <= '9') {
    const uint32_t digit = static_cast<uint32_t>(*p - '0');
    if (value > (0xffffffffu - digit) / 10u) return 0;  // overflow
    value = value * 10u + digit;
    ++p;
  }
  *out = value;
  return p;
}

// Normalise a hex digest to lowercase and require exactly 64 hex digits.
// Returns false (leaving `out` empty) for anything else — a short/long digest,
// a non-hex character, or a stand-in hash like "ab", all of which could never
// match a real SHA-256 and so must be refused at parse time rather than
// discovered as a confusing mismatch later.
bool normaliseHex64(const char* in, char out[65]) {
  out[0] = '\0';
  if (in == 0) return false;
  size_t n = 0;
  for (; in[n] != '\0'; ++n) {
    if (n >= 64) return false;  // too long
    const char ch = in[n];
    const bool digit = ch >= '0' && ch <= '9';
    const bool lower = ch >= 'a' && ch <= 'f';
    const bool upper = ch >= 'A' && ch <= 'F';
    if (!digit && !lower && !upper) return false;
    out[n] = upper ? static_cast<char>(ch - 'A' + 'a') : ch;
  }
  if (n != 64) return false;
  out[64] = '\0';
  return true;
}

}  // namespace

bool InsightOta::parseOffer(const char* json, OtaOffer* offer) {
  if (offer == 0) return false;
  *offer = OtaOffer();  // invalid/empty until proven otherwise
  if (json == 0) return false;

  const char* update = findField(json, "update");
  if (update == 0) return false;  // no envelope at all

  // `{"update":null}`: VALID, and explicitly nothing to do. This is the
  // distinction the class comment calls out — null is an ANSWER, not a parse
  // error, so a device never mistakes "you are current" for "the reply was
  // broken".
  if (isNull(update)) {
    offer->valid = true;
    offer->hasUpdate = false;
    return true;
  }

  if (*update != '{') return false;  // update must be null or an object

  // Every field is required in an update object; a missing one is malformed.
  const char* version = findField(update, "version");
  const char* size = findField(update, "size");
  const char* sha = findField(update, "sha256");
  const char* url = findField(update, "url");
  if (version == 0 || size == 0 || sha == 0 || url == 0) return false;

  const char* afterVersion = parseString(version, offer->version,
                                         sizeof(offer->version));
  if (afterVersion == 0 || offer->version[0] == '\0') return false;

  uint32_t sizeValue = 0;
  if (parseUint(size, &sizeValue) == 0) return false;

  char shaRaw[96];
  if (parseString(sha, shaRaw, sizeof(shaRaw)) == 0) return false;
  if (!normaliseHex64(shaRaw, offer->sha256)) return false;

  const char* afterUrl = parseString(url, offer->url, sizeof(offer->url));
  if (afterUrl == 0 || offer->url[0] == '\0') return false;

  offer->size = sizeValue;
  offer->valid = true;
  offer->hasUpdate = true;
  return true;
}

// ===========================================================================
// Download + verify + flash
// ===========================================================================

namespace {

// Resolve the retry-after delay, in millis, honoured for a 429 — from the
// INSTANCE seam (`retryAfterHeaderSeconds()`), not from any global. A negative
// (absent/malformed) header keeps the one-hour fallback; a real value is
// seconds -> millis, saturating rather than wrapping on an absurd value.
uint32_t resolveRetryAfterMillis(long seconds) {
  if (seconds < 0) return kOtaDefaultRetryAfterMillis;
  const uint64_t ms = static_cast<uint64_t>(seconds) * 1000u;
  return ms > 0xffffffffull ? 0xffffffffu : static_cast<uint32_t>(ms);
}

}  // namespace

bool InsightOta::downloadImage(const OtaOffer& offer, uint32_t* received) {
  *received = 0;
  if (transport_ == 0) return false;

  // ZERO from here: nothing is carried over from any previous attempt, and the
  // write index starts at 0 (D2.6 — no resume). The buffer is filled with a
  // sentinel first so an over-long body cannot be confused for a short one.
  ++attempts_;

  const size_t want = offer.size;
  for (size_t i = 0; i < want; ++i) image_[i] = 0;  // clear the staging prefix

  // The transport GET seam is a whole-buffer read; the image is fetched into
  // image_ from offset 0 with a capacity of `offer.size`, so an over-long body
  // cannot run past what the offer promised. The delivered length is read from
  // the seam's OUT-PARAMETER — never from a terminator, because image bytes are
  // opaque and a 0x00 in the middle is data, not an end-of-body marker.
  size_t delivered = 0;
  HttpOutcome outcome =
      transport_->get(offer.url, reinterpret_cast<char*>(image_), want,
                      &delivered);
  lastStatus_ = outcome.status;
  lastContentLength_ = outcome.kind == HttpOutcome::Ok ? delivered : 0;

  if (outcome.kind != HttpOutcome::Ok) return false;
  if (outcome.status < 200 || outcome.status >= 300) return false;

  // A response that delivers MORE than the offer promised is a size mismatch
  // too; clamp to the promised length so `received > offer.size` is reported by
  // the caller's equality check as a failure rather than silently accepted.
  if (delivered > want) delivered = want;
  *received = static_cast<uint32_t>(delivered);
  return true;
}

OtaResult InsightOta::processOffer(const char* offerJson) {
  nowMillis_ = readClock();
  nextAttemptAtMillis_ = 0;
  lastRetryAfter_ = 0;
  lastStatus_ = 0;

  OtaOffer offer;
  if (!parseOffer(offerJson, &offer)) {
    reason_ = OtaResult::InvalidOffer;
    return OtaResult::make(OtaResult::InvalidOffer, false, 0, 0, 0);
  }
  if (!offer.hasUpdate) {
    reason_ = OtaResult::NoUpdate;
    return OtaResult::make(OtaResult::NoUpdate, false, 0, 0, 0);
  }

  // Refuse an offer that cannot be buffered whole (or is empty) BEFORE any
  // image byte is fetched. A size we cannot hold is a size we must not start.
  if (offer.size == 0 || offer.size > maxImage_) {
    reason_ = OtaResult::UnsupportedSize;
    return OtaResult::make(OtaResult::UnsupportedSize, true, 0, 0, 0);
  }

  // A detached flash sink means there is nowhere safe to write; a fully
  // verified image would be dropped, so fail before downloading.
  if (flash_ == 0) {
    reason_ = OtaResult::TransportFailure;
    return OtaResult::make(OtaResult::TransportFailure, true, 0, 0, 0);
  }

  if (transport_ == 0) {
    reason_ = OtaResult::TransportFailure;
    return OtaResult::make(OtaResult::TransportFailure, true, 0, 0, 0);
  }

  uint32_t received = 0;
  const bool fetched = downloadImage(offer, &received);
  if (!fetched) {
    // A 429 is the one transport outcome with its own policy: record the next
    // allowed time from `retry-after` (or the one-hour default) and return —
    // never retry inside this pass (INV-O2, ST-O2).
    if (lastStatus_ == 429) {
      const uint32_t wait = resolveRetryAfterMillis(retryAfterHeaderSeconds());
      lastRetryAfter_ = wait;
      nextAttemptAtMillis_ = nowMillis_ + wait;
      reason_ = OtaResult::RateLimited;
      return OtaResult::make(OtaResult::RateLimited, true, 0, nextAttemptAtMillis_,
                             wait);
    }
    // Any other transport failure is retryable, scheduled with the shared
    // bounded backoff so a flapping network cannot hot-loop.
    const uint32_t wait = backoffMillis(0u);
    lastRetryAfter_ = wait;
    nextAttemptAtMillis_ = nowMillis_ + wait;
    reason_ = OtaResult::TransportFailure;
    return OtaResult::make(OtaResult::TransportFailure, true, received,
                           nextAttemptAtMillis_, wait);
  }

  // Enforce the promised length BEFORE hashing. A short (truncated) or long
  // read is a mismatch; nothing is flashed.
  if (received != offer.size) {
    reason_ = OtaResult::SizeMismatch;
    return OtaResult::make(OtaResult::SizeMismatch, true, received, 0, 0);
  }

  // Compute the digest over the verified-length buffer only.
  OtaResult result;
  uint8_t ctx[Sha256::kContextBytes];
  uint8_t digest[32];
  hasher_.init(ctx);
  hasher_.update(ctx, image_, received);
  hasher_.finalize(ctx, digest);
  toHex(digest, result.computedSha256);

  if (std::strcmp(result.computedSha256, offer.sha256) != 0) {
    // Byte count matched, digest did not (ST-O1(b): the last byte was altered).
    result.kind = OtaResult::HashMismatch;
    result.retry = true;
    result.received = received;
    reason_ = OtaResult::HashMismatch;
    return result;
  }

  // Size AND digest both match: this is the ONLY reachable call to the flash
  // sink, and it happens exactly once, with the whole verified image.
  const bool written = flash_(image_, received);
  if (!written) {
    const uint32_t wait = backoffMillis(0u);
    lastRetryAfter_ = wait;
    nextAttemptAtMillis_ = nowMillis_ + wait;
    reason_ = OtaResult::TransportFailure;
    return OtaResult::make(OtaResult::TransportFailure, true, received,
                           nextAttemptAtMillis_, wait);
  }

  result.kind = OtaResult::Flashed;
  result.retry = false;
  result.received = received;
  reason_ = OtaResult::Flashed;
  return result;
}

OtaResult InsightOta::runWithOffer(const char* offerJson) {
  ++attempts_;  // the offer itself was supplied, not fetched
  return processOffer(offerJson);
}

OtaResult InsightOta::run() {
  if (transport_ == 0) {
    nowMillis_ = readClock();
    lastStatus_ = 0;
    reason_ = OtaResult::TransportFailure;
    const uint32_t wait = backoffMillis(0u);
    lastRetryAfter_ = wait;
    nextAttemptAtMillis_ = nowMillis_ + wait;
    return OtaResult::make(OtaResult::TransportFailure, true, 0,
                           nextAttemptAtMillis_, wait);
  }

  // Fetch the offer envelope. Read into a bounded buffer; the seam reports the
  // outcome, the byte count, and guarantees a NUL-terminated body on success.
  char body[512];
  std::memset(body, 0, sizeof(body));
  size_t bodyLen = 0;
  ++attempts_;
  HttpOutcome outcome =
      transport_->get("/v1/ota", body, sizeof(body), &bodyLen);
  lastStatus_ = outcome.status;
  lastContentLength_ = outcome.kind == HttpOutcome::Ok ? bodyLen : 0;
  body[sizeof(body) - 1] = '\0';  // defensive: keep the parse bounded

  if (outcome.kind != HttpOutcome::Ok) {
    nowMillis_ = readClock();
    reason_ = OtaResult::TransportFailure;
    const uint32_t wait = backoffMillis(0u);
    lastRetryAfter_ = wait;
    nextAttemptAtMillis_ = nowMillis_ + wait;
    return OtaResult::make(OtaResult::TransportFailure, true, 0,
                           nextAttemptAtMillis_, wait);
  }
  if (outcome.status == 429) {
    nowMillis_ = readClock();
    const uint32_t wait = resolveRetryAfterMillis(retryAfterHeaderSeconds());
    lastRetryAfter_ = wait;
    nextAttemptAtMillis_ = nowMillis_ + wait;
    reason_ = OtaResult::RateLimited;
    return OtaResult::make(OtaResult::RateLimited, true, 0, nextAttemptAtMillis_,
                           wait);
  }
  if (outcome.status < 200 || outcome.status >= 300) {
    nowMillis_ = readClock();
    reason_ = OtaResult::TransportFailure;
    const uint32_t wait = backoffMillis(0u);
    lastRetryAfter_ = wait;
    nextAttemptAtMillis_ = nowMillis_ + wait;
    return OtaResult::make(OtaResult::TransportFailure, true, 0,
                           nextAttemptAtMillis_, wait);
  }

  return processOffer(body);
}

}  // namespace insight
