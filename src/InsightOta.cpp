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

// Find `"name"` as a complete key at or after `from`; returns a pointer to the
// VALUE (having consumed the `:`), or 0. A key must be preceded by `{` or a
// `,` (after optional whitespace) so a field name can never be matched inside
// a string VALUE — e.g. the `"size"` inside a version string must not be read
// as the size field.
//
// The scan is STRING-AWARE: it tracks in-string/in-escape state so a `,` or a
// key-shaped run of bytes INSIDE a string value can never be mistaken for the
// object's own punctuation. Without that, a value such as
// `"x, \"size\": 9999"` would let the `,` inside the quoted value start a
// phantom field match — a value the wire controls, so the guard matters. This
// is deliberately a structural-lite scan, not a full JSON parser (the SDK
// carries no JSON library, by design), but it is string-correct for the part it
// does parse.
const char* findField(const char* from, const char* name) {
  if (from == 0 || name == 0) return 0;
  const size_t nameLen = std::strlen(name);
  bool inString = false;
  bool escaped = false;
  const char* p = from;
  while (*p != '\0') {
    const char ch = *p;
    if (inString) {
      if (escaped) {
        escaped = false;  // this byte is escaped; never structural
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        inString = false;
      }
      ++p;
      continue;
    }
    if (ch == '"') {
      inString = true;
      ++p;
      continue;
    }
    if (ch == '{' || ch == ',') {
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

// True when `p` begins the literal `null` AS A WHOLE TOKEN — the four bytes
// `null` followed by a JSON delimiter (whitespace, `,`, `}` or `]`) or the end
// of input. A bare prefix match would accept `nullify`/`nullptr`/`nullx` as
// `null`, so a malformed update value could be read as a well-formed
// "nothing to do"; the delimiter requirement makes the match exact.
bool isNull(const char* p) {
  if (p == 0 || std::strncmp(p, "null", 4) != 0) return false;
  const char c = p[4];
  return c == '\0' || c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
         c == ',' || c == '}' || c == ']';
}

// Parse a JSON string starting at the opening quote into `out` (capacity
// `outLen`, always NUL-terminated). Handles the standard JSON escapes
// (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`; `\uXXXX` is copied as its
// four hex digits, which is enough for the identifiers this parser reads).
// Returns a pointer past the closing quote, or 0 on a malformed string.
//
// A value longer than `outLen` is REFUSED (returns 0), never silently
// truncated: a truncated digest, URL or version would then be compared against
// a different value and the mismatch would surface somewhere confusing rather
// than as a parse failure at the point the garbage arrived. (A truncated
// signature was the sharpest case: silently shortening a security field is
// exactly the downgrade the offer parser must not perform.)
const char* parseString(const char* p, char* out, size_t outLen) {
  if (p == 0 || *p != '"' || out == 0 || outLen == 0) return 0;
  ++p;
  size_t n = 0;
  while (*p != '\0' && *p != '"') {
    char ch = *p;
    if (ch == '\\') {
      const char next = *(p + 1);
      if (next == '\0') return 0;
      switch (next) {
        case '"': ch = '"'; break;
        case '\\': ch = '\\'; break;
        case '/': ch = '/'; break;
        case 'b': ch = '\b'; break;
        case 'f': ch = '\f'; break;
        case 'n': ch = '\n'; break;
        case 'r': ch = '\r'; break;
        case 't': ch = '\t'; break;
        default: ch = next; break;  // \uXXXX and unknown: copy the marker byte
      }
      p += 2;
    } else {
      ++p;
    }
    // Room for the byte AND the terminator; anything more is a refusal, not a
    // silent truncation.
    if (n + 1 >= outLen) return 0;
    out[n++] = ch;
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

// The same normalisation for a VARIABLE-length hex field, bounded by `maxChars`
// and requiring at least one character. It exists for the optional signed-image
// fields (a signature and a key id), which are not fixed-width: their valid
// lengths are a property of the signature scheme the verifier implements, not
// of this parser. What the parser CAN enforce — and does — is that the field is
// pure lowercase-normalisable hex and no longer than the seam can carry, so a
// non-hex or over-long security field is refused as a malformed offer instead
// of being handed to a verifier as garbage/"unsigned".
bool normaliseHexN(const char* in, char out[], size_t outLen, size_t maxChars,
                   size_t minChars) {
  if (outLen == 0) return false;
  out[0] = '\0';
  if (in == 0) return false;
  size_t n = 0;
  for (; in[n] != '\0'; ++n) {
    if (n >= maxChars || n + 1 >= outLen) return false;  // too long / no room
    const char ch = in[n];
    const bool digit = ch >= '0' && ch <= '9';
    const bool lower = ch >= 'a' && ch <= 'f';
    const bool upper = ch >= 'A' && ch <= 'F';
    if (!digit && !lower && !upper) return false;
    out[n] = upper ? static_cast<char>(ch - 'A' + 'a') : ch;
  }
  if (n < minChars) return false;
  out[n] = '\0';
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

  // Optional signed-image fields (B14 / FR-OTA-07). Absent on a server that
  // does not sign -> empty, `hasSignature == false`, offer still valid. PRESENT
  // but malformed (not hex, or over the seam's ceiling) -> the whole offer is
  // refused: a security field that cannot be read is not the same as one that
  // was not sent, and quietly ignoring it would silently drop the requirement
  // the operator asked for.
  const char* sig = findField(update, "signature");
  if (sig != 0) {
    // `findField` lands on the value position (at the `:`); read the JSON
    // string first, exactly as version/url do, THEN normalise its contents.
    char sigRaw[256];
    if (parseString(sig, sigRaw, sizeof(sigRaw)) == 0) return false;
    if (!normaliseHexN(sigRaw, offer->signature, sizeof(offer->signature),
                       kOtaSignatureHexMaxLength, 1)) {
      return false;
    }
    offer->hasSignature = true;
  }
  const char* keyid = findField(update, "pubkey_id");
  if (keyid != 0) {
    // A key id is optional even when a signature is present (a single-key
    // device does not need one); but if it IS sent it must be well-formed.
    char keyRaw[128];
    if (parseString(keyid, keyRaw, sizeof(keyRaw)) == 0) return false;
    if (!normaliseHexN(keyRaw, offer->pubkeyId, sizeof(offer->pubkeyId),
                       kOtaPubkeyIdHexMaxLength, 1)) {
      return false;
    }
  }

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

// Compare two 64-character lowercase-hex digests in CONSTANT TIME with respect
// to their contents (the number of differing bytes does not leak through an
// early return). A digest comparison is a security check: a byte-at-a-time
// early-out gives an attacker a timing oracle to recover the expected digest
// one hex digit at a time. Both operands are fixed 64-char NUL-terminated
// fields, so the loop is a fixed 64 iterations and `diff` accumulates every
// position before it is tested once.
//
// This is defence in depth: the digest is over attacker-supplied image bytes
// and is compared against the server-offered digest, so a timing side channel
// here is exactly the kind of thing that should not exist. It does not (and
// cannot) make the signature verifier constant-time — that is the crypto
// backend's job, and the seam's contract says so.
bool constantTimeHexEqual64(const char* a, const char* b) {
  unsigned char diff = 0;
  for (size_t i = 0; i < 64; ++i) {
    diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
  }
  // Both are exactly 64 hex chars by construction; also require the terminator
  // to match, so a malformed shorter string can never compare equal.
  diff |= static_cast<unsigned char>(a[64]) ^ static_cast<unsigned char>(b[64]);
  return diff == 0;
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
  // image_ from offset 0 with a capacity of `offer.size`, so the copy itself
  // can never run past what the offer promised. The delivered length is read
  // from the seam's OUT-PARAMETER — never from a terminator, because image
  // bytes are opaque and a 0x00 in the middle is data, not an end-of-body
  // marker. `delivered` is reported VERBATIM (not clamped): a seam that claims
  // MORE than the offer promised is a lie the caller's `received != offer.size`
  // check must SEE and reject, not have silently smoothed to equality — clamping
  // would turn a malformed/over-long delivery into a passing size gate.
  size_t delivered = 0;
  HttpOutcome outcome =
      transport_->get(offer.url, reinterpret_cast<char*>(image_), want,
                      &delivered);
  lastStatus_ = outcome.status;
  lastContentLength_ = outcome.kind == HttpOutcome::Ok ? delivered : 0;

  if (outcome.kind != HttpOutcome::Ok) return false;
  if (outcome.status < 200 || outcome.status >= 300) return false;

  *received = static_cast<uint32_t>(delivered);
  return true;
}

OtaResult InsightOta::processOffer(const char* offerJson) {
  nowMillis_ = readClock();
  nextAttemptAtMillis_ = 0;
  lastRetryAfter_ = 0;
  lastStatus_ = 0;

  // Reset the per-pass record, so a pass that never reaches the signature step
  // (no update, malformed offer) can never report a prior pass's signature. The
  // record is only re-populated once an update offer has parsed.
  lastSignatureChecked_ = false;
  lastSignatureOk_ = false;
  lastOfferVersion_[0] = '\0';
  lastOfferSignature_[0] = '\0';
  lastOfferPubkeyId_[0] = '\0';
  lastComputedSha256_[0] = '\0';
  lastOfferSize_ = 0;
  lastReceived_ = 0;

  OtaOffer offer;
  if (!parseOffer(offerJson, &offer)) {
    reason_ = OtaResult::InvalidOffer;
    return OtaResult::make(OtaResult::InvalidOffer, false, 0, 0, 0);
  }
  if (!offer.hasUpdate) {
    reason_ = OtaResult::NoUpdate;
    return OtaResult::make(OtaResult::NoUpdate, false, 0, 0, 0);
  }

  // Record what was OFFERED, so lastVerification() is a self-contained record
  // of the pass even when the pass later fails before any bytes arrive.
  lastOfferVersion_[0] = '\0';
  copyInto(lastOfferVersion_, sizeof(lastOfferVersion_), offer.version);
  copyInto(lastOfferSignature_, sizeof(lastOfferSignature_), offer.signature);
  copyInto(lastOfferPubkeyId_, sizeof(lastOfferPubkeyId_), offer.pubkeyId);
  lastOfferSize_ = offer.size;

  // Refuse an offer that cannot be buffered whole (or is empty) BEFORE any
  // image byte is fetched. A size we cannot hold is a size we must not start.
  //
  // NOT retryable, and no schedule: the SAME offer would be refused the same
  // way forever, so a caller that honoured a retry flag here would spin on a
  // size it can never buffer (the hot loop INV-O2 forbids). `retry == false`
  // and a zero schedule say "this offer is refused; wait for a different one".
  // lastVerification() still carries the offered size, so the refusal is
  // diagnosable.
  if (offer.size == 0 || offer.size > maxImage_) {
    reason_ = OtaResult::UnsupportedSize;
    return OtaResult::make(OtaResult::UnsupportedSize, false, 0, 0, 0);
  }

  // A detached flash sink means there is nowhere safe to write; a fully
  // verified image would be dropped, so fail before downloading.
  //
  // Still retryable (there is nothing wrong with the OFFER — the device is
  // merely unconfigured, and a caller that wires the sink can make the very
  // next pass succeed), but scheduled with a bounded backoff like every other
  // retry-worthy outcome: a genuinely misconfigured device that retries must
  // not hot-loop (INV-O2). Previously this returned `retry == true` with a ZERO
  // schedule, which is exactly the "retryable with no deadline" hole.
  if (flash_ == 0) {
    const uint32_t wait = backoffMillis(0u);
    lastRetryAfter_ = wait;
    nextAttemptAtMillis_ = nowMillis_ + wait;
    reason_ = OtaResult::TransportFailure;
    return OtaResult::make(OtaResult::TransportFailure, true, 0,
                           nextAttemptAtMillis_, wait);
  }

  if (transport_ == 0) {
    const uint32_t wait = backoffMillis(0u);
    lastRetryAfter_ = wait;
    nextAttemptAtMillis_ = nowMillis_ + wait;
    reason_ = OtaResult::TransportFailure;
    return OtaResult::make(OtaResult::TransportFailure, true, 0,
                           nextAttemptAtMillis_, wait);
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
    // Record what arrived before the failure so the record is diagnosable even
    // on a transport failure.
    lastReceived_ = received;
    return OtaResult::make(OtaResult::TransportFailure, true, received,
                           nextAttemptAtMillis_, wait);
  }

  // Enforce the promised length BEFORE hashing. A short (truncated) or long
  // read is a mismatch; nothing is flashed.
  //
  // Retryable but NOT scheduled: a size mismatch is a property of THIS
  // transfer (a truncated stream, or a seam that reported a length the offer
  // did not promise), and the caller's normal loop re-attempts on the next
  // poll. No backoff is recorded because the failure is not a 429 and is not
  // evidence of a flapping link — and crucially the offer itself is fine. The
  // computed digest is "": nothing was hashed. `received`/lastVerification()
  // carry the short/long count so the divergence is visible.
  if (received != offer.size) {
    reason_ = OtaResult::SizeMismatch;
    lastReceived_ = received;
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

  // Record the computed digest and the byte count REGARDLESS of whether the
  // digest then matches, so a HashMismatch pass — the case that most needs "what
  // did we compute?" — is diagnosable through both the OtaResult and
  // lastVerification(). (Previously this copy happened only on the success path,
  // so exactly the failing cases were the ones with an empty record.)
  copyInto(lastComputedSha256_, sizeof(lastComputedSha256_),
           result.computedSha256);
  lastReceived_ = received;

  if (!constantTimeHexEqual64(result.computedSha256, offer.sha256)) {
    // Byte count matched, digest did not (ST-O1(b): the last byte was altered).
    // The computed digest already rides on `result`, and the record carries it
    // too, so an operator sees offered-vs-computed for the failure.
    result.kind = OtaResult::HashMismatch;
    result.retry = true;
    result.received = received;
    reason_ = OtaResult::HashMismatch;
    return result;
  }

  // --- the signed-image gate (B14 / FR-OTA-07 / NFR-SEC-03) --------------
  //
  // Size and SHA-256 prove the bytes are the bytes that were OFFERED; they say
  // nothing about who offered them (an attacker who can serve the image can
  // serve its digest too). The signature is what proves authorship, and it is
  // checked here — after the digest, before the flash — so a wrongly-signed
  // image is rejected with NOTHING written, exactly like a corrupt one.
  //
  // Three cases, and the default is the one that keeps the shipped contract:
  //
  //   * no verifier installed  -> signature checking is OFF unless the caller
  //     opted into `requireSignature()`. With a signature present this is a
  //     deliberate downgrade (the device has no key); the fields are recorded
  //     but not enforced. With requireSignature() it FAILS CLOSED instead — a
  //     device told to require signing must not accept an unsigned image just
  //     because no key was wired.
  //   * verifier installed, offer unsigned -> checked only if requireSignature()
  //     (an unsigned image against a signing device), otherwise accepted on the
  //     digest alone.
  //   * verifier installed, offer signed   -> verify, and flash ONLY on true.
  const bool haveVerifier = (verifySignature_ != 0);
  const bool haveSignature = offer.hasSignature && offer.signature[0] != '\0';

  if (!haveVerifier && !requireSignature_) {
    // No key, no requirement: the pre-B14 path. Nothing was signed-checked, and
    // lastSignatureChecked_ stays false so the record cannot claim otherwise.
  } else if (!haveVerifier && requireSignature_) {
    // Unreachable-as-configured: signatures required but no verifier. Fail
    // closed — an absent key is not a licence to skip the check.
    reason_ = OtaResult::SignatureMismatch;
    return OtaResult::make(OtaResult::SignatureMismatch, false, received, 0, 0);
  } else if (!haveSignature) {
    // A verifier is installed but the offer carried no signature.
    lastSignatureChecked_ = false;
    lastSignatureOk_ = false;
    if (requireSignature_) {
      reason_ = OtaResult::SignatureMismatch;
      return OtaResult::make(OtaResult::SignatureMismatch, false, received, 0,
                             0);
    }
    // else: unsigned image, signing available but not mandatory -> fall through
    // on the digest (the caller installed a verifier to ENFORCE it; to actually
    // enforce it for every image, call setRequireSignature(true)).
  } else {
    // The real check: the verifier runs over the whole buffered image. The
    // signature and key id are the parsed lowercase-hex strings, positioned so
    // a test's fake verifier — or a firmware adapter — can compare them against
    // what it expects. A false return means "not signed by a trusted key".
    lastSignatureChecked_ = true;
    const bool ok = verifySignature_(image_, received, offer.signature,
                                     offer.pubkeyId[0] != '\0' ? offer.pubkeyId
                                                               : 0);
    lastSignatureOk_ = ok;
    if (!ok) {
      // Wrong (or hostile) signature: DO NOT flash. Not retryable — the same
      // bytes would fail the same way, and a retry loop against a bad image is
      // exactly the hammering the policy avoids.
      reason_ = OtaResult::SignatureMismatch;
      return OtaResult::make(OtaResult::SignatureMismatch, false, received, 0, 0);
    }
  }

  // Size AND digest (and, when enforced, the signature) all match: this is the
  // ONLY reachable call to the flash sink, and it happens exactly once, with
  // the whole verified image.
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

  // Scheduling note (INV-O2): this entry point is the seam a caller (or a test)
  // uses when IT has already decided to process this offer body, so it does not
  // re-check `isReady()` — the 429/quota enforcement lives in the pass that
  // FETCHES the offer (run()), the only path that can observe a server 429, and
  // enforcing a schedule here would make the injected-offer tests untestable.
  //
  // It DOES guarantee it leaves no stale deadline behind: processOffer() resets
  // `nextAttemptAtMillis_`/`lastRetryAfter_` at the top of every pass (after
  // reading the clock), so a schedule a previous pass recorded — a 429's
  // retry-after — can never be inherited by this one. A caller alternating
  // isReady()/runWithOffer() is therefore never told "not ready" because of a
  // deadline that belonged to an earlier offer. That reset is the invariant
  // test_run_with_offer_clears_stale_schedule pins.
  return processOffer(offerJson);
}

OtaResult InsightOta::run() {
  // Reset the pass schedule up front so a stale deadline from a previous pass
  // can never be observed or inherited here — every branch below either records
  // a fresh one or leaves a deliberate zero. (processOffer() resets again after
  // reading the clock; this covers the early returns before it.)
  nowMillis_ = readClock();
  nextAttemptAtMillis_ = 0;
  lastRetryAfter_ = 0;

  if (transport_ == 0) {
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
