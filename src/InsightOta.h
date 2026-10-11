#ifndef INSIGHT_OTA_H
#define INSIGHT_OTA_H

#include <cstddef>
#include <cstdint>

#include "InsightReliability.h"
#include "InsightTransport.h"

namespace insight {

// ---------------------------------------------------------------------------
// OTA image verification: the frozen route and the frozen limits
// ---------------------------------------------------------------------------

// The OTA image route. Frozen by spec §6.5 / the contract lock; the offer's
// `url` field points at it (or at a per-version path under it). Kept here as a
// single source of truth so the policy, the tests and the server cannot drift.
inline const char* otaImagePath() { return "/v1/ota/image"; }

// Longest image the download from zero will buffer. An offer whose `size`
// exceeds this is rejected before a single byte is fetched: the image is held
// whole in RAM (D2.6 — no streaming, no partial flash), so a size ceiling is
// the only thing standing between a hostile/bogus offer and an out-of-memory
// reset. Not required reading for spec conformance; it is a RAM guard.
#ifndef INSIGHT_OTA_MAX_IMAGE
#define INSIGHT_OTA_MAX_IMAGE 4096
#endif

// Default wait scheduled after a 429 that carries no usable `retry-after`.
// D2.8 puts the OTA quota at one download per device per hour, so one hour is
// the natural fallback: a malformed/absent header must never collapse into "no
// backoff at all", which would be the tight retry loop INV-O2 forbids.
const uint32_t kOtaDefaultRetryAfterMillis = 3600000u;

// Longest `sha256` digest the offer parser will accept, in hex characters.
// 64 is a real SHA-256; anything longer is not a digest we could ever match,
// and bounding it keeps the copy into Offer from overrunning its buffer.
const size_t kOtaSha256HexLength = 64;

// ---------------------------------------------------------------------------
// Parsed OTA offer
// ---------------------------------------------------------------------------

// The validated shape of one `GET /v1/ota` answer (spec §6.4):
//
//   { "update": null }                              -> no update (the device
//                                                      is current or does not
//                                                      report a version)
//   { "update": { "version", "size", "sha256", "url" } }
//
// `valid` is the single gate a caller must consult before touching any other
// field: a malformed envelope leaves `valid == false` and every string empty,
// so a caller cannot act on half-parsed garbage. A `{ "update": null }` answer
// is deliberately VALID with `hasUpdate == false` — "nothing to do" is a
// well-formed answer, not a parse failure, and the two must never be conflated
// (a device that reads a parse failure as "no update" would silently never
// upgrade; a device that reads null as a failure would alarm forever).
//
// The digest is held as LOWERCASE hex, always exactly 64 characters when
// `valid && hasUpdate`: the parser normalises case and rejects anything that is
// not 64 hex digits, so the verification step compares like with like.
struct OtaOffer {
  bool valid;       // the envelope parsed and every present field was well-formed
  bool hasUpdate;   // false => `{ "update": null }`: nothing to do
  // Offered version string; meaningful when `valid && hasUpdate`.
  char version[64];
  char sha256[65];  // lowercase hex, 64 chars + NUL
  // Where to fetch the image; meaningful when `valid && hasUpdate`.
  char url[256];
  uint32_t size;    // image length in bytes, as offered
  // Optional signed-image fields (B14 / FR-OTA-07). Both are absent on a
  // non-signing server, which leaves them EMPTY and `hasSignature == false` —
  // that is a legal offer, not a parse failure. When present they are lowercase
  // hex, bounded, and only ever filled after the same structural check the rest
  // of the envelope passes; a signature that is not valid hex makes the whole
  // offer malformed (a server that emits garbage for a security field must not
  // be silently downgraded to "unsigned").
  bool hasSignature;
  // Lowercase-hex signature (up to 128 chars + NUL); meaningful only when
  // `hasSignature`.
  char signature[129];
  // Lowercase-hex signing-key id (up to 64 chars + NUL); empty when the offer
  // carries none.
  char pubkeyId[65];

  // Construct an empty, invalid offer (the "nothing parsed yet" state).
  OtaOffer() : valid(false), hasUpdate(false), size(0), hasSignature(false) {
    version[0] = '\0';
    sha256[0] = '\0';
    url[0] = '\0';
    signature[0] = '\0';
    pubkeyId[0] = '\0';
  }
};

// ---------------------------------------------------------------------------
// Outcome of one OTA attempt
// ---------------------------------------------------------------------------

// What one `InsightOta::run()` pass concluded. Every value is actionable by the
// caller without inspecting the class's internals:
//
//   NoUpdate          - the offer said `{"update":null}`; nothing to download.
//   InvalidOffer      - the offer was malformed; do not act on it.
//   UnsupportedSize   - the offer's `size` exceeds the buffer ceiling or is 0.
//   RateLimited       - the server answered 429; the attempt is over and the
//                       next one is scheduled AT or AFTER `retry-after`. No
//                       retry was attempted in this pass (INV-O2).
//   TransportFailure  - the offer or image GET did not complete (timeout/error/
//                       a non-2xx status); retryable. Nothing was flashed.
//   SizeMismatch      - fewer or more bytes arrived than `offer.size` promised
//                       (ST-O1(a): a truncated stream); nothing was flashed.
//   HashMismatch      - the byte count matched but the SHA-256 did not
//                       (ST-O1(b): the last byte was altered); nothing flashed.
//   SignatureMismatch - the image is authentic in the SHA-256 sense but its
//                       detached signature does not verify against the trusted
//                       key (B14 / FR-OTA-07 / NFR-SEC-03). Reached ONLY when a
//                       signature verifier is installed and the offer carries a
//                       signature to check; nothing was flashed. Distinct from
//                       HashMismatch so an operator can tell a corrupt transfer
//                       from a wrongly-signed (or hostile) image.
//   Flashed           - size AND digest (and, when required, the signature) all
//                       matched; the image was handed to the flash sink EXACTLY
//                       once.
struct OtaResult {
  enum Kind {
    NoUpdate,
    InvalidOffer,
    UnsupportedSize,
    RateLimited,
    TransportFailure,
    SizeMismatch,
    HashMismatch,
    SignatureMismatch,
    Flashed
  };

  // Which outcome of the OTA operation this is.
  Kind kind;
  // True when the caller should try the whole operation again later. Every
  // failure that is not a permanent offer rejection is retry-worthy; the
  // load-bearing point is that `Flashed`, `NoUpdate` and `InvalidOffer` are not.
  bool retry;
  // Bytes actually received from the image GET (diagnostics; equals offer.size
  // on a Flashed, and is short on a SizeMismatch).
  uint32_t received;
  // millis()-domain deadline of the NEXT allowed attempt. Non-zero only after a
  // RateLimited (>= now + retry-after) or a retry-worthy failure (now + backoff).
  // Zero means "no schedule recorded".
  uint32_t retryAtMillis;
  // The duration actually scheduled: the honoured `retry-after` on a 429, or the
  // backoff on a transport failure. Exposed so a test can assert the schedule
  // instead of ever observing a sleep — this class never blocks (see below).
  uint32_t retryAfterMillis;
  // The digest this attempt computed over what it received, lowercase hex. Empty
  // unless the download completed far enough to hash.
  char computedSha256[65];

  // Construct a TransportFailure result with no schedule recorded — the
  // "nothing attempted yet" state.
  OtaResult()
      : kind(TransportFailure), retry(false), received(0), retryAtMillis(0),
        retryAfterMillis(0) {
    computedSha256[0] = '\0';
  }

  // Factory for the common case: fill the kind/retry/received/schedule fields
  // and leave computedSha256 empty. Used everywhere a result is returned
  // without reaching the hash step.
  static OtaResult make(Kind k, bool retryable, uint32_t receivedBytes,
                        uint32_t retryAt, uint32_t retryAfter) {
    OtaResult r;
    r.kind = k;
    r.retry = retryable;
    r.received = receivedBytes;
    r.retryAtMillis = retryAt;
    r.retryAfterMillis = retryAfter;
    return r;
  }
};

// ---------------------------------------------------------------------------
// Signed-image verification seam (B14 / FR-OTA-07 / NFR-SEC-03)
// ---------------------------------------------------------------------------

// The detached signature carried by an offer, as lowercase hex, BOUNDED so the
// copy into OtaOffer can never overrun. 128 hex characters is 64 signature
// bytes — room for an Ed25519 (64 B) signature and enough headroom that a
// longer scheme (e.g. a DER ECDSA signature) still has to be checked by the
// verifier, which is the component that knows the scheme. Anything longer than
// this is not a signature this SDK could ever verify and is treated as a
// malformed offer.
const size_t kOtaSignatureHexMaxLength = 128;

// The `pubkey_id` an offer may carry to name WHICH trusted key signed it. This
// is the whole reason a signature is not just a boolean: a device may hold more
// than one trusted key (during a key rotation) and the verifier must know which
// one the server claims to have used. Bounded like the digest, and lowercase
// hex by the same parser rule.
const size_t kOtaPubkeyIdHexMaxLength = 64;

// The crypto seam. This is the ONE piece of the signed-image path that is real
// cryptography in firmware, and it is deliberately a pair of plain C function
// pointers — the seam style used throughout this SDK — so that:
//
//   * native tests inject a FAKE verifier and prove the POLICY (wrong signature
//     -> no flash; right signature -> flash) with no crypto library, no key
//     material and no platform dependency; and
//   * firmware plugs in its real verifier (ESP32 `UPDATE_SIGN` /
//     `esp_image_verify_signature`-style, or an Ed25519/ECDSA primitive)
//     without this header ever naming a crypto package.
//
// `verify(image, len, signatureHex, pubkeyIdHex)` returns true ONLY when
// `signatureHex` is a valid signature, under the trusted key named/selected by
// `pubkeyIdHex`, over EXACTLY the `len` bytes of `image`. Both strings are
// NUL-terminated lowercase hex and are never modified by the callee. A null
// string means the offer did not carry that field and MUST be treated as a
// verification failure, not a pass.
//
// A null `SignatureVerifier` function pointer means "this build has no signing
// key": signature checking is then SKIPPED entirely and the offer's signature
// fields are ignored — see InsightOta::setSignatureVerifier() for why that is a
// deliberate opt-in rather than a silent downgrade.
typedef bool (*SignatureVerifier)(const uint8_t* image, size_t len, const char* signatureHex, const char* pubkeyIdHex);

// ---------------------------------------------------------------------------
// The record of what was actually checked, and what was flashed
// ---------------------------------------------------------------------------

// The end of a signed-conscious OTA pass, as a value. Bounded strings, no
// pointers: an embedder derives this from its last OtaResult (see
// makeVerification(), which owns the mapping) and can then log it, hand it to
// `reconcile`, or compare it against the running image's receipt without this
// header depending on InsightOta at all.
//
// The fields that matter for INV-O4 (the reconciler's "is what I believe
// running really what got flashed?" question):
//
//   * flashed          - a write to the partition happened THIS session. It is
//                        derived from `result == Flashed` and nothing else, so
//                        it can never claim a flash the policy did not perform.
//   * signatureChecked - a verifier was installed AND the offer carried a
//                        signature, so the accept/reject decision below was
//                        actually made by crypto. False means "unchecked", which
//                        is a materially different statement from "verified".
//   * signatureOk      - that check passed. Only ever true when
//                        `signatureChecked` is true.
//
// `sha256` is the digest the pass computed over what it received (identical to
// OtaResult::computedSha256). It is intentionally the COMPUTED digest, not the
// offered one: it is the record of the bytes, so a mismatch between the two is
// visible in exactly the HashMismatch/SignatureMismatch cases.
struct ImageVerification {
  OtaResult::Kind result;      // the pass's outcome kind
  bool flashed;                // the partition was written (result == Flashed)
  bool signatureChecked;       // a signature was present AND a verifier ran
  bool signatureOk;            // the verifier accepted (only possible if checked)
  char version[64];            // the offered version, when the offer carried one
  char sha256[65];             // computed digest, lowercase hex ("" if not hashed)
  char signature[129];         // offered signature hex, as parsed ("" if none)
  char pubkeyId[65];           // offered key id hex, as parsed ("" if none)
  uint32_t size;               // offered image length in bytes (0 if not offered)
  uint32_t received;           // bytes actually received for the image

  ImageVerification()
      : result(OtaResult::NoUpdate), flashed(false), signatureChecked(false),
        signatureOk(false), size(0), received(0) {
    version[0] = '\0';
    sha256[0] = '\0';
    signature[0] = '\0';
    pubkeyId[0] = '\0';
  }
};

// ---------------------------------------------------------------------------
// The OTA download-and-verify policy
// ---------------------------------------------------------------------------

// Does exactly one thing, safely: fetch an offered image WHOLE, prove it is the
// image that was promised, and only then hand it to the flash sink. It is the
// device-side half of D2.6 —
//
//   restart from zero -> buffer the entire image -> receivedSize == offer.size
//     -> SHA-256 == offer.sha256 -> (and only now) write the flash slot
//
// — with the D2.8 quota rule layered on top: a 429 is honoured by recording the
// next allowed time and returning, never by hammering (INV-O2).
//
// Nothing in here talks to a network, a flash chip, a hasher or a clock
// directly. All four are injected, which is the seam style used throughout this
// SDK, and it is what makes the flash-safety property — "NOT ONE BYTE reaches
// the partition before size and digest both match" (INV-O1/INV-O5) — a thing a
// native test can *prove* rather than a thing we assert in a comment:
//
//   * `InsightTransport` (from InsightTransport.h) is the offer/image transport.
//   * `FlashSink` is the ONLY write path to the partition. `run()` calls it at
//     most once, at the very end, and only on the success branch; every other
//     exit returns with `flash->write` never having been invoked. A test's sink
//     counts its calls and holds the bytes it was given, so "did we flash?" and
//     "with what?" are both observable.
//   * `Clock` is a monotonic millisecond counter (`millis()` in firmware). It is
//     read to timestamp a 429/backoff; this class NEVER waits on it. There is no
//     delay()/sleep() anywhere — the wait is *recorded* as `retryAtMillis`, and
//     the caller resumes when the clock reaches it. That is the whole reason the
//     class is safe to call from loop() without stalling the watchdog.
//
// Non-blocking by construction: `run()` makes a bounded number of transport
// calls, does CPU-only work (copy + hash), and returns. The number of bytes it
// will buffer is capped by `kOtaMaxImage` (settable), and an offer over that cap
// is refused before the image is fetched at all.
class InsightOta {
 public:
  // The flash write seam. `write(image, len)` commits `len` bytes to the OTA
  // partition and reports whether the write succeeded. It is called with the
  // FULLY VERIFIED image, exactly once per successful run(), and never at all
  // on any failure path. Returning false means the write itself failed (a bad
  // sector, a full partition); the caller sees `TransportFailure` and retries.
  //
  // MUST be a non-blocking-callable function: firmware passes a trampoline that
  // writes the staged buffer (with the watchdog paused around it, B06/B09);
  // tests pass a recorder.
  typedef bool (*FlashSink)(const uint8_t* image, size_t len);

  // Monotonic millisecond clock. May wrap (unsigned 32-bit semantics); a null
  // clock reads as a constant zero, which makes a recorded deadline
  // unobservable but never crashes — scheduleability is the caller's concern.
  typedef unsigned long (*Clock)();

  // The 429 `retry-after` seam. The transport surfaces only the status of a
  // reply, not its headers, so the `retry-after` value a 429 carried is supplied
  // through this per-instance hook. Semantics, exactly:
  //
  //   * returns the header's value in WHOLE SECONDS when the last response
  //     carried a usable (non-negative integer) `retry-after`;
  //   * returns a NEGATIVE value when it did not (absent, malformed, or no
  //     response yet), which makes a 429 fall back to
  //     `kOtaDefaultRetryAfterMillis`.
  //
  // It is INSTANCE state, not global: two InsightOta objects — different
  // devices, different projects, or two test cases in one binary — never share a
  // header, so one NIT's test can no longer leak a stale value into another's
  // (the isolation the old module-global setter could not give). Firmware wires
  // this to parse the response it just saw (see the OtaUpdate example);
  // a null source means "no header was captured", i.e. always the default.
  typedef long (*RetryAfterSource)();

  // Read `retry-after` (whole seconds) for the last response from the installed
  // source; a negative result means "no usable header". When no source is
  // installed this is the default/absent case, which resolves to the one-hour
  // fallback rather than to an immediate retry (INV-O2).
  long retryAfterHeaderSeconds() const {
    return retryAfter_ == 0 ? -1 : retryAfter_();
  }

  // --- the SHA-256 algorithm seam ---------------------------------------
  //
  // The digest is injected so the policy is testable with a stand-in hash *and*
  // so production can plug in a hardware/accelerated implementation. The
  // default is a small, self-contained, spec-correct SHA-256 (see InsightOta.cpp,
  // exercised by a known-answer test), so a real digest is what the tests verify
  // against by default — a stand-in is opt-in via setHasher().
  //
  // The contract is the plain one-shot form: init the context, absorb the whole
  // buffer (possibly across several update() calls), then finalize into 32
  // bytes. `digest_hex` renders those 32 bytes as 64 LOWERCASE hex characters.
  struct Sha256 {
    // Context is deliberately a fixed-size byte blob, large enough for the
    // built-in implementation, so no dynamic allocation crosses the seam.
    static const size_t kContextBytes = 128;

    // Initialise a fresh context.
    typedef void (*Init)(void* ctx);
    // Absorb `len` bytes of `data` into the context.
    typedef void (*Update)(void* ctx, const uint8_t* data, size_t len);
    // Finish and write the 32-byte digest to `out`.
    typedef void (*Finalize)(void* ctx, uint8_t out[32]);

    // Init seam; null when unset.
    Init init;
    // Update seam; null when unset.
    Update update;
    // Finalize seam; null when unset.
    Finalize finalize;

    // Construct from three seams, any of which may be null (see ready()).
    Sha256(Init i = 0, Update u = 0, Finalize f = 0)
        : init(i), update(u), finalize(f) {}

    // True when all three function pointers are installed.
    bool ready() const { return init != 0 && update != 0 && finalize != 0; }
  };

  // The built-in, self-contained SHA-256 (implemented in InsightOta.cpp and
  // covered by known-answer vectors, e.g. SHA-256("") = e3b0c442...). Exposed
  // as a factory so firmware and tests can both obtain the default algorithm
  // without depending on the file-private symbols.
  static Sha256 builtInSha256();

  // Parse `json` — a `GET /v1/ota` body — into `offer`. Returns true when the
  // envelope is well-formed (`{"update":null}` included). A malformed body
  // leaves `offer->valid == false`. Pure and bounded: it never allocates and
  // never reads past the NUL terminator. See OtaOffer for the null-vs-invalid
  // distinction, which is the subtle part of this parse.
  static bool parseOffer(const char* json, OtaOffer* offer);

  // Lowercase hex encoding of a 32-byte digest into `out` (needs 65 bytes).
  static void toHex(const uint8_t digest[32], char out[65]);

  // Construct detached with no seams and the default image ceiling; install
  // the transport/flash/clock seams before use (see setTransport, setFlash...).
  InsightOta()
      : transport_(0), flash_(0), clock_(0), retryAfter_(0), hasher_(),
        verifySignature_(0), requireSignature_(false),
        maxImage_(INSIGHT_OTA_MAX_IMAGE), nowMillis_(0), nextAttemptAtMillis_(0),
        attempts_(0), lastStatus_(0), lastContentLength_(0),
        lastRetryAfter_(0), lastSignatureChecked_(false), lastSignatureOk_(false),
        lastOfferVersion_(), lastOfferSignature_(), lastOfferPubkeyId_(),
        reason_(OtaResult::NoUpdate) {
    hasher_ = builtInSha256();
    lastOfferVersion_[0] = '\0';
    lastOfferSignature_[0] = '\0';
    lastOfferPubkeyId_[0] = '\0';
  }

  // --- seams -------------------------------------------------------------

  // Install the transport used for the offer and image GETs. Does not take
  // ownership; null detaches it, which turns every attempt into a
  // TransportFailure (retryable) rather than a crash.
  void setTransport(InsightTransport* transport) { transport_ = transport; }
  InsightTransport* transport() const { return transport_; }

  // Install the flash write sink — the sole path to the partition. Null
  // detaches it, and a detached sink is a HARD failure: even a perfectly
  // verified image is not written (there is nowhere safe to write), so the
  // result is TransportFailure and nothing is flashed.
  void setFlashSink(FlashSink flash) { flash_ = flash; }
  FlashSink flashSink() const { return flash_; }

  // Install the wall clock. Null reads as a constant zero.
  void setClock(Clock clock) { clock_ = clock; }
  Clock clock() const { return clock_; }

  // Install the 429 `retry-after` source (instance-scoped; see the typedef for
  // its exact contract). Null detaches it: a 429 then takes the default wait,
  // never an immediate retry.
  void setRetryAfterSource(RetryAfterSource source) { retryAfter_ = source; }
  RetryAfterSource retryAfterSource() const { return retryAfter_; }

  // Install the digest algorithm. Passing an unready Sha256() restores the
  // built-in implementation, so a half-configured hasher can never be used.
  void setHasher(const Sha256& hasher) {
    hasher_ = hasher.ready() ? hasher : builtInSha256();
  }
  Sha256 hasher() const { return hasher_; }

  // Largest image that will be buffered, in bytes. Offers above it are refused
  // (UnsupportedSize) before the image GET. 0 restores the compiled default.
  void setMaxImageSize(size_t bytes) {
    maxImage_ = bytes > 0 ? bytes : static_cast<size_t>(INSIGHT_OTA_MAX_IMAGE);
  }
  size_t maxImageSize() const { return maxImage_; }

  // --- the signed-image seam (B14 / FR-OTA-07) ---------------------------

  // Install the detached-signature verifier. Null (the default) means "no
  // signing key on this device": the offer's signature fields are ignored and
  // the image is flashed on SHA-256 alone, which is the pre-B14 contract and
  // keeps every board that has not been given a key source-compatible.
  //
  // Non-null means signature checking is ARMED: on every offer that carries a
  // signature, the verifier runs over the whole buffered image AFTER the size
  // and SHA-256 checks and BEFORE the flash sink. A false result is a
  // `SignatureMismatch` and NOTHING is flashed — this is INV-O1 extended from
  // "the bytes are the bytes that were offered" to "the bytes were signed by
  // the key we trust", and it is the property NFR-SEC-03 (verify before flash)
  // and FR-OTA-07 (signed images) exist to provide.
  void setSignatureVerifier(SignatureVerifier verifier) {
    verifySignature_ = verifier;
  }
  SignatureVerifier signatureVerifier() const { return verifySignature_; }

  // When true, an offer that OMITS a signature is refused (`SignatureMismatch`)
  // instead of being accepted unsigned. This is the "this device only ever
  // accepts signed firmware" posture, and it is OFF by default because it is
  // strictly stronger than the shipped contract: turning it on for a device
  // whose server does not yet sign images would strand that device (ESP8266
  // cannot roll back — see InsightOtaRunner — so the mistake would be
  // permanent). An operator opts in once signing is live end to end.
  //
  // Requiring signatures without installing a verifier is a configuration the
  // policy refuses to act on: it fails closed with `SignatureMismatch` rather
  // than treating "no key" as "nothing to check".
  void setRequireSignature(bool require) { requireSignature_ = require; }
  bool requireSignature() const { return requireSignature_; }

  // Did the LAST pass actually run the verifier (verifier installed AND the
  // offer carried a signature)? Lets a caller distinguish "verified" from
  // "unchecked" without re-deriving it from the offer.
  bool lastSignatureChecked() const { return lastSignatureChecked_; }

  // Did the last signature check pass? Only meaningful when
  // lastSignatureChecked() is true; false in every other case, including a
  // rejected image, so it can never report a pass that did not happen.
  bool lastSignatureOk() const { return lastSignatureOk_; }

  // Snapshot of the last pass as one value, including the offered version /
  // signature / key id and whether a flash happened. See ImageVerification.
  // `flashed` is derived from the pass's result kind, so the record can only
  // ever claim a flash the policy itself performed.
  ImageVerification lastVerification() const {
    ImageVerification v;
    v.result = reason_;
    v.flashed = (reason_ == OtaResult::Flashed);
    v.signatureChecked = lastSignatureChecked_;
    v.signatureOk = lastSignatureOk_;
    v.size = lastOfferSize_;
    v.received = lastReceived_;
    copyInto(v.version, sizeof(v.version), lastOfferVersion_);
    copyInto(v.sha256, sizeof(v.sha256), lastComputedSha256_);
    copyInto(v.signature, sizeof(v.signature), lastOfferSignature_);
    copyInto(v.pubkeyId, sizeof(v.pubkeyId), lastOfferPubkeyId_);
    return v;
  }

  // Derive the verification record from a bare result — the seam-free helper
  // an embedder (or a reconciler) uses when all it kept was the OtaResult.
  // `flashed` follows from `result.kind == Flashed`, and the digest is the one
  // the pass computed. Signature fields are left empty because an OtaResult
  // does not carry them; use lastVerification() when they matter.
  static ImageVerification makeVerification(const OtaResult& result) {
    ImageVerification v;
    v.result = result.kind;
    v.flashed = (result.kind == OtaResult::Flashed);
    v.received = result.received;
    copyInto(v.sha256, sizeof(v.sha256), result.computedSha256);
    return v;
  }

  // --- the operation -----------------------------------------------------

  // Fetch the offer (`GET /v1/ota`), and — only if it names an update — fetch
  // the whole image, verify it, and flash it. One bounded, NON-BLOCKING pass;
  // the result is fully described by the returned OtaResult and by the
  // accessors below. The image is ALWAYS re-downloaded from zero: there is no
  // resume and no reuse of a previous attempt's bytes (D2.6), so a truncated
  // transfer can never be completed by a later one and passed off as whole.
  //
  // Guarantees, in the order they matter:
  //   * The flash sink is invoked AT MOST ONCE, and only on the branch where
  //     `received == offer.size` AND the digest matches (INV-O1/INV-O5).
  //   * A 429 anywhere in the pass ends it immediately, with the next attempt
  //     scheduled at `retryAtMillis >= now + retry-after`; run() does not retry
  //     within the pass (INV-O2, ST-O2).
  //   * No timing call blocks. The clock is read, never waited on.
  OtaResult run();

  // Run with the offer body supplied directly, skipping the offer GET. This is
  // the seam the verify tests drive (they inject the image independently), and
  // it is the same code path run() uses once it has a body.
  OtaResult runWithOffer(const char* offerJson);

  // --- inspection --------------------------------------------------------

  // millis() at which the next attempt is allowed, or 0 when none is pending.
  uint32_t nextAttemptAtMillis() const { return nextAttemptAtMillis_; }

  // True when an attempt may be made at `nowMillis` (no pending schedule, or
  // the schedule has been reached). The caller loops with
  //   if (ota.isReady(millis())) ota.run();
  // and never blocks.
  bool isReady(uint32_t nowMillis) const {
    return nextAttemptAtMillis_ == 0 || nowMillis >= nextAttemptAtMillis_;
  }

  // Clock reading captured by the last pass.
  uint32_t now() const { return nowMillis_; }

  // Duration the last pass scheduled (retry-after on a 429, backoff otherwise;
  // 0 when nothing was scheduled). Exposed so a test asserts the SCHEDULE
  // rather than ever observing a delay.
  uint32_t lastRetryAfterMillis() const { return lastRetryAfter_; }

  // HTTP status of the last transport reply in the pass (0 when the pass never
  // got a reply — a timeout/error, or no transport).
  int lastStatus() const { return lastStatus_; }

  // Body length the last transport reply delivered, in bytes (0 when there was
  // no reply). Distinct from `received`: `received` is the count the image
  // verification used, while this is the raw seam report, kept for diagnostics.
  size_t lastContentLength() const { return lastContentLength_; }

  // Transport GETs issued since construction (offer + image attempts).
  size_t attempts() const { return attempts_; }

  // Kind of the most recent pass, for callers that keep state rather than the
  // returned value.
  OtaResult::Kind lastResult() const { return reason_; }

 private:
  // The core pipeline: parse `offerJson`, and on an update fetch + verify +
  // flash. Shared by run() and runWithOffer() so there is exactly one place
  // where the flash sink can be reached.
  OtaResult processOffer(const char* offerJson);

  // Buffer the image named by `offer` from ZERO into image_, enforcing the
  // size ceiling. Reports how many bytes were received. Returns false on a
  // transport failure; that is distinct from a short read (which returns true
  // with a short `*received` and is caught by the size check).
  bool downloadImage(const OtaOffer& offer, uint32_t* received);

  uint32_t readClock() const {
    return clock_ == 0 ? 0u : static_cast<uint32_t>(clock_());
  }

  // Bounded NUL-terminating copy into a fixed record field. A null source
  // yields an empty string, so an unset field is never a stale or truncated
  // pointer. Shared by lastVerification()/makeVerification() so both spell the
  // bound the same way.
  static void copyInto(char* out, size_t outLen, const char* src) {
    if (out == 0 || outLen == 0) return;
    if (src == 0) {
      out[0] = '\0';
      return;
    }
    size_t i = 0;
    for (; i + 1 < outLen && src[i] != '\0'; ++i) {
      out[i] = src[i];
    }
    out[i] = '\0';
  }

  InsightTransport* transport_;
  FlashSink flash_;
  Clock clock_;
  RetryAfterSource retryAfter_;
  Sha256 hasher_;

  // Signed-image seam. `verifySignature_ == 0` means "no key on this device":
  // the signature fields are ignored. See setSignatureVerifier().
  SignatureVerifier verifySignature_;
  bool requireSignature_;

  size_t maxImage_;

  uint32_t nowMillis_;
  uint32_t nextAttemptAtMillis_;
  size_t attempts_;
  int lastStatus_;
  size_t lastContentLength_;
  uint32_t lastRetryAfter_;
  OtaResult::Kind reason_;

  // Signature outcome of the last pass, plus the offer fields it acted on, so
  // lastVerification() can hand back a self-contained record. These are reset
  // at the top of every processOffer() so one pass can never report a previous
  // pass's signature.
  bool lastSignatureChecked_;
  bool lastSignatureOk_;
  char lastOfferVersion_[64];
  char lastOfferSignature_[129];
  char lastOfferPubkeyId_[65];
  char lastComputedSha256_[65];
  uint32_t lastOfferSize_;
  uint32_t lastReceived_;

  // Staging buffer for the whole image. Sized by the compiled ceiling so the
  // class needs no heap; setMaxImageSize() narrows the usable prefix without
  // changing the footprint.
  uint8_t image_[INSIGHT_OTA_MAX_IMAGE];
};

}  // namespace insight

#endif  // INSIGHT_OTA_H
