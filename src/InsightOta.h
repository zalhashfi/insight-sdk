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
  char version[64];
  char sha256[65];  // lowercase hex, 64 chars + NUL
  char url[256];
  uint32_t size;    // image length in bytes, as offered

  OtaOffer() : valid(false), hasUpdate(false), size(0) {
    version[0] = '\0';
    sha256[0] = '\0';
    url[0] = '\0';
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
//   Flashed           - size AND digest both matched; the image was handed to
//                       the flash sink EXACTLY once.
struct OtaResult {
  enum Kind {
    NoUpdate,
    InvalidOffer,
    UnsupportedSize,
    RateLimited,
    TransportFailure,
    SizeMismatch,
    HashMismatch,
    Flashed
  };

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

  OtaResult()
      : kind(TransportFailure), retry(false), received(0), retryAtMillis(0),
        retryAfterMillis(0) {
    computedSha256[0] = '\0';
  }

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

    typedef void (*Init)(void* ctx);
    typedef void (*Update)(void* ctx, const uint8_t* data, size_t len);
    typedef void (*Finalize)(void* ctx, uint8_t out[32]);

    Init init;
    Update update;
    Finalize finalize;

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

  InsightOta()
      : transport_(0), flash_(0), clock_(0), hasher_(),
        maxImage_(INSIGHT_OTA_MAX_IMAGE), nowMillis_(0), nextAttemptAtMillis_(0),
        attempts_(0), lastStatus_(0), lastContentLength_(0),
        lastRetryAfter_(0), reason_(OtaResult::NoUpdate) {
    hasher_ = builtInSha256();
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

  InsightTransport* transport_;
  FlashSink flash_;
  Clock clock_;
  Sha256 hasher_;

  size_t maxImage_;

  uint32_t nowMillis_;
  uint32_t nextAttemptAtMillis_;
  size_t attempts_;
  int lastStatus_;
  size_t lastContentLength_;
  uint32_t lastRetryAfter_;
  OtaResult::Kind reason_;

  // Staging buffer for the whole image. Sized by the compiled ceiling so the
  // class needs no heap; setMaxImageSize() narrows the usable prefix without
  // changing the footprint.
  uint8_t image_[INSIGHT_OTA_MAX_IMAGE];
};

// Inject the `retry-after` header value (whole seconds) that a 429 response
// carried. The transport seam surfaces only the status, not headers, so the
// header is supplied through this hook: firmware sets it from the response it
// just parsed, and tests set it directly. Passing a negative value clears it,
// which makes a 429 fall back to kOtaDefaultRetryAfterMillis. Defined in
// InsightOta.cpp.
void setOtaRetryAfterHeader(long seconds);

}  // namespace insight

#endif  // INSIGHT_OTA_H
