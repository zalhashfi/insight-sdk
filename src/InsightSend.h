#ifndef INSIGHT_SEND_H
#define INSIGHT_SEND_H

#include <cstddef>
#include <cstdint>

#include "InsightBuffer.h"
#include "InsightReliability.h"
#include "InsightTransport.h"

namespace insight {

// Endpoint a flush POSTs to, locked to the frozen telemetry route so the
// policy, the contract test and the server cannot drift apart.
inline const char* sendPath() { return "/v1/telemetry"; }

// Capacity of the JSON body buffer (including the NUL terminator) a flush
// serialises through. A body that would not fit is never sent truncated: the
// entry is kept and retried rather than posting a half-written document.
#ifndef INSIGHT_SEND_JSON_MAX
#define INSIGHT_SEND_JSON_MAX 512
#endif

// Capacity of the resident retry-state mirror. The mirror tracks the buffer's
// own FIFO order one-for-one (see stateAt()/noteAccepted()), so a correctly
// configured client needs at most one slot per queued entry. It is sized to the
// buffer's documented capacity ceiling; each slot is four bytes.
#ifndef INSIGHT_SEND_STATE_SLOTS
#define INSIGHT_SEND_STATE_SLOTS 256
#endif

// The send/flush policy: the client's decision layer over the buffer, the
// transport and the reliability classifier. It owns none of the three — they
// are installed as seams, so tests drive the whole policy with a scripted
// transport and firmware reuses exactly the code the tests pin.
//
//   send(key, value) -> bool
//     Validate a sample and queue it in the buffer. `true` = accepted
//     (queued); `false` = rejected (bad key, NaN/Inf value, no buffer). The
//     verdict is the buffer's, passed straight through, so "rejected" means
//     nothing was stored and no counter moved. send() never touches the
//     transport: buffering and transmitting are deliberately separate, so a
//     sample can be captured at full rate without waiting on the network.
//
//   flush(nowMillis)
//     Walk the entries that were queued when the pass began, oldest ->
//     newest, attempting each through the transport and classifying the result
//     with decide():
//
//       * Success (2xx)             -> the entry is REMOVED from the buffer.
//       * Retry (5xx/408/429/       -> the entry is KEPT and its next attempt
//               timeout/error)         is scheduled at now + backoffMillis();
//                                      it is NOT sent again this pass, and —
//                                      the point of the class — NOTHING IS
//                                      SLEPT ON: the wait is recorded, not
//                                      waited.
//       * Discard (other 4xx,       -> the entry is REMOVED and the dropped
//                  1xx/3xx/0)          counter is incremented. Never retried.
//
//     flush() is NON-BLOCKING: it never waits for time to pass, never calls
//     delay()/sleep(), and returns as soon as the pass reaches a retryable
//     failure (or the end of the queue). It is therefore safe to call from
//     loop() without starving a watchdog. The caller re-calls
//     flush(nowMillis) once nextAttemptAtMillis() is reached.
//
// Scheduling is non-blocking by construction. A retryable failure at `now`
// records `nextAttemptAtMillis = now + backoffMillis(attempt)`; the earliest
// such deadline (0 when nothing is pending) is readable as
// nextAttemptAtMillis(), so a caller drives the client sleep-free with
//
//   if (client.isReady(millis())) client.flush(millis());
//
// and a test asserts the exact schedule — and the exact duration a blocking
// implementation would have slept — instead of ever observing a delay().
class InsightSend {
 public:
  InsightSend()
      : buffer_(0), transport_(0), path_(sendPath()), nowMillis_(0),
        nextAttemptAtMillis_(0), sent_(0), dropped_(0), attempts_(0),
        lastStatus_(0), lastBackoff_(0), head_(0), count_(0) {}

  // --- transport seam ---------------------------------------------------

  // Install the transport flush() sends through. Does not take ownership;
  // null detaches it. With no transport every attempt reports a
  // transport-level error, so decide() retries it and nothing is lost.
  void setTransport(InsightTransport* transport) { transport_ = transport; }
  InsightTransport* transport() const { return transport_; }

  // --- buffer seam ------------------------------------------------------

  // Install the buffer send() queues into and flush() drains. Does not take
  // ownership; null models an unconfigured client, where send() accepts
  // nothing and flush() has nothing to do.
  void setBuffer(InsightBuffer* buffer) { buffer_ = buffer; }
  InsightBuffer* buffer() const { return buffer_; }

  // Path the flush POSTs to. Null (or empty) disables transmission: a flush
  // then keeps every entry rather than sending to an unknown route.
  void setPath(const char* path) { path_ = path; }
  const char* path() const { return path_; }

  // --- sending ----------------------------------------------------------

  // Validate `key`/`value` and queue the sample. Returns true when it was
  // accepted (queued), false when it was rejected — a bad key, a NaN or
  // +/-Inf value, or no buffer installed. An accepted new sample is clear to
  // transmit, so it re-arms the schedule for "now".
  bool send(const char* key, float value) { return accept(key, value, false); }

  // As send(key, value), for the explicit-null reading. Always accepted when a
  // buffer is installed and the key is valid.
  bool send(const char* key, MetricValue value) {
    return accept(key, value.value, !value.hasValue);
  }

  // --- flushing ---------------------------------------------------------

  // One non-blocking pass. Returns the number of entries that left the buffer
  // (accepted by the server, or discarded as permanent). Entries that must be
  // retried stay queued and are scheduled, not slept on. See the class comment.
  size_t flush(uint32_t nowMillis) {
    nowMillis_ = nowMillis;
    lastStatus_ = 0;
    lastBackoff_ = 0;
    if (buffer_ == 0) {
      nextAttemptAtMillis_ = 0;
      return 0;
    }

    resync();  // Keep the state mirror aligned with the buffer before walking.
    nextAttemptAtMillis_ = 0;  // Rebuild the deadline set for this pass.

    // Consider exactly the entries queued now: samples added mid-pass wait for
    // the next flush(). Reading each index fresh keeps the walk correct even
    // when the buffer's last-wins dedup overwrites a slot not yet reached.
    size_t queued = buffer_->size();
    size_t removed = 0;
    size_t i = 0;

    while (i < queued) {
      BufferEntryView entry;
      if (!buffer_->at(i, &entry)) {
        ++i;  // Raced with a concurrent push; nothing to send here.
        continue;
      }

      const State state = stateAt(i);

      // Not yet due: carry the entry — and its attempt count — forward without
      // disturbing it, and remember its deadline for the caller.
      if (state.attempts > 0 && state.nextAttemptAtMillis > nowMillis) {
        addDeadline(state.nextAttemptAtMillis);
        ++i;
        continue;
      }

      HttpOutcome outcome = postAttempt(body(entry, entry.value, entry.null));
      ++attempts_;
      lastStatus_ = outcome.status;

      switch (decide(outcome)) {
        case Decision::Success:
          removeAt(i);
          ++sent_;
          --queued;  // One fewer entry; `i` now indexes the shifted tail.
          ++removed;
          break;

        case Decision::Discard:
          removeAt(i);
          ++dropped_;
          --queued;
          ++removed;
          break;

        case Decision::Retry:
          // Transient: keep the entry; schedule, do not wait. End the pass so
          // the caller regains control immediately.
          lastBackoff_ = backoffMillis(state.attempts);
          states_[head_].attempts = state.attempts + 1;
          states_[head_].nextAttemptAtMillis = nowMillis + lastBackoff_;
          addDeadline(states_[head_].nextAttemptAtMillis);
          return removed;
      }
    }
    return removed;
  }

  // --- inspection -------------------------------------------------------

  // Wall-clock stamp handed to the last flush(), in millis() terms.
  uint32_t now() const { return nowMillis_; }

  // Earliest millis() at which a queued entry is due again, or 0 when nothing
  // is pending. This is the non-blocking schedule: a caller (or a test)
  // compares it against millis() instead of sleeping.
  uint32_t nextAttemptAtMillis() const { return nextAttemptAtMillis_; }

  // True when a queued entry is due at `nowMillis`. With no pending retry the
  // answer is true, so a caller loops with
  // `if (client.isReady(millis())) client.flush(millis());`.
  bool isReady(uint32_t nowMillis) const {
    return nextAttemptAtMillis_ == 0 || nowMillis >= nextAttemptAtMillis_;
  }

  // Samples accepted by the server (2xx) since construction.
  size_t sent() const { return sent_; }

  // Samples discarded as permanently rejected (other 4xx, 1xx/3xx/0).
  size_t dropped() const { return dropped_; }

  // Transport attempts made since construction.
  size_t attempts() const { return attempts_; }

  // HTTP status of the last attempt (0 for a timeout/error; no reply).
  int lastStatus() const { return lastStatus_; }

  // Millisecond duration the last retryable failure would have slept for had
  // this policy been allowed to block — exposed precisely so a test can assert
  // it is RETURNED and never consumed. 0 after a non-retryable outcome.
  uint32_t lastBackoffMillis() const { return lastBackoff_; }

 private:
  static const size_t kSlots = INSIGHT_SEND_STATE_SLOTS;

  // Retry bookkeeping for one queue position. Four bytes; no side effects.
  struct State {
    uint32_t attempts;             // 0-based count of failed attempts so far
    uint32_t nextAttemptAtMillis;  // millis() at which the next try is due
  };

  bool accept(const char* key, float value, bool isNull) {
    if (buffer_ == 0) return false;
    const size_t before = buffer_->size();
    const bool ok = isNull ? buffer_->push(key, MetricValue::null())
                           : buffer_->push(key, value);
    if (!ok) return false;

    // A brand-new key appends a slot at the tail; a duplicate key (same size)
    // keeps its position and shifts nothing, so the mirror stays aligned.
    if (buffer_->size() > before) noteAccepted();
    nextAttemptAtMillis_ = 0;  // A fresh sample is due immediately.
    return true;
  }

  void noteAccepted() {
    states_[(head_ + count_) % kSlots].attempts = 0;
    states_[(head_ + count_) % kSlots].nextAttemptAtMillis = 0;
    if (count_ < kSlots) ++count_;
  }

  // Snapshot of the mirror as a State for a logical queue position.
  State stateAt(size_t logical) const {
    if (count_ == 0) {
      State empty;
      empty.attempts = 0;
      empty.nextAttemptAtMillis = 0;
      return empty;
    }
    const size_t idx = logical < count_ ? logical : count_ - 1;
    return states_[(head_ + idx) % kSlots];
  }

  void addDeadline(uint32_t candidate) {
    if (candidate == 0) return;
    if (nextAttemptAtMillis_ == 0 || candidate < nextAttemptAtMillis_) {
      nextAttemptAtMillis_ = candidate;
    }
  }

  // Remove the live entry at logical `index` and its matching mirror slot, so
  // the entries after it shift left in both rings and stay aligned. Used by
  // flush() on Success/Discard, which may land on any index (a not-yet-due
  // entry can precede a due one, so the removal is not always the head).
  void removeAt(size_t index) {
    dropBufferEntryAt(index);
    if (count_ > 0 && index < count_) {
      // Shift the mirror slots after `index` one position towards the head.
      for (size_t k = index; k + 1 < count_; ++k) {
        states_[(head_ + k) % kSlots] = states_[(head_ + k + 1) % kSlots];
      }
      const size_t last = (head_ + count_ - 1) % kSlots;
      states_[last].attempts = 0;
      states_[last].nextAttemptAtMillis = 0;
      --count_;
    }
    // The pass-level deadline set is managed by flush() (reset once at entry,
    // re-seeded by every entry that is skipped as not-yet-due), so removal must
    // not clear it: a pending head that precedes the removed entry keeps its
    // deadline visible for the caller.
  }

  // Remove buffer entry `index` using only the buffer's public seam: snapshot
  // every entry except that one, clear, then re-push them in order. Bounded by
  // the queue size and free of any time wait.
  void dropBufferEntryAt(size_t index) {
    if (buffer_ == 0) return;
    const size_t n = buffer_->size();
    if (index >= n) return;

    // Snapshot every field before mutating: a borrow dies on the first push().
    char keys_[INSIGHT_SEND_STATE_SLOTS][INSIGHT_BUFFER_KEY_MAX + 1];
    float values_[INSIGHT_SEND_STATE_SLOTS];
    bool nulls_[INSIGHT_SEND_STATE_SLOTS];
    size_t kept = 0;
    for (size_t k = 0; k < n && kept < kSlots; ++k) {
      if (k == index) continue;
      BufferEntryView v;
      if (!buffer_->at(k, &v)) break;
      size_t len = v.keyLen;
      if (len > INSIGHT_BUFFER_KEY_MAX) len = INSIGHT_BUFFER_KEY_MAX;
      for (size_t c = 0; c < len; ++c) keys_[kept][c] = v.key[c];
      keys_[kept][len] = '\0';
      values_[kept] = v.value;
      nulls_[kept] = v.null;
      ++kept;
    }

    buffer_->clear();
    for (size_t k = 0; k < kept; ++k) {
      if (nulls_[k]) {
        buffer_->push(keys_[k], MetricValue::null());
      } else {
        buffer_->push(keys_[k], values_[k]);
      }
    }
  }

  // Align the mirror with the buffer's current size. Keeps the invariant
  // count_ == buffer_->size() for clients that manipulate the buffer directly
  // (or install it after samples were queued).
  void resync() {
    if (buffer_ == 0) {
      head_ = 0;
      count_ = 0;
      return;
    }
    const size_t size = buffer_->size();
    if (size > count_) {
      for (size_t k = count_; k < size && count_ < kSlots; ++k) noteAccepted();
    } else if (size < count_) {
      const size_t drop = count_ - size;
      for (size_t k = 0; k < drop; ++k) {
        states_[head_].attempts = 0;
        states_[head_].nextAttemptAtMillis = 0;
        head_ = (head_ + 1) % kSlots;
        if (count_ > 0) --count_;
      }
    }
  }

  // Serialise one entry into body_ and return it, ready for postJson().
  const char* body(const BufferEntryView& entry, float value, bool isNull) {
    size_t n = 0;
    append("{\"key\":\"", n);
    append(entry.key, n);
    append(isNull ? "\",\"value\":null}" : "\",\"value\":", n);
    if (!isNull) appendFloat(value, n);
    body_[n < sizeof(body_) ? n : sizeof(body_) - 1] = '\0';
    return body_;
  }

  // Attempt `json` through the transport. With no transport (or no path) the
  // request cannot be made at all, which is a transport-level error by
  // classification — decide() retries it, so nothing is lost.
  HttpOutcome postAttempt(const char* json) {
    if (transport_ == 0 || path_ == 0 || path_[0] == '\0') {
      return HttpOutcome::error();
    }
    return transport_->postJson(path_, json);
  }

  void append(const char* s, size_t& n) {
    while (s != 0 && *s != '\0' && n + 1 < sizeof(body_)) body_[n++] = *s++;
  }

  void appendFloat(float v, size_t& n) {
    if (v < 0.0f) {
      append("-", n);
      v = -v;
    }
    const unsigned long ip = static_cast<unsigned long>(v);
    appendULong(ip, n);
    float frac = v - static_cast<float>(ip);
    if (frac > 0.0f) {
      append(".", n);
      for (int d = 0; d < 3 && frac > 0.0f && n + 1 < sizeof(body_); ++d) {
        frac *= 10.0f;
        int digit = static_cast<int>(frac);
        if (digit < 0) digit = 0;
        if (digit > 9) digit = 9;
        body_[n++] = static_cast<char>('0' + digit);
        frac -= static_cast<float>(digit);
      }
    }
  }

  void appendULong(unsigned long v, size_t& n) {
    char tmp[24];
    size_t len = 0;
    if (v == 0) {
      tmp[len++] = '0';
    } else {
      while (v > 0 && len < sizeof(tmp)) {
        tmp[len++] = static_cast<char>('0' + (v % 10));
        v /= 10;
      }
    }
    while (len > 0 && n + 1 < sizeof(body_)) body_[n++] = tmp[--len];
  }

  InsightBuffer* buffer_;
  InsightTransport* transport_;
  const char* path_;

  uint32_t nowMillis_;
  uint32_t nextAttemptAtMillis_;

  size_t sent_;
  size_t dropped_;
  size_t attempts_;
  int lastStatus_;
  uint32_t lastBackoff_;

  size_t head_;   // mirror head (oldest slot)
  size_t count_;  // number of live mirror slots

  State states_[kSlots];
  char body_[INSIGHT_SEND_JSON_MAX];
};

}  // namespace insight

#endif  // INSIGHT_SEND_H
