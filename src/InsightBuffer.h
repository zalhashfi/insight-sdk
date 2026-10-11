#ifndef INSIGHT_BUFFER_H
#define INSIGHT_BUFFER_H

#include <cstddef>

#ifndef INSIGHT_BUFFER_KEY_MAX
// Longest metric key accepted, in bytes (excluding the NUL terminator).
#define INSIGHT_BUFFER_KEY_MAX 32
#endif

#ifndef INSIGHT_BUFFER_CAP
// Largest capacity setBufferSize() will honour. The buffer is a fixed-size
// ring allocated up front, so a capacity is also a RAM budget; this ceiling
// keeps a bad config from asking a device for an unreasonable amount.
#define INSIGHT_BUFFER_CAP 256
#endif

// Byte offsets inside a BufferEntry slot. `value` is a float, so it is aligned
// up from the end of the key; the layout is asserted at the bottom of this
// header against a compiler-laid-out witness struct.
#define INSIGHT_BUFFER_KEY_BYTES (INSIGHT_BUFFER_KEY_MAX + 1)
#define INSIGHT_BUFFER_VALUE_OFFSET (((INSIGHT_BUFFER_KEY_BYTES) + 3) & ~3u)
#define INSIGHT_BUFFER_NULL_OFFSET (INSIGHT_BUFFER_VALUE_OFFSET + 4)

namespace insight {

// A metric value is either a number or an explicit "no reading" sentinel.
// We deliberately do NOT overload `float` itself: NaN is rejected as a
// numeric value (see push()), so "null" gets its own flag rather than
// borrowing a magic float the server would have to interpret.
struct MetricValue {
  float value;    // meaningful only when hasValue is true
  bool hasValue;  // false => JSON null: a reading that does not exist

  MetricValue() : value(0.0f), hasValue(false) {}
  MetricValue(float v) : value(v), hasValue(true) {}

  static MetricValue null() { return MetricValue(); }
};

// One queued sample for a metric key.
//   - `key` is a NUL-terminated copy of the pushed key (validated on push).
//   - `null` mirrors MetricValue::hasValue inverted, for readability at the
//     call site (`if (entry.null) ...`).
struct BufferEntry {
  char key[INSIGHT_BUFFER_KEY_MAX + 1];
  float value;
  bool null;
};

// A byte-bounded, borrowable view of one entry, handed out by at()/oldest()/
// oldestEntryView(). The view points into the buffer's own storage, so it is
// valid until the next push()/clear()/setBufferSize() on that buffer.
struct BufferEntryView {
  const char* key;
  size_t keyLen;
  float value;
  bool null;
};

// Fixed-capacity RAM FIFO of metric samples.
//
// Semantics (locked by test/test_buffer):
//   * Ordering is FIFO: at() walks oldest -> newest.
//   * setBufferSize(n) sets the capacity, default 200, clamped to
//     [0, INSIGHT_BUFFER_CAP]. When at capacity, a push() drops the OLDEST
//     entry to make room and increments dropped() by one. Lowering the size
//     evicts the oldest entries immediately (each counts as dropped).
//   * n == 0 disables buffering: every push() succeeds (returns true) but
//     nothing is retained — size() stays 0 and dropped() is NOT incremented,
//     because a disabled buffer discards a whole stream by design rather
//     than shedding individual samples under pressure.
//   * Last-wins per key: pushing a key already queued overwrites that
//     entry's value IN PLACE and does not change the entry's queue position,
//     so a key occupies at most one slot at a time.
//
// push() returns true when the sample was accepted (i.e. it was valid), and
// false when it was rejected. Rejection is total: no storage, no eviction,
// no dropped()/rejected() counter moves. Validation rules:
//   * key must be non-null, non-empty, and at most INSIGHT_BUFFER_KEY_MAX
//     bytes long (rejected with rejected()++).
//   * a non-null (numeric) value must be finite: NaN and +/-Inf are rejected
//     (rejected()++). push(key, MetricValue::null()) is always accepted.
class InsightBuffer {
 public:
  // Longest key accepted by push(). Longer keys are rejected.
  static const size_t kMaxKeyLen = INSIGHT_BUFFER_KEY_MAX;
  // Default capacity applied by the constructor.
  static const size_t kDefaultSize = 200;

  InsightBuffer() : capacity_(kDefaultSize), size_(0), head_(0), dropped_(0), rejected_(0) {
    setBufferSize(kDefaultSize);
  }

  // Set the ring capacity, clamped to [0, kMaxCapacity]. Shrinking below the
  // current size evicts the oldest entries (dropped()++ per eviction) and
  // keeps the newest `capacity_` samples. Growing preserves everything
  // already queued.
  void setBufferSize(size_t n) {
    if (n > kMaxCapacity) n = kMaxCapacity;
    const size_t kept = (n < size_) ? n : size_;
    const size_t evicted = size_ - kept;
    char* base = storage();
    const size_t head = head_;
    const size_t cap = capacity_;
    // Copy the newest `kept` entries to the front of the logical order. A
    // temporary byte buffer breaks the aliasing between read and write slots
    // when source and destination index coincide at a non-zero offset.
    for (size_t i = 0; i < kept; ++i) {
      char* dst = base + i * kSlotStride;
      const char* src = base + ((head + evicted + i) % cap) * kSlotStride;
      if (dst != src) {
        char tmp[kSlotStride];
        copyEntry(tmp, src);
        copyEntry(dst, tmp);
      }
    }
    dropped_ += evicted;
    capacity_ = n;
    size_ = kept;
    head_ = 0;
  }

  // Current capacity (0 disables buffering).
  size_t capacity() const { return capacity_; }

  // Number of samples currently queued (0 when buffering is disabled).
  size_t size() const { return size_; }

  // Entries evicted to make room, since construction.
  size_t dropped() const { return dropped_; }

  // Pushes rejected by validation (bad key / non-finite value), since
  // construction.
  size_t rejected() const { return rejected_; }

  // Accept `key` with a numeric value. Rejects NaN/Inf and invalid keys.
  bool push(const char* key, float value) {
    return pushValue(key, value, false);
  }

  // Accept `key` with an explicit null value (a reading that is absent).
  bool push(const char* key, MetricValue v) {
    return pushValue(key, v.value, !v.hasValue);
  }

  // Oldest -> newest random access; 0-based. Returns false when out of range.
  bool at(size_t index, BufferEntryView* out) const {
    if (index >= size_ || out == 0) return false;
    const char* p = storage() + ((head_ + index) % capacity_) * kSlotStride;
    out->key = p;
    out->keyLen = static_cast<size_t>(keyLengthAt(p));
    const float* v = valueAt(p);
    out->value = *v;
    out->null = *nullAt(p);
    return true;
  }

  // Oldest entry, or the same empty view when the buffer is empty.
  BufferEntryView oldest() const {
    BufferEntryView view;
    if (size_ == 0) {
      view.key = "";
      view.keyLen = 0;
      view.value = 0.0f;
      view.null = false;
      return view;
    }
    at(0, &view);
    return view;
  }

  // Newest entry, or the same empty view when the buffer is empty.
  BufferEntryView newest() const {
    BufferEntryView view;
    if (size_ == 0) {
      view.key = "";
      view.keyLen = 0;
      view.value = 0.0f;
      view.null = false;
      return view;
    }
    at(size_ - 1, &view);
    return view;
  }

  // Current value of `key`, or false when the key is not queued. On success
  // `*out` receives the stored value (including the null sentinel).
  bool get(const char* key, MetricValue* out) const {
    if (key == 0 || out == 0) return false;
    const int idx = indexOf(key);
    if (idx < 0) return false;
    BufferEntryView view;
    at(static_cast<size_t>(idx), &view);
    out->value = view.value;
    out->hasValue = !view.null;
    return true;
  }

  // Drain oldest -> newest, invoking `visitor(view)` for each queued entry.
  // Afterwards the buffer is empty (size() == 0); dropped()/rejected() are
  // cumulative and are left untouched. Pass a null function pointer to
  // discard everything without a visitor.
  template <typename Visitor>
  void drain(Visitor* visitor) {
    for (size_t i = 0; i < size_; ++i) {
      BufferEntryView view;
      at(i, &view);
      if (visitor) (*visitor)(view);
    }
    clear();
  }

  // Drop every queued entry without touching the cumulative counters.
  void clear() {
    size_ = 0;
    head_ = 0;
  }

 private:
  // Largest capacity setBufferSize() honours (see INSIGHT_BUFFER_CAP).
  static const size_t kMaxCapacity = INSIGHT_BUFFER_CAP;
  // Distance between consecutive slots in the raw ring storage.
  static const size_t kSlotStride = sizeof(BufferEntry);

  bool pushValue(const char* key, float value, bool isNull) {
    if (!isValidKey(key)) {
      ++rejected_;
      return false;
    }
    // NaN and +/-Inf cannot be serialised; reject rather than store a value
    // the server would choke on. null values skip the check entirely.
    if (!isNull && !isFinite(value)) {
      ++rejected_;
      return false;
    }

    const int existing = indexOf(key);
    if (existing >= 0) {
      // Last-wins: overwrite in place, keeping the original queue position.
      char* slot = slotAt(static_cast<size_t>(existing));
      writeValue(slot, value, isNull);
      return true;
    }

    if (capacity_ == 0) {
      // Buffering disabled: accept but do not retain (documented rule).
      return true;
    }

    if (size_ == capacity_) {
      // Full: overwrite the oldest slot (physical `head_`) with the new entry,
      // then advance the head past it. The head is already a physical ring
      // index, so it is used directly — routing it through slotAt() would
      // apply the head offset a second time.
      char* slot = physicalSlotAt(head_);
      writeValue(slot, value, isNull);
      writeKey(slot, key);
      head_ = (head_ + 1) % capacity_;
      ++dropped_;
      return true;
    }

    char* slot = physicalSlotAt((head_ + size_) % capacity_);
    writeValue(slot, value, isNull);
    writeKey(slot, key);
    ++size_;
    return true;
  }

  // Key must exist, be non-empty and fit within kMaxKeyLen bytes.
  // keyLengthWithin returns -1 for a key longer than the limit; that must be
  // an explicit `>= 0` test, since a bare `-1` would convert to `true`.
  static bool isValidKey(const char* key) {
    if (key == 0 || key[0] == '\0') return false;
    return keyLengthWithin(key, kMaxKeyLen + 1) >= 0;
  }

  // Index of `key` in logical order, or -1 when absent.
  int indexOf(const char* key) const {
    if (key == 0) return -1;
    for (size_t i = 0; i < size_; ++i) {
      const char* p = storage() + ((head_ + i) % capacity_) * kSlotStride;
      if (streq(p, key)) return static_cast<int>(i);
    }
    return -1;
  }

  // --- ring accessors ---------------------------------------------------
  // head_/size_/capacity_ are invariants of at(); callers must respect them.
  const char* storage() const {
    return reinterpret_cast<const char*>(ring_);
  }
  char* storage() { return reinterpret_cast<char*>(ring_); }
  char* slotAt(size_t logical) const {
    return const_cast<char*>(storage()) +
           ((head_ + logical) % capacity_) * kSlotStride;
  }
  // Physical slot by ring index (already reduced modulo capacity_).
  char* physicalSlotAt(size_t physical) const {
    return const_cast<char*>(storage()) + physical * kSlotStride;
  }

  // --- raw slot field accessors ----------------------------------------
  // These read/write plain bytes so the ring needs no reinterpret_cast of a
  // not-yet-constructed object (slot contents are controlled by push()).
  static size_t keyCapacity() { return kMaxKeyLen + 1; }
  static size_t valueOffset() { return INSIGHT_BUFFER_VALUE_OFFSET; }
  static size_t nullOffset() { return INSIGHT_BUFFER_NULL_OFFSET; }

  static const char* keyAt(const char* slot) { return slot; }
  static char* keyAt(char* slot) { return slot; }
  static int keyLengthAt(const char* slot) { return keyLengthWithin(slot, keyCapacity()); }
  static const float* valueAt(const char* slot) {
    return reinterpret_cast<const float*>(slot + valueOffset());
  }
  static float* valueAt(char* slot) {
    return reinterpret_cast<float*>(slot + valueOffset());
  }
  static const bool* nullAt(const char* slot) {
    return reinterpret_cast<const bool*>(slot + nullOffset());
  }
  static bool* nullAt(char* slot) {
    return reinterpret_cast<bool*>(slot + nullOffset());
  }

  static void writeKey(char* slot, const char* key) {
    char* dst = keyAt(slot);
    size_t i = 0;
    for (; key[i] != '\0' && i < kMaxKeyLen; ++i) dst[i] = key[i];
    dst[i] = '\0';
  }
  static void writeValue(char* slot, float value, bool isNull) {
    *valueAt(slot) = value;
    *nullAt(slot) = isNull;
  }
  static void copyEntry(char* dst, const char* src) {
    for (size_t i = 0; i < kMaxKeyLen + 1; ++i) dst[i] = src[i];
    *valueAt(dst) = *valueAt(src);
    *nullAt(dst) = *nullAt(src);
  }

  // --- tiny helpers (no <cstring>/<cmath> dependency) -------------------
  static bool streq(const char* a, const char* b) {
    size_t i = 0;
    for (; a[i] != '\0' && b[i] != '\0'; ++i) {
      if (a[i] != b[i]) return false;
    }
    return a[i] == b[i];
  }
  // Length of the NUL-terminated string, provided the terminator is found
  // within `limit` bytes (i.e. length < limit); -1 when overlong/unterminated.
  static int keyLengthWithin(const char* s, size_t limit) {
    for (size_t i = 0; i < limit; ++i) {
      if (s[i] == '\0') return static_cast<int>(i);
    }
    return -1;
  }
  // NaN/Inf test without <cmath>: NaN != itself; Inf has a saturated exponent.
  static bool isFinite(float v) {
    if (v != v) return false;  // NaN
    const float maxFloat = 3.4028234663852886e+38f;
    return v <= maxFloat && v >= -maxFloat;  // Inf fails both bounds
  }

  // Raw fixed-size ring. Stored as bytes so a slot can be written before any
  // BufferEntry constructor would have run; layout is asserted in the tests.
  unsigned char ring_[kMaxCapacity * sizeof(BufferEntry)];
  size_t capacity_;
  size_t size_;
  size_t head_;
  size_t dropped_;
  size_t rejected_;
};

}  // namespace insight

// The ring stores BufferEntry fields at hand-computed byte offsets (key at 0,
// then `value`, then `null`). `float` is 4-byte aligned, so the value field is
// *not* at keyLen+1 on every platform — the padding amount comes from the
// compiler's own layout of an identical struct. These assertions fail the
// build if that layout ever drifts from the offsets the buffer computes.
namespace insight {
namespace layout {
struct Witness {
  char key[INSIGHT_BUFFER_KEY_MAX + 1];
  float value;
  bool null;
};
static_assert(sizeof(Witness) == sizeof(BufferEntry),
              "BufferEntry layout drifted: size mismatch");
static_assert(offsetof(Witness, value) == INSIGHT_BUFFER_VALUE_OFFSET,
              "BufferEntry layout drifted: value offset");
static_assert(offsetof(Witness, null) == INSIGHT_BUFFER_NULL_OFFSET,
              "BufferEntry layout drifted: null offset");
}  // namespace layout
}  // namespace insight

#endif  // INSIGHT_BUFFER_H
