#ifndef INSIGHT_CONTROL_H
#define INSIGHT_CONTROL_H

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "InsightDevice.h"
#include "InsightReliability.h"
#include "InsightTransport.h"

namespace insight {

// ---------------------------------------------------------------------------
// The frozen downlink routes (spec §6.2/§6.3)
// ---------------------------------------------------------------------------
//
// Two paths, byte-for-byte identical to the contract lock
// (`insight/test/contracts/contract-lock.ts`, `GET_CONTROL.path` /
// `POST_CONTROL_ACK.path`). A device polls the first to learn what a project is
// asking of it and reports onto the second once it has acted. Both live here as
// single sources of truth so the policy, the tests and the server cannot drift.
inline const char* controlPath() { return "/v1/control"; }
inline const char* controlAckPath() { return "/v1/control/ack"; }

// Capacity of the buffer a `GET /v1/control` body is read into. The seam hands
// the whole body back at once (there is no streaming), so this is the largest
// envelope the parser will ever see; a body that would not fit is a transport
// failure, never a half-parsed command list.
#ifndef INSIGHT_CONTROL_BODY_MAX
#define INSIGHT_CONTROL_BODY_MAX 1024
#endif

// Most commands one poll will retain. A `GET /v1/control` answer is an array of
// `{id,variable,value}` objects; the device acts on them and acks them by id, so
// the list only needs to be bounded, not unbounded — anything past this cap is
// dropped with the list still reported as parseable (see ControlBatch::truncated).
#ifndef INSIGHT_CONTROL_MAX_COMMANDS
#define INSIGHT_CONTROL_MAX_COMMANDS 16
#endif

// Longest command id retained, in bytes (excluding the NUL terminator). Ids are
// opaque server tokens; this is the RAM guard that keeps one from overrunning
// the fixed-size slot it is copied into.
#ifndef INSIGHT_CONTROL_ID_MAX
#define INSIGHT_CONTROL_ID_MAX 48
#endif

// Longest variable name retained, in bytes (excluding the NUL terminator).
#ifndef INSIGHT_CONTROL_VARIABLE_MAX
#define INSIGHT_CONTROL_VARIABLE_MAX 32
#endif

// Longest command value retained, in bytes (excluding the NUL terminator). The
// wire value is a JSON string; a `null` value is a distinct flag, never "".
#ifndef INSIGHT_CONTROL_VALUE_MAX
#define INSIGHT_CONTROL_VALUE_MAX 64
#endif

// ---------------------------------------------------------------------------
// One parsed command
// ---------------------------------------------------------------------------

// A single `{ "id", "variable", "value" }` element of a `GET /v1/control`
// answer, exactly the three fields the frozen contract names
// (`CONTROL_COMMAND_FIELDS`). The `id` is what an ack carries back, so an empty
// id is never produced: a command whose id is missing or empty makes the whole
// parse fail rather than yielding something the device would then be unable to
// acknowledge.
struct ControlCommand {
  char id[INSIGHT_CONTROL_ID_MAX + 1];
  char variable[INSIGHT_CONTROL_VARIABLE_MAX + 1];
  char value[INSIGHT_CONTROL_VALUE_MAX + 1];
  bool valueIsNull;  // true => the wire value was JSON `null`

  ControlCommand() : valueIsNull(false) {
    id[0] = '\0';
    variable[0] = '\0';
    value[0] = '\0';
  }
};

// ---------------------------------------------------------------------------
// The parsed answer to one poll
// ---------------------------------------------------------------------------

// The result of parsing a `GET /v1/control` body:
//
//   `{ "control": [ { "id", "variable", "value" } ] }`
//
// `valid` is the single gate a caller must consult before touching `commands`:
// a malformed envelope — no `control` key, a scalar where the array must be, an
// element without an id — leaves `valid == false` and `count == 0`. An empty
// array (`{"control":[]}`) is deliberately VALID with `count == 0`: "the project
// asks nothing of you" is a well-formed answer, not a parse failure, and a
// device that conflated the two would either act on garbage or alarm forever.
//
// `truncated` is set when the body held more commands than the fixed slot array
// can hold. The batch is still `valid` — the commands that fit are real and
// actioned — but a caller that cares about the cap can see it was hit.
struct ControlBatch {
  // True when the envelope parsed; the gate before touching `commands`.
  bool valid;
  // Number of valid entries in `commands` (0 when !valid).
  size_t count;
  // True when the body held more commands than `commands` could hold.
  bool truncated;
  // The parsed commands, newest policy first, at most INSIGHT_CONTROL_MAX_COMMANDS.
  ControlCommand commands[INSIGHT_CONTROL_MAX_COMMANDS];

  // Construct an empty, invalid batch (the "nothing parsed yet" state).
  ControlBatch() : valid(false), count(0), truncated(false) {}
};

// ---------------------------------------------------------------------------
// Poll → execute → ack: the downlink policy
// ---------------------------------------------------------------------------
//
// The device half of downlink control. It owns a transport seam (never the
// transport itself) and nothing else: it holds no commands between calls except
// the ids it has already acked, which is exactly the state FR-CTL-02 needs to
// make an ack idempotent from the device's own side.
//
//   poll()
//     GET /v1/control and parse the envelope into a caller-supplied batch
//     (see poll(ControlBatch*)). A non-2xx status, a timeout, a transport error
//     or a body that overflows the read buffer all report `ok == false` and
//     leave the batch unmodified (invalid, empty) — a device never acts on a
//     partial answer. An empty command list is a SUCCESS with `count == 0`.
//
//   ack(ids, count)
//     POST `{"ids":[...]}` to /v1/control/ack. Idempotent from the device's own
//     view: ids already acked are filtered out, so a repeated ack of the same
//     set is (a) not re-sent when nothing new remains and (b) never carries a
//     duplicate. The server is idempotent too (spec §6.3), but relying on that
//     alone would make every retry a round trip; the resident acked-id mirror
//     means a re-ack after a LOST 204 costs nothing until the server has
//     confirmed it, which is the case the mirror does NOT suppress — see
//     ack()'s return contract.
//
// The class is non-blocking: no delay()/sleep() anywhere. A transport failure on
// the poll is simply reported, so a caller drives it on a cadence from loop().
class InsightControl {
 public:
  InsightControl()
      : transport_(0), polls_(0), acks_(0), lastStatus_(0),
        lastContentLength_(0), nextIndex_(0), ackedCount_(0) {}

  // --- transport seam ---------------------------------------------------

  // Install the transport poll()/ack() go through. Does not take ownership;
  // null detaches it, which turns every attempt into a transport-level failure
  // rather than a crash.
  void setTransport(InsightTransport* transport) { transport_ = transport; }
  InsightTransport* transport() const { return transport_; }

  // --- polling ----------------------------------------------------------

  // GET `path` (default /v1/control, or the installed override), parse it into
  // `batch`, and report whether a usable answer arrived. On success the batch is
  // replaced; on any failure it is left invalid and empty. `batch` must not be
  // null.
  bool poll(ControlBatch* batch, const char* path = controlPath()) {
    if (batch == 0) return false;
    *batch = ControlBatch();
    if (transport_ == 0 || path == 0 || path[0] == '\0') return false;

    char body[INSIGHT_CONTROL_BODY_MAX];
    std::memset(body, 0, sizeof(body));
    size_t bodyLen = 0;
    ++polls_;
    const HttpOutcome outcome =
        transport_->get(path, body, sizeof(body), &bodyLen);

    lastStatus_ = outcome.status;
    lastContentLength_ =
        outcome.kind == HttpOutcome::Ok ? bodyLen : 0;
    if (outcome.kind != HttpOutcome::Ok) return false;
    if (outcome.status < 200 || outcome.status >= 300) return false;

    // Defensive: keep the parse bounded even if a seam forgot the terminator.
    body[sizeof(body) - 1] = '\0';
    if (!parseControlBody(body, batch)) {
      *batch = ControlBatch();
      return false;
    }
    nextIndex_ = 0;  // a fresh answer is walked from its first command
    return true;
  }

  // Pull the next un-acked command out of `batch`, oldest first, into `out`.
  // Returns false once every command in the batch has been either returned by a
  // earlier call or acked already (so a poll followed by repeated nextCommand()
  // calls walks the list exactly once). This is the "execute" half of the loop:
  // the caller runs the command, then acks its id.
  bool nextCommand(const ControlBatch& batch, ControlCommand* out) {
    if (out == 0) return false;
    for (size_t i = nextIndex_; i < batch.count; ++i) {
      if (isAcked(batch.commands[i].id)) continue;
      nextIndex_ = i + 1;
      *out = batch.commands[i];
      return true;
    }
    nextIndex_ = batch.count;
    return false;
  }

  // Restart nextCommand()'s walk from the start of `batch`. Called
  // automatically by poll(); exposed so a caller that keeps a batch across a
  // failed execution can re-walk it.
  void rewind() { nextIndex_ = 0; }

  // --- acknowledgement --------------------------------------------------

  // POST `{"ids":[ids[0],...]}` to `path` (default /v1/control/ack). Ids already
  // acked on this device are filtered out first, so:
  //
  //   * a repeated ack of a set with nothing new in it sends NOTHING and
  //     returns true — the idempotent no-op (no second round trip);
  //   * a set with new ids sends only those ids, never a duplicate;
  //   * on a 2xx the ids sent are recorded, so a later re-ack is the no-op
  //     above. On a non-2xx/transport failure the ids are NOT recorded, so a
  //     retry re-sends them — the server idempotency (§6.3) makes that safe,
  //     and dropping the ack would leave the command pending forever.
  //
  // Returns true when there is nothing left to acknowledge (including the
  // all-filtered and empty cases) or the POST was accepted (2xx). Returns false
  // only when a POST was attempted and was not accepted.
  bool ack(const char* const* ids, size_t count,
           const char* path = controlAckPath()) {
    if (ids == 0 || count == 0) return true;
    if (transport_ == 0 || path == 0 || path[0] == '\0') return false;

    // Build the body from the not-yet-acked ids only.
    char body[INSIGHT_CONTROL_ACK_BODY_MAX];
    size_t n = 0;
    append("{\"ids\":[", body, n);
    size_t fresh = 0;
    for (size_t i = 0; i < count; ++i) {
      const char* id = ids[i];
      if (id == 0 || id[0] == '\0') continue;
      if (isAcked(id)) continue;  // idempotent: never re-send a known id
      if (n + 8 >= INSIGHT_CONTROL_ACK_BODY_MAX) break;  // room for `"]}` + NUL
      if (fresh > 0) append(",", body, n);
      append("\"", body, n);
      append(id, body, n);
      append("\"", body, n);
      ++fresh;
    }
    append("]}", body, n);
    body[n < sizeof(body) ? n : sizeof(body) - 1] = '\0';

    if (fresh == 0) return true;  // everything was already acked: a no-op

    ++acks_;
    const HttpOutcome outcome = transport_->postJson(path, body);
    lastStatus_ = outcome.status;
    if (outcome.kind != HttpOutcome::Ok) return false;
    if (outcome.status < 200 || outcome.status >= 300) return false;

    // Record only now, once the server has accepted. Recording optimistically
    // would swallow a retry after a lost 204 and strand the command.
    for (size_t i = 0; i < count; ++i) {
      const char* id = ids[i];
      if (id == 0 || id[0] == '\0') continue;
      remember(id);
    }
    return true;
  }

  // Convenience: ack a single id. Returns true when nothing needed sending or
  // the ack was accepted; false when a POST was attempted and rejected.
  bool ack(const char* id) {
    const char* one[1];
    one[0] = id;
    return ack(one, 1);
  }

  // True once `id` has been acknowledged (and the server accepted).
  bool isAcked(const char* id) const {
    if (id == 0 || id[0] == '\0') return false;
    for (size_t i = 0; i < ackedCount_; ++i) {
      if (std::strcmp(acked_[i], id) == 0) return true;
    }
    return false;
  }

  // --- inspection -------------------------------------------------------

  // HTTP status of the last poll/ack attempt (0 when no reply).
  int lastStatus() const { return lastStatus_; }

  // Body byte count the last poll delivered (0 when there was no reply).
  size_t lastContentLength() const { return lastContentLength_; }

  // Control GETs issued since construction.
  size_t polls() const { return polls_; }

  // Ack POSTs issued since construction (filtered/no-op acks are not counted,
  // so a re-ack of an already-acked set leaves this unchanged).
  size_t acks() const { return acks_; }

  // Distinct ids currently remembered as acked.
  size_t ackedCount() const { return ackedCount_; }

 private:
  // Resident acked-id mirror. Rolling: ids past this many distinct acks are
  // forgotten (and would be re-acked once against the idempotent server); a
  // project polling a device every few seconds will not approach it in steady
  // state. Sized to keep the object heap-free.
  static const size_t kMaxAcked = 32;
  // Fixed capacity of the ack request body. `{"ids":[...]}` with up to a few
  // dozen ids; an id set that would overflow is sent in the prefix that fits,
  // and the remainder re-sent on the next call (the server is idempotent).
  static const size_t INSIGHT_CONTROL_ACK_BODY_MAX = 512;

  void remember(const char* id) {
    if (id == 0 || id[0] == '\0') return;
    if (ackedCount_ < kMaxAcked) {
      copyBounded(acked_[ackedCount_], sizeof(acked_[ackedCount_]), id);
      ++ackedCount_;
      return;
    }
    // Full: overwrite the oldest slot (a rolling window), keeping it valid.
    for (size_t i = 0; i + 1 < kMaxAcked; ++i) {
      copyBounded(acked_[i], sizeof(acked_[i]), acked_[i + 1]);
    }
    copyBounded(acked_[kMaxAcked - 1], sizeof(acked_[kMaxAcked - 1]), id);
  }

  // --- JSON scan (structural-lite, no library) --------------------------
  //
  // The SDK carries no JSON library by design. The envelope is shallow and its
  // shape is frozen, so a bounded scan over the known keys is sufficient — and
  // it is what keeps the parser provable on the host. Every helper below is
  // pure and never reads past the NUL terminator.

  static const char* skipWs(const char* p) {
    while (p != 0 && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
      ++p;
    }
    return p;
  }

  // Find `"name"` as a complete key at or after `from`, returning a pointer to
  // the value that follows its colon, or 0. A key must be preceded by `{` or a
  // `,` (after optional whitespace) so a name can never be matched inside a
  // string VALUE — the `"value"` inside a command's variable name must not be
  // read as the field. This mirrors InsightOta.cpp's `findField` exactly.
  static const char* findField(const char* from, const char* name) {
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

  static bool isNull(const char* p) {
    return p != 0 && std::strncmp(p, "null", 4) == 0;
  }

  // Parse a JSON string starting at the opening quote into `out` (capacity
  // `outLen`, always NUL-terminated). Handles `\"`, `\\` and `\/`; other escapes
  // copy the following byte (enough for ids/variables/values). Returns a pointer
  // past the closing quote, or 0 on a malformed string.
  static const char* parseString(const char* p, char* out, size_t outLen) {
    if (p == 0 || *p != '"' || outLen == 0) return 0;
    ++p;
    size_t n = 0;
    while (*p != '\0' && *p != '"') {
      char ch = *p;
      if (ch == '\\') {
        const char next = *(p + 1);
        if (next == '\0') return 0;
        ch = next;
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

  // Advance past a complete JSON value beginning at `p` (a string, object,
  // array, literal or number). Strings are skipped with escape handling so a `}`
  // or `]` inside a value cannot end the scan early. Returns the position just
  // past the value, or 0 when it is malformed/unterminated.
  static const char* skipValue(const char* p) {
    if (p == 0) return 0;
    p = skipWs(p);
    if (*p == '"') return skipString(p);
    if (*p == '{' || *p == '[') {
      const char open = *p;
      const char close = (open == '{') ? '}' : ']';
      int depth = 0;
      while (*p != '\0') {
        if (*p == '"') {
          p = skipString(p);
          if (p == 0) return 0;
          continue;
        }
        if (*p == open) ++depth;
        if (*p == close) {
          --depth;
          ++p;
          if (depth == 0) return p;
          continue;
        }
        ++p;
      }
      return 0;
    }
    // Literal / number: consume until a structural delimiter.
    while (*p != '\0' && *p != ',' && *p != '}' && *p != ']') ++p;
    return p;
  }

  // Skip a complete JSON string beginning at the opening quote, honoring
  // escapes. Returns the position past the closing quote, or 0.
  static const char* skipString(const char* p) {
    if (p == 0 || *p != '"') return 0;
    ++p;
    while (*p != '\0' && *p != '"') {
      if (*p == '\\' && *(p + 1) != '\0') {
        p += 2;
      } else {
        ++p;
      }
    }
    if (*p != '"') return 0;
    return p + 1;
  }

  // Parse one `{"id","variable","value"}` object starting at `{` into `out`.
  // The id is mandatory and non-empty (a command the device could not ack is
  // not a command); `variable` is mandatory; `value` may be a string or JSON
  // null (which sets valueIsNull). Returns a pointer just past the object, or 0
  // on a malformed element.
  static const char* parseCommand(const char* p, ControlCommand* out) {
    if (p == 0 || *p != '{') return 0;
    *out = ControlCommand();

    const char* id = findField(p, "id");
    const char* variable = findField(p, "variable");
    const char* value = findField(p, "value");
    if (id == 0 || variable == 0) return 0;

    if (parseString(id, out->id, sizeof(out->id)) == 0) return 0;
    if (out->id[0] == '\0') return 0;  // an unackable command is malformed
    if (parseString(variable, out->variable, sizeof(out->variable)) == 0) {
      return 0;
    }

    if (value != 0) {
      if (isNull(value)) {
        out->valueIsNull = true;
        out->value[0] = '\0';
      } else if (*value == '"') {
        if (parseString(value, out->value, sizeof(out->value)) == 0) return 0;
      } else {
        // A non-string, non-null value (number/bool): copy its literal text.
        size_t n = 0;
        while (value[n] != '\0' && value[n] != ',' && value[n] != '}' &&
               n + 1 < sizeof(out->value)) {
          out->value[n] = value[n];
          ++n;
        }
        out->value[n] = '\0';
      }
    }

    // Walk past the object so the caller can continue the array walk.
    return skipValue(p);
  }

  // Parse a whole `{"control":[...]}` body into `batch`. Returns true when the
  // envelope is well-formed (including the empty-array answer).
  static bool parseControlBody(const char* json, ControlBatch* batch) {
    if (json == 0 || batch == 0) return false;
    const char* control = findField(json, "control");
    if (control == 0) return false;
    if (*control != '[') return false;  // `control` must be an array

    const char* p = control + 1;
    for (;;) {
      p = skipWs(p);
      if (*p == ']') {
        batch->valid = true;
        return true;
      }
      if (*p == '\0') return false;  // unterminated array
      if (*p != '{') return false;   // an array of commands only holds objects

      ControlCommand command;
      const char* after = parseCommand(p, &command);
      if (after == 0) return false;

      if (batch->count < INSIGHT_CONTROL_MAX_COMMANDS) {
        batch->commands[batch->count] = command;
        ++batch->count;
      } else {
        batch->truncated = true;
      }

      p = skipWs(after);
      if (*p == ',') {
        ++p;
        continue;
      }
      if (*p == ']') {
        batch->valid = true;
        return true;
      }
      return false;  // expected `,` or `]`
    }
  }

  // --- small string helpers --------------------------------------------

  static void append(const char* s, char* dst, size_t& n) {
    while (s != 0 && *s != '\0' && n + 1 < INSIGHT_CONTROL_ACK_BODY_MAX) {
      dst[n++] = *s++;
    }
  }

  static void copyBounded(char* dst, size_t dstLen, const char* src) {
    if (dst == 0 || dstLen == 0) return;
    size_t i = 0;
    for (; i + 1 < dstLen && src != 0 && src[i] != '\0'; ++i) dst[i] = src[i];
    dst[i] = '\0';
  }

  InsightTransport* transport_;

  size_t polls_;
  size_t acks_;
  int lastStatus_;
  size_t lastContentLength_;
  size_t nextIndex_;

  char acked_[kMaxAcked][INSIGHT_CONTROL_ID_MAX + 1];
  size_t ackedCount_;
};

}  // namespace insight

#endif  // INSIGHT_CONTROL_H
