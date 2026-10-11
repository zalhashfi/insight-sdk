// Downlink control + ACK test for the insight-sdk (PlatformIO native).
//
// Exercises the poll -> execute -> ack loop over a FAKE transport, so the whole
// policy is proven on the host with no network and no hardware (spec §6.2/§6.3,
// FR-CTL-01/02). What is pinned here:
//
//   * GET /v1/control returns commands; the SDK parses `{control:[{id,
//     variable,value}]}` into a batch and hands them out one at a time.
//   * ACK posts `{"ids":[...]}` to /v1/control/ack — the frozen request shape
//     and the frozen path.
//   * ACKing the same id twice is a NO-OP the second time: nothing is sent, so
//     a device that re-acks never repeats a round trip.
//   * A command that has been ACKed is no longer offered — a later poll of a
//     server that still lists it (because the ack was in flight) does not hand
//     it back.
//   * The failure paths: a non-2xx / timeout / malformed body yields no batch;
//     an empty array is a valid "nothing to do" answer.

#include <unity.h>

#include <cstring>

#include "InsightControl.h"
#include "InsightTransport.h"

// ---------------------------------------------------------------------------
// Fake transport: a tiny scripted control server.
//
// It answers GET /v1/control with the currently-pending command list and
// records every POST /v1/control/ack body, so the test can assert both what the
// device parsed and exactly what it put on the wire.
// ---------------------------------------------------------------------------
class FakeControlServer : public insight::InsightTransport {
 public:
  // The JSON body GET /v1/control answers with. Defaults to "no commands".
  const char* pendingBody = "{\"control\":[]}";
  insight::HttpOutcome getResult = insight::HttpOutcome::ok(200);

  // Scripted ack outcome. Defaults to the frozen `204`.
  insight::HttpOutcome ackResult = insight::HttpOutcome::ok(204);

  // When true the fake behaves like the real server: an acked command is no
  // longer listed. Set false to hand back a STALE list (as if an ack were still
  // in flight) and prove the device itself never re-offers an acked id.
  bool honorAcks = true;

  // Recording.
  int getCount = 0;
  int postCount = 0;
  char lastGetPath[64] = {0};
  char lastPostPath[64] = {0};
  char lastPostBody[512] = {0};

  // The ids this fake currently considers ACKed (so a subsequent poll omits
  // them, mirroring the server's own "acked commands are gone" rule).
  char ackedIds[16][64];
  int ackedCount = 0;

  insight::HttpOutcome get(const char* path, char* buffer, size_t bufferLen,
                           size_t* contentLength) override {
    ++getCount;
    std::strncpy(lastGetPath, path, sizeof(lastGetPath) - 1);
    if (getResult.kind == insight::HttpOutcome::Ok) {
      const char* body = honorAcks ? bodyExcludingAcked() : pendingBody;
      const size_t len = std::strlen(body);
      if (bufferLen > 0) {
        const size_t n = len < bufferLen - 1 ? len : bufferLen - 1;
        std::memcpy(buffer, body, n);
        buffer[n] = '\0';
        if (contentLength != 0) *contentLength = n;
      }
    }
    return getResult;
  }

  insight::HttpOutcome postJson(const char* path, const char* json) override {
    ++postCount;
    std::strncpy(lastPostPath, path, sizeof(lastPostPath) - 1);
    std::strncpy(lastPostBody, json, sizeof(lastPostBody) - 1);
    if (ackResult.kind == insight::HttpOutcome::Ok &&
        ackResult.status >= 200 && ackResult.status < 300) {
      captureIds(json);
    }
    return ackResult;
  }

  // Did this fake (the "server") ever receive an ack for `id`?
  bool serverSawAck(const char* id) const {
    for (int i = 0; i < ackedCount; ++i) {
      if (std::strcmp(ackedIds[i], id) == 0) return true;
    }
    return false;
  }

 private:
  // Build the pending body, dropping any command whose id was acked. The list
  // is small and the fixtures are short, so a string scan is enough; the point
  // is that an acked command is never handed back.
  const char* bodyExcludingAcked() {
    if (ackedCount == 0) return pendingBody;

    static char filtered[512];
    filtered[0] = '\0';
    // Fast path: if no acked id appears in the body, answer verbatim.
    bool anyPresent = false;
    for (int i = 0; i < ackedCount; ++i) {
      if (std::strstr(pendingBody, ackedIds[i]) != 0) {
        anyPresent = true;
        break;
      }
    }
    if (!anyPresent) return pendingBody;

    // Rebuild the array, keeping whole `{...}` elements whose id is not acked.
    const char* open = std::strchr(pendingBody, '[');
    if (open == 0) return pendingBody;
    size_t n = 0;
    appendLiteral(filtered, n, "{\"control\":[");
    const char* p = open + 1;
    bool first = true;
    while (*p != '\0' && *p != ']') {
      const char* brace = std::strchr(p, '{');
      if (brace == 0) break;
      const char* end = std::strchr(brace, '}');
      if (end == 0) break;
      const size_t elemLen = static_cast<size_t>(end - brace) + 1;

      char element[96];
      const size_t copy = elemLen < sizeof(element) - 1 ? elemLen : sizeof(element) - 1;
      std::memcpy(element, brace, copy);
      element[copy] = '\0';

      bool drop = false;
      for (int i = 0; i < ackedCount; ++i) {
        if (std::strstr(element, ackedIds[i]) != 0) {
          drop = true;
          break;
        }
      }
      if (!drop) {
        if (!first) appendLiteral(filtered, n, ",");
        appendLiteral(filtered, n, element);
        first = false;
      }
      p = end + 1;
    }
    appendLiteral(filtered, n, "]}");
    return filtered;
  }

  static void appendLiteral(char* dst, size_t& n, const char* s) {
    while (s != 0 && *s != '\0' && n + 1 < 512) dst[n++] = *s++;
    dst[n] = '\0';
  }

  // Extract the string ids from an `{"ids":["a","b"]}` body into ackedIds.
  void captureIds(const char* json) {
    const char* p = std::strchr(json, '[');
    if (p == 0) return;
    ++p;
    while (*p != '\0' && *p != ']') {
      if (*p == '"') {
        ++p;
        size_t n = 0;
        while (*p != '\0' && *p != '"' && n < 63) ackedIds[ackedCount][n++] = *p++;
        ackedIds[ackedCount][n] = '\0';
        if (*p == '"') ++p;
        if (n > 0 && ackedCount < 15) ++ackedCount;
      } else {
        ++p;
      }
    }
  }
};

void setUp(void) {}

void tearDown(void) {}

// ---------------------------------------------------------------------------
// Poll: GET /v1/control returns commands, parsed into a batch
// ---------------------------------------------------------------------------

void test_poll_returns_commands(void) {
  FakeControlServer server;
  server.pendingBody =
      "{\"control\":[{\"id\":\"c_1\",\"variable\":\"led\",\"value\":\"1\"},"
      "{\"id\":\"c_2\",\"variable\":\"interval\",\"value\":\"30\"}]}";

  insight::InsightControl control;
  control.setTransport(&server);

  insight::ControlBatch batch;
  TEST_ASSERT_TRUE(control.poll(&batch));

  TEST_ASSERT_TRUE(batch.valid);
  TEST_ASSERT_EQUAL_INT(2, batch.count);
  TEST_ASSERT_EQUAL_INT(1, server.getCount);
  TEST_ASSERT_EQUAL_STRING("/v1/control", server.lastGetPath);

  TEST_ASSERT_EQUAL_STRING("c_1", batch.commands[0].id);
  TEST_ASSERT_EQUAL_STRING("led", batch.commands[0].variable);
  TEST_ASSERT_EQUAL_STRING("1", batch.commands[0].value);
  TEST_ASSERT_FALSE(batch.commands[0].valueIsNull);

  TEST_ASSERT_EQUAL_STRING("c_2", batch.commands[1].id);
  TEST_ASSERT_EQUAL_STRING("interval", batch.commands[1].variable);
  TEST_ASSERT_EQUAL_STRING("30", batch.commands[1].value);
}

// An empty array is a VALID "nothing to do" answer, not a parse failure.
void test_poll_empty_is_valid_and_empty(void) {
  FakeControlServer server;
  server.pendingBody = "{\"control\":[]}";

  insight::InsightControl control;
  control.setTransport(&server);

  insight::ControlBatch batch;
  TEST_ASSERT_TRUE(control.poll(&batch));
  TEST_ASSERT_TRUE(batch.valid);
  TEST_ASSERT_EQUAL_INT(0, batch.count);
}

// A `null` value is surfaced as a null command value, distinct from "".
void test_poll_null_value_is_flagged(void) {
  FakeControlServer server;
  server.pendingBody =
      "{\"control\":[{\"id\":\"c_9\",\"variable\":\"active\",\"value\":null}]}";

  insight::InsightControl control;
  control.setTransport(&server);

  insight::ControlBatch batch;
  TEST_ASSERT_TRUE(control.poll(&batch));
  TEST_ASSERT_EQUAL_INT(1, batch.count);
  TEST_ASSERT_TRUE(batch.commands[0].valueIsNull);
  TEST_ASSERT_EQUAL_STRING("", batch.commands[0].value);
}

// A malformed body is NOT a batch: the device must not act on half an answer.
void test_poll_malformed_body_is_invalid(void) {
  FakeControlServer server;
  insight::InsightControl control;
  control.setTransport(&server);

  const char* bad[] = {
      "not json at all",
      "{\"control\":{}}",                       // object where array required
      "{\"other\":[]}",                         // no control key
      "{\"control\":[{\"variable\":\"x\"}]}",   // element without an id
      "{\"control\":[{\"id\":\"\",\"variable\":\"x\"}]}",  // empty id
      "{\"control\":[{\"id\":\"c_1\"}]}"        // element without a variable
  };

  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
    server.pendingBody = bad[i];
    insight::ControlBatch batch;
    TEST_ASSERT_FALSE_MESSAGE(control.poll(&batch), bad[i]);
    TEST_ASSERT_FALSE(batch.valid);
    TEST_ASSERT_EQUAL_INT(0, batch.count);
  }
}

// A non-2xx status, a timeout and a transport error all yield no batch.
void test_poll_failure_paths(void) {
  FakeControlServer server;
  server.pendingBody = "{\"control\":[{\"id\":\"c_1\",\"variable\":\"v\",\"value\":\"1\"}]}";
  insight::InsightControl control;
  control.setTransport(&server);

  const insight::HttpOutcome outcomes[] = {
      insight::HttpOutcome::ok(401),
      insight::HttpOutcome::ok(500),
      insight::HttpOutcome::timeout(),
      insight::HttpOutcome::error(),
  };
  for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); ++i) {
    server.getResult = outcomes[i];
    insight::ControlBatch batch;
    TEST_ASSERT_FALSE(control.poll(&batch));
    TEST_ASSERT_FALSE(batch.valid);
    TEST_ASSERT_EQUAL_INT(0, batch.count);
  }

  // With no transport at all the poll fails cleanly rather than crashing.
  insight::InsightControl detached;
  insight::ControlBatch batch;
  TEST_ASSERT_FALSE(detached.poll(&batch));
}

// nextCommand() walks the batch exactly once, oldest first.
void test_next_command_walks_once(void) {
  FakeControlServer server;
  server.pendingBody =
      "{\"control\":[{\"id\":\"c_1\",\"variable\":\"a\",\"value\":\"1\"},"
      "{\"id\":\"c_2\",\"variable\":\"b\",\"value\":\"2\"}]}";

  insight::InsightControl control;
  control.setTransport(&server);
  insight::ControlBatch batch;
  TEST_ASSERT_TRUE(control.poll(&batch));

  insight::ControlCommand command;
  TEST_ASSERT_TRUE(control.nextCommand(batch, &command));
  TEST_ASSERT_EQUAL_STRING("c_1", command.id);
  TEST_ASSERT_TRUE(control.nextCommand(batch, &command));
  TEST_ASSERT_EQUAL_STRING("c_2", command.id);
  TEST_ASSERT_FALSE(control.nextCommand(batch, &command));
}

// ---------------------------------------------------------------------------
// ACK: POST {"ids":[...]} to /v1/control/ack
// ---------------------------------------------------------------------------

void test_ack_posts_ids_to_frozen_path(void) {
  FakeControlServer server;
  server.pendingBody = "{\"control\":[{\"id\":\"c_1\",\"variable\":\"led\",\"value\":\"1\"}]}";

  insight::InsightControl control;
  control.setTransport(&server);
  insight::ControlBatch batch;
  TEST_ASSERT_TRUE(control.poll(&batch));

  TEST_ASSERT_TRUE(control.ack(batch.commands[0].id));
  TEST_ASSERT_EQUAL_INT(1, server.postCount);
  TEST_ASSERT_EQUAL_STRING("/v1/control/ack", server.lastPostPath);
  TEST_ASSERT_EQUAL_STRING("{\"ids\":[\"c_1\"]}", server.lastPostBody);
  TEST_ASSERT_TRUE(server.serverSawAck("c_1"));
  TEST_ASSERT_TRUE(control.isAcked("c_1"));
}

// ACKing the SAME id twice is a no-op: the second call sends nothing.
void test_ack_same_id_twice_is_noop(void) {
  FakeControlServer server;
  insight::InsightControl control;
  control.setTransport(&server);

  TEST_ASSERT_TRUE(control.ack("c_1"));
  TEST_ASSERT_EQUAL_INT(1, server.postCount);

  // Re-ack the very same id: idempotent, so no second round trip.
  TEST_ASSERT_TRUE(control.ack("c_1"));
  TEST_ASSERT_EQUAL_INT(1, server.postCount);  // unchanged — the no-op
  TEST_ASSERT_EQUAL_INT(1, control.ackedCount());
}

// A batch ack with a mix of new and already-acked ids sends only the new ones.
void test_ack_filters_already_acked(void) {
  FakeControlServer server;
  insight::InsightControl control;
  control.setTransport(&server);

  TEST_ASSERT_TRUE(control.ack("c_1"));
  TEST_ASSERT_EQUAL_INT(1, server.postCount);

  const char* ids[3];
  ids[0] = "c_1";  // already acked
  ids[1] = "c_2";  // new
  ids[2] = "c_3";  // new
  TEST_ASSERT_TRUE(control.ack(ids, 3));
  TEST_ASSERT_EQUAL_INT(2, server.postCount);
  TEST_ASSERT_EQUAL_STRING("{\"ids\":[\"c_2\",\"c_3\"]}", server.lastPostBody);

  // All-acked set: nothing new, so nothing is sent and it still returns true.
  TEST_ASSERT_TRUE(control.ack(ids, 3));
  TEST_ASSERT_EQUAL_INT(2, server.postCount);
}

// None of the ids went through when the server rejected the ack, so a retry is
// allowed (the server's own idempotency makes the repeat safe).
void test_ack_failure_is_retried_not_remembered(void) {
  FakeControlServer server;
  server.ackResult = insight::HttpOutcome::ok(500);
  insight::InsightControl control;
  control.setTransport(&server);

  TEST_ASSERT_FALSE(control.ack("c_1"));
  TEST_ASSERT_FALSE(control.isAcked("c_1"));  // not recorded on a failure
  TEST_ASSERT_EQUAL_INT(1, server.postCount);

  server.ackResult = insight::HttpOutcome::ok(204);
  TEST_ASSERT_TRUE(control.ack("c_1"));  // retried
  TEST_ASSERT_EQUAL_INT(2, server.postCount);
  TEST_ASSERT_TRUE(control.isAcked("c_1"));
}

// ---------------------------------------------------------------------------
// End to end: poll -> execute -> ack, then an acked command is not re-offered
// ---------------------------------------------------------------------------

void test_poll_execute_ack_stops_reoffering(void) {
  FakeControlServer server;
  server.pendingBody =
      "{\"control\":[{\"id\":\"c_1\",\"variable\":\"led\",\"value\":\"1\"},"
      "{\"id\":\"c_2\",\"variable\":\"interval\",\"value\":\"30\"}]}";

  insight::InsightControl control;
  control.setTransport(&server);

  // Poll #1: two commands; execute each, collect its id, then ack the batch.
  insight::ControlBatch batch;
  TEST_ASSERT_TRUE(control.poll(&batch));
  TEST_ASSERT_EQUAL_INT(2, batch.count);

  insight::ControlCommand command;
  char idStore[2][64];
  const char* ackedIds[2];
  size_t executed = 0;
  while (control.nextCommand(batch, &command)) {
    // Execute locally, then keep a COPY of the id to acknowledge (the walk
    // hands the same `command` object back each time).
    std::strncpy(idStore[executed], command.id, sizeof(idStore[executed]) - 1);
    idStore[executed][sizeof(idStore[executed]) - 1] = '\0';
    ackedIds[executed] = idStore[executed];
    ++executed;
  }
  TEST_ASSERT_EQUAL_INT(2, executed);

  TEST_ASSERT_TRUE(control.ack(ackedIds, executed));
  TEST_ASSERT_EQUAL_INT(1, server.postCount);
  TEST_ASSERT_EQUAL_STRING("{\"ids\":[\"c_1\",\"c_2\"]}", server.lastPostBody);

  // Poll #2: the server no longer offers the acked commands.
  TEST_ASSERT_TRUE(control.poll(&batch));
  TEST_ASSERT_TRUE(batch.valid);
  TEST_ASSERT_EQUAL_INT(0, batch.count);
  TEST_ASSERT_FALSE(control.nextCommand(batch, &command));

  // Even if a STALE answer still listed them (an ack in flight), the device
  // itself never re-offers an id it has already acknowledged.
  server.honorAcks = false;
  server.pendingBody =
      "{\"control\":[{\"id\":\"c_1\",\"variable\":\"led\",\"value\":\"1\"}]}";
  TEST_ASSERT_TRUE(control.poll(&batch));
  TEST_ASSERT_EQUAL_INT(1, batch.count);  // the command is still IN the batch...
  TEST_ASSERT_FALSE(control.nextCommand(batch, &command));  // ...but never offered
}

// A second, unrelated command still flows after a first is acked.
void test_new_command_after_ack_still_offered(void) {
  FakeControlServer server;
  server.pendingBody = "{\"control\":[{\"id\":\"c_1\",\"variable\":\"led\",\"value\":\"1\"}]}";

  insight::InsightControl control;
  control.setTransport(&server);
  insight::ControlBatch batch;
  TEST_ASSERT_TRUE(control.poll(&batch));
  TEST_ASSERT_TRUE(control.ack("c_1"));

  server.pendingBody = "{\"control\":[{\"id\":\"c_7\",\"variable\":\"led\",\"value\":\"0\"}]}";
  TEST_ASSERT_TRUE(control.poll(&batch));
  TEST_ASSERT_EQUAL_INT(1, batch.count);

  insight::ControlCommand command;
  TEST_ASSERT_TRUE(control.nextCommand(batch, &command));
  TEST_ASSERT_EQUAL_STRING("c_7", command.id);
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_poll_returns_commands);
  RUN_TEST(test_poll_empty_is_valid_and_empty);
  RUN_TEST(test_poll_null_value_is_flagged);
  RUN_TEST(test_poll_malformed_body_is_invalid);
  RUN_TEST(test_poll_failure_paths);
  RUN_TEST(test_next_command_walks_once);
  RUN_TEST(test_ack_posts_ids_to_frozen_path);
  RUN_TEST(test_ack_same_id_twice_is_noop);
  RUN_TEST(test_ack_filters_already_acked);
  RUN_TEST(test_ack_failure_is_retried_not_remembered);
  RUN_TEST(test_poll_execute_ack_stops_reoffering);
  RUN_TEST(test_new_command_after_ack_still_offered);
  return UNITY_END();
}
