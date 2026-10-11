// Documentation-contract test for the insight-sdk (PlatformIO native).
//
// Ticket B15 (FR-SDK-11, NFR-MNT-06). Two rules are locked here, both by
// READING the shipped artefacts rather than trusting a reviewer's eye:
//
//   1. DOC-COVERAGE RULE — "every public declaration in a public header has a
//      preceding doc-comment."
//
//      The public headers are `src/Insight*.h`: the aggregate `Insight.h` and
//      the `Insight<Capability>.h` capability headers a sketch may include.
//      Implementation files (`*.cpp`) and the example sketches are out of
//      scope. The header set is enumerated by the `Insight*.h` naming
//      convention and each named file MUST open — a rename is a test failure,
//      never a silently skipped header.
//
//      A "doc-comment" is a `//` line-comment, or a `/* ... */` block, whose
//      LAST comment line sits on the line DIRECTLY above the declaration. Only
//      other comment lines and blank lines may separate the two, so a file
//      header comment (always followed by a blank line) never covers the first
//      declaration in a file. The doc-comment may be arbitrarily long — every
//      line of it must itself be a comment line.
//
//      A "public declaration" is a line at namespace scope, or in a `public:`
//      section of a class/struct, that introduces:
//        * a (template) class / struct / enum / union,
//        * an enum constant,
//        * a function or method declaration/definition — including a
//          constructor or destructor, and including a static data member with
//          an initialiser such as `static const size_t kMax = 4;`.
//      Lines are attributed to the LAST access specifier seen (`public:` /
//      `private:` / `protected:`), reset at each `};`. Members of a `private:`
//      or `protected:` section are not public API and are not required to
//      carry a doc-comment; in this SDK most of them carry a trailing `//`
//      note instead, which this rule deliberately does not count.
//
//      Statements inside an inline method body are not declarations and are
//      skipped: a line is only considered when it closes a declaration
//      (`;`/`{`/`}`/`:`/`,`) and does not start with a statement keyword
//      (`return`, `if`, `for`, ...). The body depth is tracked so a declaration
//      after an inline body — or after a nested block ending in `}` — is still
//      judged at its own level.
//
//   2. CHANGELOG RULE — the repository-root `CHANGELOG.md` has an entry for
//      the CURRENT version, where "current" is the string `insight::sdkVersion()`
//      reports. The test extracts that string from `src/Insight.h` (so the
//      literal is never duplicated here) and asserts `## [x.y.z]` appears in
//      the CHANGELOG. A release therefore cannot bump the version without
//      recording it.
//
// The scan is deliberately textual rather than a compiler AST: the SDK has no
// parser dependency (it must build for ESP8266 too), and the invariants being
// locked — "is this line documented" and "is this version recorded" — are
// exactly the textual facts a reviewer checks.

#include <unity.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

const size_t kMaxFileBytes = 128 * 1024;

// Read a whole file into `out` (NUL-terminated); returns the length, or
// `(size_t)-1` when the file cannot be opened or does not fit.
size_t readFile(const char* path, char* out, size_t capacity) {
  FILE* f = std::fopen(path, "rb");
  if (f == 0) return static_cast<size_t>(-1);
  size_t n = std::fread(out, 1, capacity - 1, f);
  const bool tooBig = n == capacity - 1 && std::fgetc(f) != EOF;
  std::fclose(f);
  if (tooBig) return static_cast<size_t>(-1);
  out[n] = '\0';
  return n;
}


// ---------------------------------------------------------------------------
// Tiny string helpers (no <string>)
// ---------------------------------------------------------------------------

size_t len(const char* s) {
  size_t n = 0;
  while (s != 0 && s[n] != '\0') ++n;
  return n;
}

bool startsWith(const char* s, const char* prefix) {
  for (size_t i = 0; prefix[i] != '\0'; ++i) {
    if (s[i] != prefix[i]) return false;
  }
  return true;
}

bool equals(const char* a, const char* b) {
  size_t i = 0;
  for (; a[i] != '\0' && b[i] != '\0'; ++i) {
    if (a[i] != b[i]) return false;
  }
  return a[i] == b[i];
}

void joinPath(char* out, size_t outSize, const char* dir, const char* name) {
  std::snprintf(out, outSize, "%s/%s", dir, name);
}

// Project root discovery, so the test does not depend on the working directory
// PlatformIO happens to launch the binary with. `PWD` is the directory `pio`
// was invoked from; `PROJECT_DIR` (when PlatformIO reports it unquoted) is the
// project root itself. Either is used as a starting point and walked upward
// until an `Insight*.h` names a real file — that is what makes the scan find
// `src/` and the repository-root `CHANGELOG.md` from a plain `pio test`, from
// an IDE, or from a direct run of the built binary.
const size_t kMaxRoots = 8;
const char* g_roots[kMaxRoots];
size_t g_rootCount = 0;

bool looksLikeProjectRoot(const char* dir) {
  char candidate[1024];
  joinPath(candidate, sizeof(candidate), dir, "src/Insight.h");
  FILE* f = std::fopen(candidate, "rb");
  if (f == 0) {
    joinPath(candidate, sizeof(candidate), dir, "Insight.h");
    f = std::fopen(candidate, "rb");
  }
  if (f == 0) return false;
  std::fclose(f);
  return true;
}

void addRoot(const char* dir) {
  if (dir == 0 || dir[0] == '\0') return;
  if (g_rootCount < kMaxRoots) g_roots[g_rootCount++] = dir;
}

const char* parentOf(const char* dir) {
  const size_t n = len(dir);
  if (n == 0) return 0;
  for (size_t i = n - 1; i > 0; --i) {
    if (dir[i] == '/' || dir[i] == '\\') return dir + i;  // includes separator
  }
  return 0;
}

bool resolveFromRoot(const char* root, const char* relative, char* out,
                     size_t outSize, char* text, size_t textSize,
                     size_t* length) {
  char candidate[1024];
  joinPath(candidate, sizeof(candidate), root, relative);
  *length = readFile(candidate, text, textSize);
  if (*length == static_cast<size_t>(-1)) return false;
  std::strncpy(out, candidate, outSize - 1);
  out[outSize - 1] = '\0';
  return true;
}

// Walk up from the launch directory until a root with `src/Insight.h` is found.
const char* projectRoot() {
  if (g_rootCount == 0) {
    char up[1024];
    const char* dir = std::getenv("PWD");
    if (dir != 0 && dir[0] != '\0') {
      std::strncpy(up, dir, sizeof(up) - 1);
      up[sizeof(up) - 1] = '\0';
      while (len(up) > 1) {
        if (looksLikeProjectRoot(up)) {
          addRoot(up);
          break;
        }
        const char* parent = parentOf(up);
        if (parent == 0) break;
        up[parent - up] = '\0';
      }
    }
    addRoot(std::getenv("PROJECT_DIR"));
  }
  return g_rootCount > 0 ? g_roots[0] : ".";
}

// Candidate roots, most specific first, for a possible fallback search.
void candidateRoots(const char* out[], size_t* count) {
  *count = 0;
  const char* env = std::getenv("PWD");
  if (env != 0 && env[0] != '\0') out[(*count)++] = env;
  out[(*count)++] = projectRoot();
  const char* project = std::getenv("PROJECT_DIR");
  if (project != 0 && project[0] != '\0') out[(*count)++] = project;
  out[(*count)++] = ".";
}

// Resolve a repository-relative path (e.g. "Insight.h" or "CHANGELOG.md") by
// trying, in order: the discovered project root with and without a `src/`
// prefix, then the same under every candidate root. The first hit wins.
bool resolveProjectFile(const char* relative, char* out, size_t outSize,
                        char* text, size_t textSize, size_t* length) {
  const char* roots[kMaxRoots + 4];
  size_t count = 0;
  candidateRoots(roots, &count);

  char underSrc[256];
  std::snprintf(underSrc, sizeof(underSrc), "src/%s", relative);

  for (size_t i = 0; i < count; ++i) {
    if (resolveFromRoot(roots[i], relative, out, outSize, text, textSize, length)) {
      return true;
    }
    if (resolveFromRoot(roots[i], underSrc, out, outSize, text, textSize, length)) {
      return true;
    }
  }
  std::snprintf(out, outSize, "%s/%s", projectRoot(), relative);
  return false;
}

// ---------------------------------------------------------------------------
// Char classification
// ---------------------------------------------------------------------------

bool isSpace(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

bool isIdentChar(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_';
}

bool isIdentStart(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

// ---------------------------------------------------------------------------
// Line indexing
// ---------------------------------------------------------------------------

struct Lines {
  char* start[8000];
  size_t length[8000];
  int count;
};

void splitLines(char* text, Lines* out) {
  out->count = 0;
  if (*text == '\0') return;
  char* p = text;
  while (*p != '\0') {
    char* begin = p;
    while (*p != '\0' && *p != '\n') ++p;
    // Line endings are mixed across this repo (some files are CRLF, some LF),
    // so a trailing '\r' is carriage-return mechanics, never content: dropping
    // it here is what keeps the "is the previous line a comment?" test from
    // seeing `\r` as the last non-space character. A lone '\r' inside a line
    // (old Mac endings) is not a concern for these sources.
    size_t n = static_cast<size_t>(p - begin);
    if (n > 0 && begin[n - 1] == '\r') --n;
    if (out->count < 8000) {
      out->start[out->count] = begin;
      out->length[out->count] = n;
      ++out->count;
    }
    if (*p == '\n') ++p;
  }
}

bool isBlank(const char* s, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (!isSpace(s[i])) return false;
  }
  return true;
}

// A comment-only line: `// ...`, `/* ...`, `* ...`, or `*/` with nothing but
// whitespace (or comment markers) before the marker. This also makes the
// continuation lines of a multi-line block comment count as comment lines, so
// a long doc-comment reads as one uninterrupted run.
bool isCommentOnly(const char* s, size_t n) {
  size_t i = 0;
  while (i < n && isSpace(s[i])) ++i;
  if (i >= n) return false;  // blank is not a comment
  if (s[i] == '/' && i + 1 < n && (s[i + 1] == '/' || s[i + 1] == '*')) {
    return true;
  }
  if (s[i] == '*') return true;  // block continuation / closing line
  return false;
}

// ---------------------------------------------------------------------------
// Declaration detection
// ---------------------------------------------------------------------------

// Keywords that begin a STATEMENT, never a declaration at namespace/class
// scope. Keeping the list tight is right: `static`/`const`/`inline` are
// omitted on purpose so that a `static const size_t k = 4;` member still has
// to be documented. `using`/`typedef` are included because an alias is not a
// member whose meaning needs a doc-comment — and this SDK has none in a public
// section anyway.
bool isStatementKeyword(const char* w, size_t n) {
  static const char* const kWords[] = {
      "return",        "if",      "else",     "for",        "while",
      "switch",        "break",   "continue", "do",         "case",
      "default",       "goto",    "delete",   "new",        "throw",
      "try",           "catch",   "typedef",  "using",      "namespace",
      "extern",        "sizeof",  "static_assert",
  };
  for (size_t i = 0; i < sizeof(kWords) / sizeof(kWords[0]); ++i) {
    if (len(kWords[i]) == n && std::strncmp(kWords[i], w, n) == 0) return true;
  }
  return false;
}

// A line introduces a declaration when its last significant character closes
// one: `;` (declaration), `{` (definition), `}` (inline body / init list),
// `:` (access specifier / base list), `,` (enum constant list).
char lastSignificant(const char* s, size_t n) {
  for (size_t i = n; i > 0; --i) {
    const char c = s[i - 1];
    if (!isSpace(c)) return c;
  }
  return '\0';
}

bool firstWord(const char* s, size_t n, char* out, size_t outSize) {
  size_t i = 0;
  while (i < n && isSpace(s[i])) ++i;
  if (i >= n || !isIdentStart(s[i])) return false;
  size_t j = 0;
  while (i < n && isIdentChar(s[i]) && j + 1 < outSize) out[j++] = s[i++];
  out[j] = '\0';
  return j > 0;
}

// A line that opens a type body: `class X {`, `struct X {`, `enum class E {`,
// `union U {` (light indentation tolerated).
bool isTypeOpening(const char* s) {
  size_t i = 0;
  while (i < 3 && s[i] != '\0' && isSpace(s[i])) ++i;
  const char* p = s + i;
  if (startsWith(p, "struct") && !isIdentChar(p[6])) return true;
  if (startsWith(p, "class") && !isIdentChar(p[5])) return true;
  if (startsWith(p, "union") && !isIdentChar(p[5])) return true;
  if (startsWith(p, "enum") && !isIdentChar(p[4])) return true;
  return false;
}

// First non-space character on a line (0 for a blank line).
const char* firstNonSpace(const char* s, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    if (!isSpace(s[i])) return s + i;
  }
  return 0;
}

// A line that opens an enum body (`enum Kind {`, `enum class TlsMode {`).
// Enum constants are members of the type, so the enum body is transparent for
// access purposes: the constants belong to the class that holds the enum.
bool isEnumOpening(const char* s) {
  size_t i = 0;
  while (i < 3 && s[i] != '\0' && isSpace(s[i])) ++i;
  const char* p = s + i;
  return startsWith(p, "enum") && !isIdentChar(p[4]);
}

// A line that opens a namespace body: `namespace insight {` or
// `namespace {` (anonymous). A namespace body is transparent — declarations
// inside it are at namespace scope, exactly like the file itself.
bool isNamespaceOpening(const char* s, size_t n) {
  const char* first = firstNonSpace(s, n);
  if (first == 0) return false;
  if (!startsWith(first, "namespace")) return false;
  if (isIdentChar(first[9])) return false;  // `namespacex`, not a namespace
  return lastSignificant(s, n) == '{';
}

// Does this line start with a statement keyword (so it cannot begin a
// declaration)? Used only to decide whether a `{` opens a function body.
bool isStatementKeywordLine(const char* s, size_t n) {
  char word[40];
  if (!firstWord(s, n, word, sizeof(word))) return false;
  return isStatementKeyword(word, len(word));
}

// Line-bounded `strstr`: lines are views into one buffer and are NOT
// NUL-terminated, so `std::strstr` would run past the end of a line into the
// rest of the file (which is how `INSIGHT_` in a later `#endif` comment used
// to make every declaration line look like a guard flag). This searches only
// `[s, s + n)`.
bool containsWithin(const char* s, size_t n, const char* needle) {
  const size_t m = len(needle);
  if (m == 0 || n < m) return false;
  for (size_t i = 0; i + m <= n; ++i) {
    if (std::strncmp(s + i, needle, m) == 0) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// The doc-coverage scan
//
// A declaration is judged at its OPENING LINE only. Continuation lines — an
// initialiser list (`: base(x),`), a second base/variable (`int a, b;`), the
// closing `};` of an enum or class, and the brace/depth bookkeeping that
// follows — belong to the declaration already judged and are never judged
// again. That is what keeps a doc-comment that describes one declaration from
// having to be repeated on every line it spans.
//
// The mechanism is `pending`: a declaration whose closing punctuation has not
// yet been seen. While `pending` is set, subsequent lines are consumed until
// the statement terminates (`;` at the current depth) or a body opens.
// ---------------------------------------------------------------------------

enum Access { kPublic, kPrivate, kProtected };

struct Miss {
  int line;  // 0 when the scan found nothing
  const char* reason;
};

void scanFile(const char* text, Miss* miss) {
  miss->line = 0;
  miss->reason = "";

  Lines lines;
  splitLines(const_cast<char*>(text), &lines);

  // Per-depth block kind: a namespace, a type body, a function body, or an
  // enum/enum-class body (whose constants are members of the type).
  enum BlockKind { kNamespace, kType, kEnum, kBody };
  const int kMaxDepth = 64;
  BlockKind kind[kMaxDepth];
  Access savedAccess[kMaxDepth];
  int savedDeclDepth[kMaxDepth];
  bool savedSawOpening[kMaxDepth];

  int depth = 0;
  Access access = kPublic;
  int declDepth = 0;      // depth of the innermost type whose members we judge
  bool sawOpening = false;
  bool pending = false;   // a declaration has opened; swallow its continuations

  kind[0] = kNamespace;
  savedAccess[0] = kPublic;
  savedDeclDepth[0] = 0;
  savedSawOpening[0] = false;

  for (int i = 0; i < lines.count; ++i) {
    const char* s = lines.start[i];
    const size_t n = lines.length[i];

    if (isBlank(s, n)) continue;
    if (isCommentOnly(s, n)) continue;

    const Access current = access;
    const bool inBody = depth > 0 && kind[depth] == kBody;

    const bool typeOpening = isTypeOpening(s);
    const bool enumOpening = isEnumOpening(s);

    // Run the brace bookkeeping FIRST so the block kinds and depth are current
    // when the line is judged below. Braces inside string and character
    // literals are ignored: a body-building line such as `append("]}", ...)`
    // carries a `}` in a literal that must not close a block.
    int quote = 0;  // 0 none, otherwise the opening quote character
    for (size_t k = 0; k < n; ++k) {
      const char c = s[k];
      if (quote != 0) {
        if (c == '\\') {
          ++k;  // skip the escaped character
        } else if (c == quote) {
          quote = 0;
        }
        continue;
      }
      if (c == '"' || c == '\'') {
        quote = c;
        continue;
      }
      if (c == '{') {
        ++depth;
        if (depth < kMaxDepth) {
          // Classify the block this `{` opens. Only two kinds are TRANSPARENT
          // (a declaration inside them is still public API at type scope):
          //   * a namespace body, and
          //   * an enum body (its constants belong to the enclosing type).
          // Everything else — a function definition's body, a `for`/`if` block,
          // an initialiser list — is OPAQUE: nothing inside it is a public
          // declaration. Anonymous namespaces and nested types are handled by
          // the same rule (a nested type re-establishes `declDepth`).
          BlockKind opened = kBody;
          if (isNamespaceOpening(s, n)) {
            opened = kNamespace;
          } else if (enumOpening) {
            opened = kEnum;
          } else if (typeOpening) {
            opened = kType;
          }
          kind[depth] = opened;
          savedAccess[depth] = access;
          savedDeclDepth[depth] = declDepth;
          savedSawOpening[depth] = sawOpening;
          if (opened == kType) {
            access = kPublic;
            sawOpening = true;
            declDepth = depth;
          }
        }
      } else if (c == '}') {
        if (depth > 0) {
          if (depth < kMaxDepth && kind[depth] == kType) {
            // The type closed: hand the access context back to the enclosing
            // type (or to "public" at namespace scope).
            access = savedAccess[depth];
            declDepth = savedDeclDepth[depth];
            sawOpening = savedSawOpening[depth];
          }
          --depth;
        }
      }
    }

    // A line inside a function body is a statement, never a declaration.
    if (depth > 0 && kind[depth] == kBody) continue;

    // --- access specifiers ------------------------------------------------
    const char* firstChar = firstNonSpace(s, n);
    if (firstChar == 0) continue;
    if (startsWith(firstChar, "public:")) {
      access = kPublic;
      continue;
    }
    if (startsWith(firstChar, "private:")) {
      access = kPrivate;
      continue;
    }
    if (startsWith(firstChar, "protected:")) {
      access = kProtected;
      continue;
    }

    // --- continuations of an already-judged declaration -------------------
    if (pending) {
      // A declaration that opened on an earlier line is consumed until it
      // terminates: `;` at the declaration's own depth, or until the depth has
      // dropped back (its body/initialiser closed). Nothing here is judged
      // again — the whole declaration is covered by one doc-comment.
      const char last = lastSignificant(s, n);
      if (depth <= declDepth && (last == ';' || last == '}')) pending = false;
      continue;
    }

    // --- the rule ---------------------------------------------------------
    if (current != kPublic) continue;  // private/protected members are free

    // Only a line that BEGINS a declaration is judged: its first token is an
    // identifier (a type name, a qualifier or a macro), never punctuation.
    if (!isIdentStart(*firstChar)) continue;
    char word[40];
    const bool hasWord = firstWord(s, n, word, sizeof(word));
    if (hasWord && (isStatementKeyword(word, len(word)) ||
                    equals(word, "typedef") || equals(word, "using"))) {
      continue;
    }
    // `INSIGHT_*` guard flags are preprocessor lines, not declarations.
    if (*firstChar == '#' || containsWithin(s, n, "INSIGHT_")) continue;

    const char last = lastSignificant(s, n);
    const bool declares = last == ';' || last == '{' || last == ',' || last == ':' ||
                          last == ')' || last == '(';
    if (!declares) continue;

    // The previous non-blank line must be a comment line.
    int previous = i - 1;
    while (previous >= 0 &&
           isBlank(lines.start[previous], lines.length[previous])) {
      --previous;
    }
    if (previous < 0 ||
        !isCommentOnly(lines.start[previous], lines.length[previous])) {
      miss->line = i + 1;  // 1-based, as an editor reports it
      miss->reason = "public declaration without a preceding doc-comment";
      return;
    }

    // This declaration spans further lines unless it terminated here.
    if (last != ';') pending = true;
  }
}

// ---------------------------------------------------------------------------
// Fixture: the public headers
// ---------------------------------------------------------------------------

const char* const kPublicHeaders[] = {
    "Insight.h",
    "InsightBuffer.h",
    "InsightControl.h",
    "InsightDevice.h",
    "InsightDiagnostics.h",
    "InsightOta.h",
    "InsightOtaRunner.h",
    "InsightOtaSigned.h",
    "InsightReliability.h",
    "InsightSend.h",
    "InsightSensor.h",
    "InsightTls.h",
    "InsightTransport.h",
    "InsightWatchdog.h",
    "InsightWifi.h",
};

// The aggregate must include every documented capability header, so one
// `#include <Insight.h>` really is the whole public API.
void test_aggregate_includes_every_public_header(void) {
  static char text[kMaxFileBytes];
  size_t length = 0;
  char path[1024];
  const bool found =
      resolveProjectFile("Insight.h", path, sizeof(path), text, sizeof(text), &length);
  TEST_ASSERT_TRUE_MESSAGE(found, "could not read src/Insight.h");

  for (size_t i = 0; i < sizeof(kPublicHeaders) / sizeof(kPublicHeaders[0]);
       ++i) {
    const char* name = kPublicHeaders[i];
    if (std::strcmp(name, "Insight.h") == 0) continue;  // the aggregate itself
    char needle[128];
    std::snprintf(needle, sizeof(needle), "#include \"%s\"", name);
    char message[200];
    std::snprintf(message, sizeof(message), "Insight.h does not include %s", name);
    TEST_ASSERT_NOT_NULL_MESSAGE(std::strstr(text, needle), message);
  }
}

// RULE 1 — the scan.
void test_every_public_declaration_has_a_doc_comment(void) {
  static char text[kMaxFileBytes];
  size_t length = 0;
  char path[1024];
  int scanned = 0;

  for (size_t i = 0; i < sizeof(kPublicHeaders) / sizeof(kPublicHeaders[0]);
       ++i) {
    const bool found = resolveProjectFile(kPublicHeaders[i], path, sizeof(path),
                                          text, sizeof(text), &length);
    TEST_ASSERT_TRUE_MESSAGE(found, kPublicHeaders[i]);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(static_cast<int>(kMaxFileBytes),
                                  static_cast<int>(length),
                                  kPublicHeaders[i]);

    Miss miss;
    scanFile(text, &miss);
    if (miss.line != 0) {
      char message[600];
      std::snprintf(message, sizeof(message), "%s:%d: %s", kPublicHeaders[i],
                    miss.line, miss.reason);
      TEST_FAIL_MESSAGE(message);
    }
    ++scanned;
  }
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      static_cast<int>(sizeof(kPublicHeaders) / sizeof(kPublicHeaders[0])),
      scanned, "not every public header was scanned");
}

// RULE 2 — the CHANGELOG entry for the current version.
void test_changelog_has_an_entry_for_the_current_version(void) {
  static char header[kMaxFileBytes];
  size_t length = 0;
  char path[1024];
  const bool found = resolveProjectFile("Insight.h", path, sizeof(path), header,
                                        sizeof(header), &length);
  TEST_ASSERT_TRUE_MESSAGE(found, "could not read src/Insight.h");

  const char* marker = std::strstr(header, "sdkVersion()");
  TEST_ASSERT_NOT_NULL_MESSAGE(marker,
                               "Insight.h does not declare sdkVersion()");
  const char* quote = std::strchr(marker, '"');
  TEST_ASSERT_NOT_NULL_MESSAGE(quote, "sdkVersion() has no string literal");
  const char* close = std::strchr(quote + 1, '"');
  TEST_ASSERT_NOT_NULL_MESSAGE(close, "sdkVersion() literal is unterminated");

  char version[64];
  const size_t versionLength = static_cast<size_t>(close - quote - 1);
  TEST_ASSERT_TRUE_MESSAGE(versionLength > 0 && versionLength < sizeof(version),
                           "sdkVersion() literal is empty or overlong");
  std::strncpy(version, quote + 1, versionLength);
  version[versionLength] = '\0';

  static char changelog[kMaxFileBytes];
  size_t changelogLength = 0;
  const bool hasChangelog =
      resolveProjectFile("CHANGELOG.md", path, sizeof(path), changelog,
                         sizeof(changelog), &changelogLength);
  TEST_ASSERT_TRUE_MESSAGE(hasChangelog,
                           "could not read CHANGELOG.md at the repository root");

  char needle[80];
  std::snprintf(needle, sizeof(needle), "## [%s]", version);
  char message[256];
  std::snprintf(
      message, sizeof(message),
      "CHANGELOG.md has no entry for the current version %s (looked for \"%s\")",
      version, needle);
  TEST_ASSERT_NOT_NULL_MESSAGE(std::strstr(changelog, needle), message);
}

}  // namespace

void setUp(void) {}

void tearDown(void) {}

int main(int, char**) {
  UNITY_BEGIN();

  RUN_TEST(test_aggregate_includes_every_public_header);
  RUN_TEST(test_every_public_declaration_has_a_doc_comment);
  RUN_TEST(test_changelog_has_an_entry_for_the_current_version);

  return UNITY_END();
}
