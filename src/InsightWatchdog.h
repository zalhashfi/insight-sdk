#ifndef INSIGHT_WATCHDOG_H
#define INSIGHT_WATCHDOG_H

namespace insight {

// Periodic hardware-watchdog feeding, with an explicit pause for the windows
// that must not be interrupted.
//
// A hardware watchdog resets the device unless something "feeds" it (pets it)
// often enough. Feeding on a fixed cadence is exactly what firmware wants 99%
// of the time — and exactly what it must NOT do during a flash/OTA write.
// Erasing and writing flash stalls the CPU and the cache for hundreds of
// milliseconds, so the main loop cannot run on schedule, but a watchdog feed
// issued from a timer (or simply left enabled with too short a window) can
// reset the device mid-write and brick it. pause()/resume() bracket those
// windows so the feed is suspended deliberately, not accidentally.
//
// Nothing here talks to a watchdog or a clock directly: the two things that
// make this untestable on a host — the feed call and the passage of time — are
// injected as seams. `feed` performs one feed; `clock` returns a monotonic
// millisecond counter. Both are plain C function pointers, which is the seam
// style used throughout this SDK: production code passes the platform's real
// pet routine and Arduino `millis()` (or `std::chrono`), and host tests pass
// small trampolines that forward to a fixture.
//
// Rules:
//
//   * DISABLED by default. A default-constructed watchdog has interval 0 and
//     never feeds, whatever the clock says. Feeding is opt-in: the caller must
//     enable(intervalMs) with a positive interval, which is also the moment
//     the scheduling window starts.
//
//   * Enabled, it feeds on schedule. The FIRST feed is due immediately — the
//     watchdog is expected to be constructed at boot alongside the hardware
//     watchdog, so the safest thing is to feed once as soon as it is armed
//     rather than wait out an interval during which nothing has been fed.
//     After that a feed is due once `intervalMs` has elapsed since the last
//     feed (measured by unsigned subtraction, so it survives a `millis()`
//     rollover).
//
//   * poll() is non-blocking and latches. Each call samples the clock at most
//     once and issues at most one feed, so poll() can be called from the main
//     loop as often as the loop runs without ever blocking. It reports whether
//     it fed, so a caller can trace the cadence.
//
//   * pause()/resume() are idempotent and safe in any order. While paused,
//     poll() NEVER feeds, no matter how far the clock advances — this is the
//     OTA-safety property, and it holds when the watchdog is disabled too.
//     Paused is the one state in which the feed guarantee is deliberately
//     withdrawn, so the caller is responsible for calling resume() (or
//     disabling) before the hardware window elapses.
//
//   * Resume restarts the window. A poll() immediately after resume() (or
//     after enabling) feeds right away and re-arms the interval from that
//     moment. Time that passed while paused is deliberately discarded: a feed
//     that is instantly due again at the end of a long OTA write is a worse
//     failure mode than one interval of additional slack, and the caller just
//     spent that whole window not needing the feed.
//
// A null `feed` is legal and models a board whose watchdog is absent/disabled:
// scheduling and the feed counter still advance, nothing external is touched,
// and no call is made through a null pointer.

class InsightWatchdog {
 public:
  // One watchdog feed. Must return promptly; it is called from poll().
  typedef void (*Feed)();

  // Monotonic millisecond clock. May wrap (unsigned 32-bit semantics). A null
  // clock is read as a constant zero (time frozen): an enabled watchdog then
  // feeds exactly once — the immediate first feed — and never again, because
  // the frozen clock can never reach the interval.
  typedef unsigned long (*Clock)();

  InsightWatchdog()
      : intervalMs_(0),
        feed_(0),
        clock_(0),
        lastFeedMs_(0),
        started_(false),
        paused_(false),
        due_(false),
        feeds_(0) {}

  InsightWatchdog(unsigned long intervalMs, Feed feed, Clock clock)
      : intervalMs_(0),
        feed_(feed),
        clock_(clock),
        lastFeedMs_(0),
        started_(false),
        paused_(false),
        due_(false),
        feeds_(0) {
    enable(intervalMs);
  }

  // --- injected seams ---------------------------------------------------
  // Install / inspect the seams. Passing null detaches one; see the class
  // comment for what that implies. Installing a different feed after
  // enable() keeps the schedule running — only the function changes.
  void setFeed(Feed feed) { feed_ = feed; }
  Feed feed() const { return feed_; }

  void setClock(Clock clock) { clock_ = clock; }
  Clock clock() const { return clock_; }

  // --- configuration ----------------------------------------------------
  // Arm the watchdog with a feed period of `intervalMs` milliseconds, or
  // disable it when `intervalMs == 0`. Time starts NOW: the interval is
  // measured from this call, and the next poll() feeds immediately. Enabling
  // an already-enabled watchdog simply restarts the window with the new
  // interval; it does not feed by itself.
  void enable(unsigned long intervalMs = 10000) {
    intervalMs_ = intervalMs;
    lastFeedMs_ = now();
    started_ = intervalMs != 0;
    // Arm the immediate first feed. `lastFeedMs_` is set to "now" so the
    // steady-state schedule runs from this moment, but `due_` records that one
    // feed is outstanding right away — boot is exactly when nothing has been
    // fed yet. The two pieces of state are separate because a zero-length
    // elapsed time must still be due exactly once, at arming, and never again.
    due_ = started_;
  }

  // Disarm. Equivalent to enable(0): poll() stops feeding until the next
  // enable(). Cumulative counters are left untouched.
  void disable() { enable(0); }

  // The configured feed period in milliseconds; 0 means disabled.
  unsigned long interval() const { return intervalMs_; }

  // True while armed with a non-zero interval.
  bool enabled() const { return started_; }

  // --- pause / resume ---------------------------------------------------
  // Suspend feeding. While paused, poll() is a no-op for any amount of elapsed
  // time. Idempotent: pausing twice is the same as pausing once, and pausing a
  // disabled watchdog is harmless. Used to bracket flash/OTA writes.
  void pause() { paused_ = true; }

  // Resume feeding. Idempotent: resuming a running watchdog is a no-op, and
  // resuming a disabled one arms nothing (it stays disabled until enable()).
  // Resuming restarts the window, so the next poll() feeds immediately.
  void resume() {
    paused_ = false;
    lastFeedMs_ = now();
    // Resume re-arms the window, which means the immediate-feed debt exists
    // again: the first poll after resume feeds at once rather than waiting out
    // an interval. Only an armed watchdog owes a feed.
    due_ = started_;
  }

  // True while feeding is suspended (independent of enabled()).
  bool paused() const { return paused_; }

  // --- scheduling -------------------------------------------------------
  // Sample the clock once and feed if a feed is due. Returns true when it
  // fed. Never blocks. A no-op (returning false) when disabled or paused.
  bool poll() {
    if (!started_ || paused_) {
      return false;
    }
    // A feed is due when the arming/resume debt is outstanding, or when a full
    // interval has elapsed since the last feed. The elapsed-time test uses
    // unsigned subtraction (rollover-safe) and is evaluated only when no feed
    // is already owed, so a single millisecond cannot produce two feeds and a
    // long stalled loop still produces one feed, not a burst.
    if (!due_ && now() - lastFeedMs_ < intervalMs_) {
      return false;
    }
    doFeed();
    return true;
  }

  // Feeds issued by poll() since construction. Observable so tests can pin the
  // exact cadence the schedule implies.
  unsigned long feeds() const { return feeds_; }

 private:
  void doFeed() {
    lastFeedMs_ = now();
    due_ = false;
    ++feeds_;
    if (feed_ != 0) {
      feed_();
    }
  }

  unsigned long now() const { return clock_ == 0 ? 0 : clock_(); }

  unsigned long intervalMs_;
  Feed feed_;
  Clock clock_;
  unsigned long lastFeedMs_;
  bool started_;  // enabled: interval is non-zero
  bool paused_;   // feeding suspended (the OTA-safety state)
  bool due_;      // a feed is owed now (armed by enable()/resume())
  unsigned long feeds_;
};

}  // namespace insight

#endif  // INSIGHT_WATCHDOG_H
