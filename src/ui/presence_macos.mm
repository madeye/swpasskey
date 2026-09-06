// macOS user-presence prompt: an AppKit NSAlert with Approve / Deny.
//
// DESIGN.md K13 allows NSAlert instead of UNUserNotificationCenter:
// actionable UN categories need a signed .app bundle plus user authorization,
// which does not exist yet (the entitlement spike is K26/PR3). NSAlert only
// needs a GUI session and a run loop on the *main* thread — hence
// needs_main_thread()/run_main_loop(): `main()` runs the daemon loop on a side
// thread and hands the main thread to us.
//
// `confirm()` runs on the authenticator worker. It dispatches the alert to the
// main queue and waits on a condvar with 50 ms wakeups so a CTAPHID CANCEL or
// the 30 s deadline is honoured promptly; on cancel/timeout it dispatches
// -[NSApplication abortModal], which unwinds the modal loop.
#if defined(__APPLE__)

#include "swpasskey/ui/presence.hpp"

#include "presence_util.hpp"
#include "swpasskey/log/log.hpp"

#import <AppKit/AppKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace swpk::ui {
namespace {

constexpr auto kPollInterval = std::chrono::milliseconds(50);
constexpr auto kTeardownTimeout = std::chrono::seconds(2);
constexpr CFTimeInterval kStopPollSeconds = 0.1;

NSString* ns_string(const std::string& s) {
  NSString* out = [NSString stringWithUTF8String:s.c_str()];
  return out != nil ? out : @"?";
}

class AlertPresence final : public Presence {
public:
  Decision confirm(const PresenceRequest& req, ctap::CancelToken& cancel,
                   std::chrono::milliseconds timeout) override;
  const char* name() const override { return "alert"; }
  bool needs_main_thread() const override { return true; }
  void run_main_loop(std::function<bool()> should_stop) override;

  // For the shutdown timer, which must not abort a run loop that is not modal.
  bool modal_running() {
    std::lock_guard<std::mutex> lk(mu_);
    return modal_running_;
  }

private:
  std::mutex mu_;
  std::condition_variable cv_;
  // All guarded by mu_.
  bool busy_{false};
  bool decided_{false};
  bool modal_running_{false};
  bool abort_requested_{false};
  bool finished_{true};  // the main-queue block ran to completion
  Decision decision_{Decision::Deny};
};

Decision AlertPresence::confirm(const PresenceRequest& req, ctap::CancelToken& cancel,
                                std::chrono::milliseconds timeout) {
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (busy_) {
      // Only one worker exists; be defensive rather than stacking modals.
      log::warn("presence_alert_busy", {{"rp", req.rp_id}});
      return Decision::Deny;
    }
    busy_ = true;
    decided_ = false;
    modal_running_ = false;
    abort_requested_ = false;
    finished_ = false;
    decision_ = Decision::Deny;
  }

  NSString* title =
      [NSString stringWithFormat:@"swpasskey: %s", detail::kind_action(req.kind)];
  std::string info = "Site: " + detail::clamp_text(req.rp_id);
  if (!req.user_display.empty()) {
    info += "\nUser: " + detail::clamp_text(req.user_display);
  }
  NSString* body = ns_string(info);

  dispatch_async(dispatch_get_main_queue(), ^{
    bool run_it = false;
    {
      std::lock_guard<std::mutex> lk(mu_);
      run_it = !decided_ && !abort_requested_;
      modal_running_ = run_it;
    }
    NSModalResponse resp = NSModalResponseAbort;
    if (run_it) {
      @autoreleasepool {
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = title;
        alert.informativeText = body;
        alert.alertStyle = NSAlertStyleInformational;
        [alert addButtonWithTitle:@"Approve"];
        [alert addButtonWithTitle:@"Deny"];
        [NSApp activateIgnoringOtherApps:YES];
        resp = [alert runModal];
        [alert.window orderOut:nil];
      }
    }
    {
      std::lock_guard<std::mutex> lk(mu_);
      modal_running_ = false;
      if (run_it && !decided_) {
        decided_ = true;
        decision_ = resp == NSAlertFirstButtonReturn ? Decision::Allow : Decision::Deny;
      }
      finished_ = true;
    }
    cv_.notify_all();
  });

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  Decision out = Decision::Timeout;
  bool need_abort = false;
  {
    std::unique_lock<std::mutex> lk(mu_);
    for (;;) {
      if (decided_) {
        out = decision_;
        break;
      }
      if (cancel.is_cancelled()) {
        out = Decision::Cancelled;
        break;
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        out = Decision::Timeout;
        break;
      }
      cv_.wait_for(lk, kPollInterval);
    }
    // Latch the answer so the modal cannot overwrite a cancel/timeout.
    decided_ = true;
    decision_ = out;
    abort_requested_ = true;
    need_abort = !finished_;
  }

  if (need_abort) {
    dispatch_async(dispatch_get_main_queue(), ^{
      bool running = false;
      {
        std::lock_guard<std::mutex> lk(mu_);
        running = modal_running_;
      }
      // Both blocks run on the main queue, so this cannot interleave with the
      // alert block's own code: either the modal loop is spinning (and is
      // servicing this queue), or the alert block has not started / has fully
      // finished and modal_running_ is false. -[NSApp abortModal] raises
      // NSAbortModalException, which -[NSAlert runModal] catches; nothing may
      // follow it in this block.
      if (running) {
        [NSApp abortModal];
      }
    });
    std::unique_lock<std::mutex> lk(mu_);
    if (!cv_.wait_for(lk, kTeardownTimeout, [this] { return finished_; })) {
      // run_main_loop() is not running: nobody drains the main queue.
      log::warn("presence_alert_no_main_loop");
    }
  }
  {
    std::lock_guard<std::mutex> lk(mu_);
    busy_ = false;
  }
  log::debug("presence_alert_done",
             {{"rp", req.rp_id},
              {"decision", out == Decision::Allow       ? "allow"
                           : out == Decision::Deny      ? "deny"
                           : out == Decision::Cancelled ? "cancelled"
                                                        : "timeout"}});
  return out;
}

struct StopCtx {
  AlertPresence* self;
  std::function<bool()>* should_stop;
};

void stop_timer_fired(CFRunLoopTimerRef, void* info) {
  auto* ctx = static_cast<StopCtx*>(info);
  if (ctx == nullptr || ctx->should_stop == nullptr || !*ctx->should_stop) {
    return;
  }
  if (!(*ctx->should_stop)()) {
    return;
  }
  if (ctx->self != nullptr && ctx->self->modal_running()) {
    // Shutting down with a prompt on screen: unwind the modal loop first; the
    // next tick (100 ms) stops the application loop itself.
    [NSApp abortModal];
    return;
  }
  [NSApp stop:nil];
  // -[NSApp stop:] only takes effect once another event is dispatched.
  NSEvent* wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                     location:NSZeroPoint
                                modifierFlags:0
                                    timestamp:0
                                 windowNumber:0
                                      context:nil
                                      subtype:0
                                        data1:0
                                        data2:0];
  [NSApp postEvent:wake atStart:YES];
}

void AlertPresence::run_main_loop(std::function<bool()> should_stop) {
  @autoreleasepool {
    NSApplication* app = [NSApplication sharedApplication];
    // Accessory: a GUI-capable process with no Dock icon and no menu bar
    // (matches LSUIElement in packaging/macos/swpasskeyd.app).
    [app setActivationPolicy:NSApplicationActivationPolicyAccessory];

    StopCtx ctx{this, &should_stop};
    CFRunLoopTimerContext tctx{0, &ctx, nullptr, nullptr, nullptr};
    CFRunLoopTimerRef timer =
        CFRunLoopTimerCreate(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent() + kStopPollSeconds,
                             kStopPollSeconds, 0, 0, &stop_timer_fired, &tctx);
    if (timer == nullptr) {
      log::error("presence_main_loop_no_timer");
      return;
    }
    // Common modes so the poll keeps running inside a modal session too.
    CFRunLoopAddTimer(CFRunLoopGetMain(), timer, kCFRunLoopCommonModes);
    log::debug("presence_main_loop_start");
    [app run];
    CFRunLoopRemoveTimer(CFRunLoopGetMain(), timer, kCFRunLoopCommonModes);
    CFRelease(timer);
    log::debug("presence_main_loop_stop");
  }
}

}  // namespace

std::unique_ptr<Presence> make_desktop_presence() {
  // No Aqua session (ssh, a system LaunchDaemon): AppKit cannot draw, and
  // touching NSApplication there would abort the process.
  CFDictionaryRef session = CGSessionCopyCurrentDictionary();
  if (session == nullptr) {
    log::warn("presence_notify_unavailable", {{"reason", "no macOS GUI session"}});
    return nullptr;
  }
  CFRelease(session);
  log::info("presence_alert_ready");
  return std::make_unique<AlertPresence>();
}

}  // namespace swpk::ui

#endif  // __APPLE__
