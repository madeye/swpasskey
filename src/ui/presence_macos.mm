// macOS user-presence prompt: a small app-modal panel that names the action
// ("Sign in to github.com?") with Cancel and an action button ("Sign In").
// The action button is the default but starts disabled for kArmDelay: the
// panel takes focus, so a keystroke already in flight must not approve a
// request the user has not seen.
//
// DESIGN.md K13 allows an in-process prompt instead of UNUserNotificationCenter:
// actionable UN categories need a signed .app bundle plus user authorization,
// which does not exist yet (the entitlement spike is K26/PR3). The panel only
// needs a GUI session and a run loop on the *main* thread — hence
// needs_main_thread()/run_main_loop(): `main()` runs the daemon loop on a side
// thread and hands the main thread to us.
//
// `confirm()` runs on the authenticator worker. It dispatches the panel to the
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

namespace {

constexpr NSTimeInterval kArmDelay = 0.8;

NSString* ns_string(const std::string& s) {
  NSString* out = [NSString stringWithUTF8String:s.c_str()];
  return out != nil ? out : @"?";
}

struct PanelText {
  NSString* headline;
  NSString* detail;
  NSString* action;
  bool destructive{false};
};

PanelText panel_text(swpk::ui::PresenceRequest::Kind kind, NSString* site, NSString* account) {
  using Kind = swpk::ui::PresenceRequest::Kind;
  NSString* who = account.length > 0 ? [NSString stringWithFormat:@"Account: %@", account] : nil;
  switch (kind) {
    case Kind::MakeCredential:
      return {[NSString stringWithFormat:@"Create a passkey for %@?", site],
              who != nil ? [who stringByAppendingString:@"\nThe passkey is saved on this Mac."]
                         : @"The passkey is saved on this Mac.",
              @"Create Passkey"};
    case Kind::GetAssertion:
      return {[NSString stringWithFormat:@"Sign in to %@?", site],
              who != nil ? who : @"Use your saved passkey for this site.", @"Sign In"};
    case Kind::Reset:
      return {@"Erase all passkeys?",
              @"Every passkey on this security key will be deleted, and sites will stop accepting them. "
              @"This can’t be undone.",
              @"Erase All", true};
    case Kind::SetPin:
      return {@"Change the security key PIN?",
              @"Allow this only if you just set a PIN in swpasskey Settings or with swpasskeyctl.",
              @"Change PIN"};
    case Kind::Selection:
      return {@"Use swpasskey?", @"An app or browser wants to use this security key.", @"Use This Key"};
  }
  return {@"Allow this request?", @"", @"Allow"};
}

}  // namespace

// Stops the modal session with OK (action) or Cancel. Closing is not offered:
// the panel has no title bar buttons, and Esc maps to Cancel.
@interface SWPKPresencePanel : NSObject
- (instancetype)initWithText:(const PanelText&)text;
- (NSModalResponse)runModal;
@end

@implementation SWPKPresencePanel {
  NSPanel* panel_;
  NSButton* action_;
}

- (instancetype)initWithText:(const PanelText&)text {
  self = [super init];
  if (self == nil) return nil;
  const CGFloat W = 340;
  panel_ = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, W, 200)
                                      styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskFullSizeContentView)
                                        backing:NSBackingStoreBuffered
                                          defer:NO];
  panel_.titlebarAppearsTransparent = YES;
  panel_.titleVisibility = NSWindowTitleHidden;
  panel_.movableByWindowBackground = YES;
  // Above every app, including a browser in full screen, on whichever Space
  // the user is looking at: the request comes from another app and must not
  // hide behind it.
  panel_.level = NSStatusWindowLevel;
  panel_.collectionBehavior = NSWindowCollectionBehaviorCanJoinAllSpaces |
                              NSWindowCollectionBehaviorFullScreenAuxiliary |
                              NSWindowCollectionBehaviorTransient;
  panel_.hidesOnDeactivate = NO;
  panel_.releasedWhenClosed = NO;
  for (NSWindowButton b : {NSWindowCloseButton, NSWindowMiniaturizeButton, NSWindowZoomButton}) {
    [panel_ standardWindowButton:b].hidden = YES;
  }

  NSImageView* icon = [NSImageView imageViewWithImage:[NSApp applicationIconImage]];
  [icon.widthAnchor constraintEqualToConstant:56].active = YES;
  [icon.heightAnchor constraintEqualToConstant:56].active = YES;

  NSTextField* headline = [NSTextField wrappingLabelWithString:text.headline];
  headline.font = [NSFont systemFontOfSize:15 weight:NSFontWeightSemibold];
  headline.alignment = NSTextAlignmentCenter;
  headline.selectable = NO;

  NSTextField* detail = [NSTextField wrappingLabelWithString:text.detail];
  detail.font = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
  detail.textColor = [NSColor secondaryLabelColor];
  detail.alignment = NSTextAlignmentCenter;
  detail.selectable = NO;
  detail.hidden = text.detail.length == 0;

  NSButton* cancel = [NSButton buttonWithTitle:@"Cancel" target:self action:@selector(cancel:)];
  cancel.keyEquivalent = @"\033";
  cancel.controlSize = NSControlSizeLarge;
  action_ = [NSButton buttonWithTitle:text.action target:self action:@selector(approve:)];
  action_.keyEquivalent = @"\r";
  action_.controlSize = NSControlSizeLarge;
  action_.enabled = NO;
  if (text.destructive) {
    action_.hasDestructiveAction = YES;
    action_.bezelColor = [NSColor systemRedColor];
  }
  NSStackView* buttons = [NSStackView stackViewWithViews:@[ cancel, action_ ]];
  buttons.distribution = NSStackViewDistributionFillEqually;
  buttons.spacing = 10;

  NSStackView* stack = [NSStackView stackViewWithViews:@[ icon, headline, detail, buttons ]];
  stack.orientation = NSUserInterfaceLayoutOrientationVertical;
  stack.alignment = NSLayoutAttributeCenterX;
  stack.spacing = 10;
  [stack setCustomSpacing:14 afterView:icon];
  [stack setCustomSpacing:18 afterView:detail];
  stack.edgeInsets = NSEdgeInsetsMake(28, 24, 20, 24);
  stack.translatesAutoresizingMaskIntoConstraints = NO;

  NSView* content = panel_.contentView;
  [content addSubview:stack];
  const CGFloat inner = W - 48;
  [NSLayoutConstraint activateConstraints:@[
    [stack.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
    [stack.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
    [stack.topAnchor constraintEqualToAnchor:content.topAnchor],
    [stack.bottomAnchor constraintEqualToAnchor:content.bottomAnchor],
    [content.widthAnchor constraintEqualToConstant:W],
    [headline.widthAnchor constraintEqualToConstant:inner],
    [detail.widthAnchor constraintEqualToConstant:inner],
    [buttons.widthAnchor constraintEqualToConstant:inner],
  ]];
  [panel_ layoutIfNeeded];
  [self centerOnActiveScreen];
  return self;
}

// With several displays, show the prompt where the user is working: the
// screen under the pointer, a little above center like a system alert.
- (void)centerOnActiveScreen {
  NSScreen* screen = [NSScreen mainScreen];
  const NSPoint mouse = [NSEvent mouseLocation];
  for (NSScreen* s in [NSScreen screens]) {
    if (NSPointInRect(mouse, s.frame)) {
      screen = s;
      break;
    }
  }
  const NSRect area = screen != nil ? screen.visibleFrame : NSZeroRect;
  const NSSize size = panel_.frame.size;
  [panel_ setFrameOrigin:NSMakePoint(NSMidX(area) - size.width / 2,
                                     NSMinY(area) + (area.size.height - size.height) * 0.62)];
}

- (NSModalResponse)runModal {
  NSTimer* arm = [NSTimer timerWithTimeInterval:kArmDelay
                                        repeats:NO
                                          block:^(NSTimer*) {
                                            self->action_.enabled = YES;
                                          }];
  [[NSRunLoop currentRunLoop] addTimer:arm forMode:NSRunLoopCommonModes];
  // macOS 27 may refuse to activate an accessory app on demand ("ordered
  // front from a non-active application and may order beneath"). Put the
  // panel on screen above everything first, then ask for activation so it
  // also takes keyboard focus when the system allows it.
  [panel_ orderFrontRegardless];
  [NSApp activateIgnoringOtherApps:YES];
  [panel_ makeKeyWindow];
  const NSModalResponse r = [NSApp runModalForWindow:panel_];
  [arm invalidate];
  [panel_ orderOut:nil];
  return r;
}

- (void)approve:(id)sender {
  if (action_.enabled) [NSApp stopModalWithCode:NSModalResponseOK];
}

- (void)cancel:(id)sender {
  [NSApp stopModalWithCode:NSModalResponseCancel];
}

@end

namespace swpk::ui {
namespace {

constexpr auto kPollInterval = std::chrono::milliseconds(50);
constexpr auto kTeardownTimeout = std::chrono::seconds(2);
constexpr CFTimeInterval kStopPollSeconds = 0.1;

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
  // Bumped per confirm(). A main-queue block from an earlier request that
  // runs late (its confirm() gave up waiting) sees a newer generation and
  // does nothing, so it can never show old text or decide a newer request.
  std::uint64_t generation_{0};
};

Decision AlertPresence::confirm(const PresenceRequest& req, ctap::CancelToken& cancel,
                                std::chrono::milliseconds timeout) {
  std::uint64_t gen = 0;
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
    gen = ++generation_;
  }

  const PanelText text = panel_text(req.kind, ns_string(detail::clamp_text(req.rp_id)),
                                    ns_string(detail::clamp_text(req.user_display)));

  dispatch_async(dispatch_get_main_queue(), ^{
    bool run_it = false;
    {
      std::lock_guard<std::mutex> lk(mu_);
      if (gen != generation_) {
        return;  // stale: a newer confirm() owns the state now
      }
      run_it = !decided_ && !abort_requested_;
      modal_running_ = run_it;
    }
    NSModalResponse resp = NSModalResponseAbort;
    if (run_it) {
      @autoreleasepool {
        resp = [[[SWPKPresencePanel alloc] initWithText:text] runModal];
      }
    }
    {
      std::lock_guard<std::mutex> lk(mu_);
      modal_running_ = false;
      if (run_it && !decided_) {
        decided_ = true;
        decision_ = resp == NSModalResponseOK ? Decision::Allow : Decision::Deny;
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
        running = modal_running_ && gen == generation_;
      }
      // Both blocks run on the main queue, so this cannot interleave with the
      // alert block's own code: either the modal loop is spinning (and is
      // servicing this queue), or the alert block has not started / has fully
      // finished and modal_running_ is false. -[NSApp abortModal] makes
      // -[NSApp runModalForWindow:] return NSModalResponseAbort (Deny); keep
      // it the last statement in this block.
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
