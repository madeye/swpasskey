// macOS menu bar status item for swpasskeyd: a key icon whose menu shows the
// passkey count and opens the Passkeys window (toolbar with search and delete
// over a table of saved passkeys) and the Settings window (General, Security
// and About tabs), and quits the daemon.
//
// Dock: the app is an accessory (no Dock icon) until its status menu is open
// or one of its windows is on screen; then it becomes a regular app so the
// windows show up in the Dock and Cmd-Tab. It drops back when both are gone.
// A short welcome window at launch says where the app lives, unless it was
// started by its own login item or the user turned the welcome off.
//
// Everything here runs on the main thread inside the AppKit loop that
// AlertPresence::run_main_loop() drives. Store reads go through
// CredentialStore's own mutex; deletes go through Authenticator::ctl_delete
// via MenuBarDeps::delete_key, which serialises against CTAP traffic.
#if defined(__APPLE__)

#include "swpasskey/ui/menubar.hpp"

#include "swpasskey/log/log.hpp"
#include "swpasskey/ui/keys_model.hpp"

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr const char* kLogLevelDefault = "SWPKLogLevel";
constexpr const char* kHideWelcomeDefault = "SWPKHideWelcome";
constexpr const char* kAgentLabel = "com.tangzixiang.swpasskey.daemon";
NSString* const kAgentPlist = @"com.tangzixiang.swpasskey.daemon.plist";

NSToolbarItemIdentifier const kSearchItem = @"swpk.search";
NSToolbarItemIdentifier const kDeleteItem = @"swpk.delete";

constexpr CGFloat kSettingsWidth = 500;
constexpr NSTimeInterval kDockHideDelay = 2.0;  // see -updateDockPolicy

// launchd sets XPC_SERVICE_NAME to the job label for the login item.
bool launched_by_login_item() {
  const char* name = std::getenv("XPC_SERVICE_NAME");
  return name != nullptr && std::strcmp(name, kAgentLabel) == 0;
}

NSString* ns(const std::string& s) {
  NSString* out = [NSString stringWithUTF8String:s.c_str()];
  return out != nil ? out : @"?";
}

std::vector<std::uint8_t> unhex(const std::string& h) {
  std::vector<std::uint8_t> out;
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  if (h.size() % 2 != 0) return out;
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
    const int a = nib(h[i]), b = nib(h[i + 1]);
    if (a < 0 || b < 0) return {};
    out.push_back(static_cast<std::uint8_t>(a * 16 + b));
  }
  return out;
}

struct LevelChoice {
  swpk::log::Level level;
  const char* key;    // stored in defaults
  NSString* title;    // shown in Settings
};

const LevelChoice kLevels[] = {
    {swpk::log::Level::Error, "error", @"Errors only"},
    {swpk::log::Level::Warn, "warn", @"Warnings and errors"},
    {swpk::log::Level::Info, "info", @"Standard"},
    {swpk::log::Level::Debug, "debug", @"Detailed (for troubleshooting)"},
};

// Opening a window from the status menu is an explicit user request, so take
// the foreground outright. The cooperative -[NSApp activate] (macOS 14+) is
// often declined here because the previously active app never yielded,
// which left the Passkeys window behind other apps.
void activate_app() {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  [NSApp activateIgnoringOtherApps:YES];
#pragma clang diagnostic pop
}

NSTextField* label(NSString* text) {
  NSTextField* f = [NSTextField labelWithString:text];
  f.lineBreakMode = NSLineBreakByTruncatingMiddle;
  return f;
}

NSTextField* note(NSString* text) {
  NSTextField* f = [NSTextField wrappingLabelWithString:text];
  f.font = [NSFont systemFontOfSize:[NSFont smallSystemFontSize]];
  f.textColor = [NSColor secondaryLabelColor];
  f.selectable = NO;
  return f;
}

NSMenuItem* menu_item(NSString* title, SEL action, NSString* key, id target = nil) {
  NSMenuItem* item = [[NSMenuItem alloc] initWithTitle:title action:action keyEquivalent:key];
  item.target = target;
  return item;
}

NSDate* date_of(std::uint64_t unix_seconds) {
  return [NSDate dateWithTimeIntervalSince1970:static_cast<double>(unix_seconds)];
}

// The UI is English-only, so dates are too: a system locale would mix
// "3 天前" into English columns.
NSLocale* ui_locale() {
  static NSLocale* l = [NSLocale localeWithLocaleIdentifier:@"en_US"];
  return l;
}

NSDateFormatter* date_formatter(NSDateFormatterStyle date, NSDateFormatterStyle time) {
  NSDateFormatter* d = [[NSDateFormatter alloc] init];
  d.locale = ui_locale();
  d.dateStyle = date;
  d.timeStyle = time;
  return d;
}

// "Created": the day only; the time adds noise to a list.
NSString* format_day(std::uint64_t unix_seconds) {
  if (unix_seconds == 0) return @"—";
  static NSDateFormatter* f = date_formatter(NSDateFormatterMediumStyle, NSDateFormatterNoStyle);
  return [f stringFromDate:date_of(unix_seconds)];
}

// "Last Used": relative ("2 hours ago"), which is what the column is for.
NSString* format_recent(std::uint64_t unix_seconds) {
  if (unix_seconds == 0) return @"Never";
  static NSRelativeDateTimeFormatter* f = [] {
    NSRelativeDateTimeFormatter* r = [[NSRelativeDateTimeFormatter alloc] init];
    r.locale = ui_locale();
    r.unitsStyle = NSRelativeDateTimeFormatterUnitsStyleFull;
    return r;
  }();
  return [f localizedStringForDate:date_of(unix_seconds) relativeToDate:[NSDate date]];
}

// Tooltip: the exact moment.
NSString* format_full(std::uint64_t unix_seconds) {
  if (unix_seconds == 0) return nil;
  static NSDateFormatter* f = date_formatter(NSDateFormatterLongStyle, NSDateFormatterShortStyle);
  return [f stringFromDate:date_of(unix_seconds)];
}

// The domain is what the passkey is bound to; the RP's display name is only a
// hint and goes in the tooltip.
NSString* site_text(const swpk::ui::KeyRow& r) { return ns(r.rp_id); }

NSString* account_text(const swpk::ui::KeyRow& r) {
  if (r.u2f) return @"Security key sign-in";
  return ns(r.user_name.empty() ? r.user_display : r.user_name);
}

// A settings pane: a vertical stack with fixed width, pinned to the top.
NSViewController* pane(NSString* title, NSString* symbol, NSArray<NSView*>* rows) {
  NSStackView* stack = [NSStackView stackViewWithViews:rows];
  stack.orientation = NSUserInterfaceLayoutOrientationVertical;
  stack.alignment = NSLayoutAttributeLeading;
  stack.spacing = 8;
  stack.edgeInsets = NSEdgeInsetsMake(20, 28, 24, 28);
  stack.translatesAutoresizingMaskIntoConstraints = NO;
  NSView* v = [[NSView alloc] init];
  [v addSubview:stack];
  [NSLayoutConstraint activateConstraints:@[
    [stack.leadingAnchor constraintEqualToAnchor:v.leadingAnchor],
    [stack.trailingAnchor constraintEqualToAnchor:v.trailingAnchor],
    [stack.topAnchor constraintEqualToAnchor:v.topAnchor],
    [stack.bottomAnchor constraintEqualToAnchor:v.bottomAnchor],
    [v.widthAnchor constraintEqualToConstant:kSettingsWidth],
  ]];
  // Full-width text, separators and grids, unless the caller already sized
  // the row (an indented note).
  for (NSView* row in rows) {
    BOOL sized = NO;
    for (NSLayoutConstraint* c in row.constraints) {
      if (c.firstItem == row && c.firstAttribute == NSLayoutAttributeWidth) sized = YES;
    }
    if (!sized && ([row isKindOfClass:[NSTextField class]] || [row isKindOfClass:[NSBox class]] ||
                   [row isKindOfClass:[NSGridView class]])) {
      [row.widthAnchor constraintEqualToConstant:kSettingsWidth - 56].active = YES;
    }
  }
  NSViewController* vc = [[NSViewController alloc] init];
  vc.view = v;
  vc.title = title;
  vc.preferredContentSize = v.fittingSize;
  vc.representedObject = [NSImage imageWithSystemSymbolName:symbol accessibilityDescription:title];
  return vc;
}

NSBox* separator() {
  NSBox* b = [[NSBox alloc] init];
  b.boxType = NSBoxSeparator;
  return b;
}

NSTextField* heading(NSString* text) {
  NSTextField* f = label(text);
  f.font = [NSFont systemFontOfSize:[NSFont systemFontSize] weight:NSFontWeightSemibold];
  return f;
}

}  // namespace

@interface SWPKMenuController
    : NSObject <NSApplicationDelegate, NSMenuDelegate, NSSearchFieldDelegate, NSTableViewDataSource,
                NSTableViewDelegate, NSToolbarDelegate, NSWindowDelegate>
- (instancetype)initWithDeps:(swpk::ui::MenuBarDeps)deps;
- (void)teardown;
@end

@implementation SWPKMenuController {
  swpk::ui::MenuBarDeps deps_;
  std::vector<swpk::ui::KeyRow> allRows_;
  std::vector<swpk::ui::KeyRow> rows_;  // allRows_ filtered by the search field
  std::vector<std::string> shownIds_;   // cred ids in the order the table shows them
  NSTimer* keysTimer_;                  // runs only while the Passkeys window is open
  unsigned keysTicks_;
  NSStatusItem* item_;
  NSMenu* menu_;
  NSMenuItem* summaryItem_;

  NSWindow* keysWindow_;
  NSTableView* table_;
  NSView* emptyState_;
  NSTextField* emptyTitle_;
  NSToolbarItem* deleteItem_;
  NSSearchField* search_;

  NSWindow* settingsWindow_;
  NSButton* loginCheckbox_;
  NSTextField* loginNote_;
  NSButton* welcomeCheckbox_;
  NSPopUpButton* levelPopup_;
  NSButton* pinButton_;
  NSTextField* pinStatus_;

  NSWindow* welcomeWindow_;
  NSButton* welcomeHide_;

  BOOL pinBusy_;
  BOOL menuOpen_;
  BOOL tornDown_;
}

- (instancetype)initWithDeps:(swpk::ui::MenuBarDeps)deps {
  self = [super init];
  if (self == nil) return nil;
  deps_ = std::move(deps);
  [self applyLogLevelPreference];

  item_ = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
  NSImage* icon = [NSImage imageWithSystemSymbolName:@"key.fill" accessibilityDescription:@"swpasskey"];
  if (icon != nil) {
    [icon setTemplate:YES];
    item_.button.image = icon;
  } else {
    item_.button.title = @"\U0001F511";
  }
  item_.button.toolTip = @"swpasskey";

  menu_ = [[NSMenu alloc] initWithTitle:@"swpasskey"];
  menu_.delegate = self;
  summaryItem_ = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
  summaryItem_.enabled = NO;
  [menu_ addItem:summaryItem_];
  [menu_ addItem:[NSMenuItem separatorItem]];
  [menu_ addItem:menu_item(@"Passkeys…", @selector(showKeys:), @"k", self)];
  [menu_ addItem:menu_item(@"Settings…", @selector(showSettings:), @",", self)];
  [menu_ addItem:[NSMenuItem separatorItem]];
  [menu_ addItem:menu_item(@"Quit swpasskey", @selector(quit:), @"q", self)];
  item_.menu = menu_;
  [self refreshSummary];
  [self installMainMenu];
  NSApp.delegate = self;
  // Queued until the presence loop runs NSApp (it sets the accessory policy
  // first), so the welcome's Dock switch is not overwritten.
  if (!launched_by_login_item() &&
      ![[NSUserDefaults standardUserDefaults] boolForKey:@(kHideWelcomeDefault)]) {
    dispatch_async(dispatch_get_main_queue(), ^{
      if (!tornDown_) [self showWelcome];
    });
  }
  swpk::log::info("menubar_ready");
  return self;
}

- (void)teardown {
  tornDown_ = YES;
  [NSObject cancelPreviousPerformRequestsWithTarget:self];
  [keysTimer_ invalidate];
  keysTimer_ = nil;
  if (item_ != nil) {
    [[NSStatusBar systemStatusBar] removeStatusItem:item_];
    item_ = nil;
  }
  if (NSApp.delegate == self) {
    NSApp.delegate = nil;
  }
  [welcomeWindow_ close];
  [keysWindow_ close];
  [settingsWindow_ close];
}

// Only visible while the app is regular (a window is open): Settings, Quit,
// the edit commands the PIN fields need, and Close / Minimize for windows.
- (void)installMainMenu {
  NSMenu* bar = [[NSMenu alloc] init];
  NSMenu* app = [[NSMenu alloc] initWithTitle:@"swpasskey"];
  [app addItem:menu_item(@"Settings…", @selector(showSettings:), @",", self)];
  [app addItem:[NSMenuItem separatorItem]];
  [app addItem:menu_item(@"Quit swpasskey", @selector(quit:), @"q", self)];
  NSMenu* edit = [[NSMenu alloc] initWithTitle:@"Edit"];
  [edit addItem:menu_item(@"Cut", @selector(cut:), @"x")];
  [edit addItem:menu_item(@"Copy", @selector(copy:), @"c")];
  [edit addItem:menu_item(@"Paste", @selector(paste:), @"v")];
  [edit addItem:menu_item(@"Select All", @selector(selectAll:), @"a")];
  [edit addItem:[NSMenuItem separatorItem]];
  [edit addItem:menu_item(@"Find", @selector(focusSearch:), @"f", self)];
  NSMenu* window = [[NSMenu alloc] initWithTitle:@"Window"];
  [window addItem:menu_item(@"Close", @selector(performClose:), @"w")];
  [window addItem:menu_item(@"Minimize", @selector(performMiniaturize:), @"m")];
  [window addItem:[NSMenuItem separatorItem]];
  [window addItem:menu_item(@"Passkeys", @selector(showKeys:), @"k", self)];
  for (NSMenu* sub in @[ app, edit, window ]) {
    NSMenuItem* holder = [[NSMenuItem alloc] initWithTitle:sub.title action:nil keyEquivalent:@""];
    holder.submenu = sub;
    [bar addItem:holder];
  }
  NSApp.mainMenu = bar;
  NSApp.windowsMenu = window;
}

#pragma mark - Dock

- (BOOL)wantsDockIcon {
  BOOL visible = menuOpen_;
  for (NSWindow* w : {welcomeWindow_, keysWindow_, settingsWindow_}) {
    if (w != nil && (w.visible || w.miniaturized)) visible = YES;
  }
  return visible;
}

// Showing the Dock icon is immediate (a window cannot take focus without
// it). Hiding is debounced by kDockHideDelay: every policy change makes the
// menu bar re-lay out, so closing and reopening windows, or glancing at the
// status menu, must not flip it back and forth.
- (void)updateDockPolicy {
  if (tornDown_) return;
  [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(hideDockIconNow) object:nil];
  if ([self wantsDockIcon]) {
    if (NSApp.activationPolicy != NSApplicationActivationPolicyRegular) {
      [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    }
    return;
  }
  if (NSApp.activationPolicy == NSApplicationActivationPolicyAccessory) return;
  [self performSelector:@selector(hideDockIconNow)
             withObject:nil
             afterDelay:kDockHideDelay
                inModes:@[ NSRunLoopCommonModes ]];
}

- (void)hideDockIconNow {
  if (tornDown_ || [self wantsDockIcon]) return;
  if (NSApp.modalWindow != nil) {
    // An approval prompt is up: hiding the app would hide the prompt too.
    [self updateDockPolicy];
    return;
  }
  if (!NSApp.active) {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    return;
  }
  // Dropping to accessory while frontmost pulls our menus out from under
  // the menu bar in place. Hand the menu bar back to the previous app first,
  // then switch once we are in the background.
  [NSApp hide:nil];
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 150 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
    if (!tornDown_ && ![self wantsDockIcon] && NSApp.modalWindow == nil) {
      [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    }
  });
}

// Deferred one turn: the window being closed is still visible here, and a
// menu action (Passkeys…, Settings…) runs after menuDidClose:.
- (void)scheduleDockUpdate {
  dispatch_async(dispatch_get_main_queue(), ^{
    [self updateDockPolicy];
  });
}

- (void)present:(NSWindow*)window {
  // Opened from the menu bar: come to the Space and display the user is on
  // instead of switching Spaces or opening on a far-away screen. A window
  // that is already open, or remembered on this screen, stays where it is.
  window.collectionBehavior |= NSWindowCollectionBehaviorMoveToActiveSpace;
  if (!window.visible) {
    NSScreen* screen = [NSScreen mainScreen];
    const NSPoint mouse = [NSEvent mouseLocation];
    for (NSScreen* s in [NSScreen screens]) {
      if (NSPointInRect(mouse, s.frame)) screen = s;
    }
    if (screen != nil && !NSIntersectsRect(window.frame, screen.visibleFrame)) {
      const NSRect area = screen.visibleFrame;
      const NSSize size = window.frame.size;
      [window setFrameOrigin:NSMakePoint(NSMidX(area) - size.width / 2, NSMidY(area) - size.height / 2)];
    }
  }
  [NSApp unhide:nil];
  [self updateDockPolicy];
  [window makeKeyAndOrderFront:nil];
  [window orderFrontRegardless];
  activate_app();
  // The policy switch to regular lands on the next turn; activate again then
  // so the window really ends up in front of the app that was active.
  dispatch_async(dispatch_get_main_queue(), ^{
    activate_app();
    [window makeKeyAndOrderFront:nil];
  });
}

- (void)windowWillClose:(NSNotification*)notification {
  if (notification.object == keysWindow_) {
    [keysTimer_ invalidate];
    keysTimer_ = nil;
  }
  [self scheduleDockUpdate];
}

- (void)windowDidBecomeKey:(NSNotification*)notification {
  if (notification.object == keysWindow_) [self reloadKeys];
  if (notification.object == settingsWindow_) [self refreshSettings];
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication*)sender {
  // Dock › Quit or logout: stop the daemon loop, which stops NSApp and lets
  // main() shut down cleanly. Later (not Cancel) so logout is not vetoed;
  // the process exits before a reply is needed.
  [self quit:sender];
  return NSTerminateLater;
}

- (BOOL)applicationShouldHandleReopen:(NSApplication*)sender hasVisibleWindows:(BOOL)flag {
  if (!flag) [self showKeys:sender];
  return NO;
}

#pragma mark - welcome

- (void)showWelcome {
  if (welcomeWindow_ == nil) {
    [self buildWelcomeWindow];
  }
  [self present:welcomeWindow_];
}

- (void)buildWelcomeWindow {
  const CGFloat W = 400;
  welcomeWindow_ = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, W, 200)
                                               styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                          NSWindowStyleMaskFullSizeContentView)
                                                 backing:NSBackingStoreBuffered
                                                   defer:NO];
  welcomeWindow_.titlebarAppearsTransparent = YES;
  welcomeWindow_.titleVisibility = NSWindowTitleHidden;
  welcomeWindow_.movableByWindowBackground = YES;
  welcomeWindow_.releasedWhenClosed = NO;
  welcomeWindow_.delegate = self;

  NSImageView* icon = [NSImageView imageViewWithImage:[NSApp applicationIconImage]];
  [icon.widthAnchor constraintEqualToConstant:64].active = YES;
  [icon.heightAnchor constraintEqualToConstant:64].active = YES;
  NSTextField* title = label(@"swpasskey is ready");
  title.font = [NSFont systemFontOfSize:17 weight:NSFontWeightSemibold];
  NSTextField* body = [NSTextField wrappingLabelWithString:
      @"Websites can now use swpasskey as a security key. It runs in the menu bar: click the key icon "
      @"to see your passkeys or open Settings."];
  body.alignment = NSTextAlignmentCenter;
  body.textColor = [NSColor secondaryLabelColor];
  body.selectable = NO;

  welcomeHide_ = [NSButton checkboxWithTitle:@"Don’t show this again" target:nil action:nil];
  NSButton* ok = [NSButton buttonWithTitle:@"OK" target:self action:@selector(dismissWelcome:)];
  ok.keyEquivalent = @"\r";
  ok.controlSize = NSControlSizeLarge;
  [ok.widthAnchor constraintGreaterThanOrEqualToConstant:90].active = YES;
  NSStackView* footer = [NSStackView stackViewWithViews:@[ welcomeHide_, ok ]];
  footer.distribution = NSStackViewDistributionEqualSpacing;

  NSStackView* stack = [NSStackView stackViewWithViews:@[ icon, title, body, footer ]];
  stack.orientation = NSUserInterfaceLayoutOrientationVertical;
  stack.alignment = NSLayoutAttributeCenterX;
  stack.spacing = 8;
  [stack setCustomSpacing:14 afterView:icon];
  [stack setCustomSpacing:22 afterView:body];
  stack.edgeInsets = NSEdgeInsetsMake(32, 28, 20, 28);
  stack.translatesAutoresizingMaskIntoConstraints = NO;
  NSView* content = welcomeWindow_.contentView;
  [content addSubview:stack];
  [NSLayoutConstraint activateConstraints:@[
    [stack.leadingAnchor constraintEqualToAnchor:content.leadingAnchor],
    [stack.trailingAnchor constraintEqualToAnchor:content.trailingAnchor],
    [stack.topAnchor constraintEqualToAnchor:content.topAnchor],
    [stack.bottomAnchor constraintEqualToAnchor:content.bottomAnchor],
    [content.widthAnchor constraintEqualToConstant:W],
    [body.widthAnchor constraintEqualToConstant:W - 56],
    [footer.widthAnchor constraintEqualToConstant:W - 56],
  ]];
  [welcomeWindow_ layoutIfNeeded];
  [welcomeWindow_ center];
}

- (void)dismissWelcome:(id)sender {
  if (welcomeHide_.state == NSControlStateValueOn) {
    [[NSUserDefaults standardUserDefaults] setBool:YES forKey:@(kHideWelcomeDefault)];
  }
  [welcomeWindow_ close];
}

#pragma mark - menu

- (void)menuNeedsUpdate:(NSMenu*)menu {
  [self refreshSummary];
}

- (void)menuWillOpen:(NSMenu*)menu {
  menuOpen_ = YES;
  [self updateDockPolicy];
}

- (void)menuDidClose:(NSMenu*)menu {
  menuOpen_ = NO;
  [self scheduleDockUpdate];
}

- (void)refreshSummary {
  const std::size_t n = deps_.store != nullptr ? deps_.store->size() : 0;
  summaryItem_.title = ns(swpk::ui::keys_summary(n, deps_.key_backend));
}

- (void)quit:(id)sender {
  swpk::log::info("menubar_quit");
  if (deps_.quit) {
    deps_.quit();
  }
}

#pragma mark - Passkeys window

- (void)showKeys:(id)sender {
  if (keysWindow_ == nil) {
    [self buildKeysWindow];
  }
  [self reloadKeys];
  [self present:keysWindow_];
  [self startKeysTimer];
}

// Live list: sites register and sign in while the window is open. Poll the
// in-process store every 2 s and reload only when a row changed; refresh
// the relative "Last Used" text every 30 s.
- (void)startKeysTimer {
  if (keysTimer_ != nil) return;
  keysTicks_ = 0;
  __weak SWPKMenuController* weak = self;
  keysTimer_ = [NSTimer timerWithTimeInterval:2.0
                                      repeats:YES
                                        block:^(NSTimer*) {
                                          [weak keysTimerFired];
                                        }];
  keysTimer_.tolerance = 0.5;
  [[NSRunLoop mainRunLoop] addTimer:keysTimer_ forMode:NSRunLoopCommonModes];
}

- (void)keysTimerFired {
  if (tornDown_ || !keysWindow_.visible) return;
  if (deps_.store == nullptr) return;
  auto fresh = swpk::ui::key_rows(*deps_.store);
  const bool changed =
      fresh.size() != allRows_.size() ||
      !std::equal(fresh.begin(), fresh.end(), allRows_.begin(), [](const auto& a, const auto& b) {
        return a.cred_id_hex == b.cred_id_hex && a.sign_count == b.sign_count &&
               a.last_used_unix == b.last_used_unix && a.user_name == b.user_name;
      });
  if (changed) {
    allRows_ = std::move(fresh);
    [self applyFilter];
    [self refreshSummary];
  } else if (++keysTicks_ % 15 == 0 && table_.numberOfRows > 0) {
    const NSInteger col = [table_ columnWithIdentifier:@"used"];
    if (col >= 0) {
      [table_ reloadDataForRowIndexes:[NSIndexSet indexSetWithIndexesInRange:NSMakeRange(0, rows_.size())]
                        columnIndexes:[NSIndexSet indexSetWithIndex:static_cast<NSUInteger>(col)]];
    }
  }
}

- (void)focusSearch:(id)sender {
  if (keysWindow_.visible) [keysWindow_ makeFirstResponder:search_];
}

- (void)buildKeysWindow {
  const NSRect frame = NSMakeRect(0, 0, 760, 420);
  keysWindow_ = [[NSWindow alloc] initWithContentRect:frame
                                            styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                       NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable |
                                                       NSWindowStyleMaskFullSizeContentView)
                                              backing:NSBackingStoreBuffered
                                                defer:NO];
  keysWindow_.title = @"Passkeys";
  keysWindow_.subtitle = @"";
  keysWindow_.releasedWhenClosed = NO;
  keysWindow_.minSize = NSMakeSize(560, 260);
  keysWindow_.delegate = self;
  keysWindow_.toolbarStyle = NSWindowToolbarStyleUnified;
  keysWindow_.frameAutosaveName = @"SWPKPasskeysWindow";

  NSToolbar* toolbar = [[NSToolbar alloc] initWithIdentifier:@"SWPKPasskeysToolbar"];
  toolbar.delegate = self;
  toolbar.displayMode = NSToolbarDisplayModeIconOnly;
  keysWindow_.toolbar = toolbar;

  NSScrollView* scroll = [[NSScrollView alloc] initWithFrame:frame];
  scroll.hasVerticalScroller = YES;
  scroll.autohidesScrollers = YES;
  scroll.borderType = NSNoBorder;
  scroll.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

  table_ = [[NSTableView alloc] initWithFrame:scroll.bounds];
  table_.style = NSTableViewStyleInset;
  table_.dataSource = self;
  table_.delegate = self;
  table_.allowsMultipleSelection = NO;
  table_.usesAlternatingRowBackgroundColors = YES;
  table_.rowHeight = 28;
  table_.columnAutoresizingStyle = NSTableViewUniformColumnAutoresizingStyle;
  table_.target = self;
  struct Col {
    NSString* id;
    NSString* title;
    CGFloat width;
    BOOL ascending;  // first click: A→Z for text, newest / most first for dates and counts
  };
  const Col cols[] = {
      {@"site", @"Website", 185, YES},   {@"account", @"Account", 190, YES},
      {@"used", @"Last Used", 115, NO},  {@"created", @"Created", 115, NO},
      {@"count", @"Sign-ins", 84, NO},
  };
  for (const auto& c : cols) {
    NSTableColumn* col = [[NSTableColumn alloc] initWithIdentifier:c.id];
    col.title = c.title;
    col.width = c.width;
    col.minWidth = 50;
    col.sortDescriptorPrototype = [NSSortDescriptor sortDescriptorWithKey:c.id ascending:c.ascending];
    if ([c.id isEqualToString:@"count"]) {
      col.headerCell.alignment = NSTextAlignmentRight;
    }
    [table_ addTableColumn:col];
  }
  // Column widths and the chosen sort survive relaunches; first run shows
  // the most recently used passkeys on top.
  table_.autosaveName = @"SWPKPasskeysTable";
  table_.autosaveTableColumns = YES;
  if (table_.sortDescriptors.count == 0) {
    table_.sortDescriptors = @[ [NSSortDescriptor sortDescriptorWithKey:@"used" ascending:NO] ];
  }
  NSMenu* context = [[NSMenu alloc] init];
  [context addItem:menu_item(@"Copy Website", @selector(copySite:), @"", self)];
  [context addItem:[NSMenuItem separatorItem]];
  [context addItem:menu_item(@"Delete Passkey…", @selector(deleteSelected:), @"", self)];
  table_.menu = context;
  scroll.documentView = table_;

  NSView* content = keysWindow_.contentView;
  scroll.frame = content.bounds;
  [content addSubview:scroll];
  [table_ sizeToFit];

  emptyTitle_ = label(@"No Passkeys");
  emptyTitle_.font = [NSFont systemFontOfSize:17 weight:NSFontWeightSemibold];
  emptyTitle_.textColor = [NSColor secondaryLabelColor];
  NSTextField* emptyBody = note(@"When you create a passkey on a website with swpasskey, it appears here.");
  emptyBody.alignment = NSTextAlignmentCenter;
  NSStackView* empty = [NSStackView stackViewWithViews:@[ emptyTitle_, emptyBody ]];
  empty.orientation = NSUserInterfaceLayoutOrientationVertical;
  empty.spacing = 6;
  empty.translatesAutoresizingMaskIntoConstraints = NO;
  [content addSubview:empty];
  [NSLayoutConstraint activateConstraints:@[
    [empty.centerXAnchor constraintEqualToAnchor:content.centerXAnchor],
    [empty.centerYAnchor constraintEqualToAnchor:content.centerYAnchor constant:20],
    [emptyBody.widthAnchor constraintLessThanOrEqualToConstant:320],
  ]];
  emptyState_ = empty;
  [keysWindow_ center];
}

- (NSArray<NSToolbarItemIdentifier>*)toolbarDefaultItemIdentifiers:(NSToolbar*)toolbar {
  return @[ NSToolbarFlexibleSpaceItemIdentifier, kDeleteItem, kSearchItem ];
}

- (NSArray<NSToolbarItemIdentifier>*)toolbarAllowedItemIdentifiers:(NSToolbar*)toolbar {
  return [self toolbarDefaultItemIdentifiers:toolbar];
}

- (NSToolbarItem*)toolbar:(NSToolbar*)toolbar
        itemForItemIdentifier:(NSToolbarItemIdentifier)identifier
    willBeInsertedIntoToolbar:(BOOL)flag {
  if ([identifier isEqualToString:kSearchItem]) {
    NSSearchToolbarItem* item = [[NSSearchToolbarItem alloc] initWithItemIdentifier:identifier];
    search_ = item.searchField;
    search_.placeholderString = @"Search websites and accounts";
    search_.delegate = self;
    search_.target = self;
    search_.action = @selector(searchChanged:);
    return item;
  }
  NSToolbarItem* item = [[NSToolbarItem alloc] initWithItemIdentifier:identifier];
  item.target = self;
  item.bordered = YES;
  if ([identifier isEqualToString:kDeleteItem]) {
    item.label = @"Delete";
    item.toolTip = @"Delete the selected passkey";
    item.image = [NSImage imageWithSystemSymbolName:@"trash" accessibilityDescription:@"Delete"];
    item.action = @selector(deleteSelected:);
    item.autovalidates = NO;
    item.enabled = NO;
    deleteItem_ = item;
  }
  return item;
}

- (void)searchChanged:(id)sender {
  [self applyFilter];
}

- (void)controlTextDidChange:(NSNotification*)notification {
  if (notification.object == search_) [self applyFilter];
}

- (void)reloadKeys {
  allRows_ = deps_.store != nullptr ? swpk::ui::key_rows(*deps_.store) : std::vector<swpk::ui::KeyRow>{};
  [self applyFilter];
  [self refreshSummary];
}

- (void)applyFilter {
  NSString* q = search_ != nil ? search_.stringValue : @"";
  q = [q stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
  rows_.clear();
  for (const auto& r : allRows_) {
    if (q.length == 0 || [site_text(r) localizedCaseInsensitiveContainsString:q] ||
        [account_text(r) localizedCaseInsensitiveContainsString:q]) {
      rows_.push_back(r);
    }
  }
  [self sortRows];
  [self reloadTablePreservingSelection];
  const bool none = allRows_.empty();
  emptyTitle_.stringValue = none ? @"No Passkeys" : @"No Results";
  emptyState_.hidden = !rows_.empty();
  table_.enclosingScrollView.hidden = rows_.empty();
  if (none) {
    keysWindow_.subtitle = @"";
  } else {
    keysWindow_.subtitle = ns(swpk::ui::keys_summary(allRows_.size(), deps_.key_backend));
  }
  [self updateDeleteItem];
}

// Sorts rows_ by the header's sort descriptor; ties fall back to website,
// then account, so the order never jumps between reloads.
- (void)sortRows {
  NSSortDescriptor* d = table_.sortDescriptors.firstObject;
  NSString* key = d != nil ? d.key : @"used";
  const bool asc = d != nil ? d.ascending : false;
  auto three_way = [](auto x, auto y) {
    return x < y ? NSOrderedAscending : x > y ? NSOrderedDescending : NSOrderedSame;
  };
  auto by_name = [](const swpk::ui::KeyRow& a, const swpk::ui::KeyRow& b) {
    NSComparisonResult r = [site_text(a) localizedStandardCompare:site_text(b)];
    return r != NSOrderedSame ? r : [account_text(a) localizedStandardCompare:account_text(b)];
  };
  auto cmp = [&](const swpk::ui::KeyRow& a, const swpk::ui::KeyRow& b) -> bool {
    NSComparisonResult r = NSOrderedSame;
    if ([key isEqualToString:@"site"]) {
      r = by_name(a, b);
    } else if ([key isEqualToString:@"account"]) {
      r = [account_text(a) localizedStandardCompare:account_text(b)];
    } else if ([key isEqualToString:@"used"]) {
      r = three_way(a.last_used_unix, b.last_used_unix);
    } else if ([key isEqualToString:@"created"]) {
      r = three_way(a.created_unix, b.created_unix);
    } else if ([key isEqualToString:@"count"]) {
      r = three_way(a.sign_count, b.sign_count);
    }
    if (r != NSOrderedSame) {
      return asc ? r == NSOrderedAscending : r == NSOrderedDescending;
    }
    return by_name(a, b) == NSOrderedAscending;  // tie-break always A→Z
  };
  std::stable_sort(rows_.begin(), rows_.end(), cmp);
}

// Reloads the table and keeps the same passkey selected when it is still
// listed (sorting and refreshing move rows around).
- (void)reloadTablePreservingSelection {
  const NSInteger sel = table_.selectedRow;
  const std::string keep =
      sel >= 0 && static_cast<std::size_t>(sel) < shownIds_.size() ? shownIds_[static_cast<std::size_t>(sel)] : "";
  shownIds_.clear();
  for (const auto& r : rows_) shownIds_.push_back(r.cred_id_hex);
  [table_ reloadData];
  const auto it = std::find(shownIds_.begin(), shownIds_.end(), keep);
  if (!keep.empty() && it != shownIds_.end()) {
    const NSInteger row = static_cast<NSInteger>(it - shownIds_.begin());
    [table_ selectRowIndexes:[NSIndexSet indexSetWithIndex:static_cast<NSUInteger>(row)] byExtendingSelection:NO];
    [table_ scrollRowToVisible:row];
  } else {
    [table_ deselectAll:nil];
  }
}

- (void)tableView:(NSTableView*)tableView sortDescriptorsDidChange:(NSArray<NSSortDescriptor*>*)oldDescriptors {
  [self sortRows];
  [self reloadTablePreservingSelection];
  [self updateDeleteItem];
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tableView {
  return static_cast<NSInteger>(rows_.size());
}

- (NSView*)tableView:(NSTableView*)tableView viewForTableColumn:(NSTableColumn*)column row:(NSInteger)row {
  if (row < 0 || static_cast<std::size_t>(row) >= rows_.size()) return nil;
  const auto& r = rows_[static_cast<std::size_t>(row)];
  NSString* ident = column.identifier;
  NSTableCellView* view = [tableView makeViewWithIdentifier:ident owner:self];
  if (view == nil) {
    // A bare text field would sit at the top of the row; center it.
    view = [[NSTableCellView alloc] init];
    view.identifier = ident;
    NSTextField* tf = label(@"");
    tf.lineBreakMode = NSLineBreakByTruncatingTail;
    tf.translatesAutoresizingMaskIntoConstraints = NO;
    [view addSubview:tf];
    view.textField = tf;
    [NSLayoutConstraint activateConstraints:@[
      [tf.leadingAnchor constraintEqualToAnchor:view.leadingAnchor constant:2],
      [tf.trailingAnchor constraintEqualToAnchor:view.trailingAnchor constant:-2],
      [tf.centerYAnchor constraintEqualToAnchor:view.centerYAnchor],
    ]];
  }
  NSTextField* cell = view.textField;
  cell.textColor = [NSColor labelColor];
  cell.alignment = NSTextAlignmentNatural;
  cell.toolTip = nil;
  if ([ident isEqualToString:@"site"]) {
    cell.stringValue = site_text(r);
    cell.toolTip = r.rp_name.empty() || r.rp_name == r.rp_id
                       ? [NSString stringWithFormat:@"Stored in %@", ns(r.backend)]
                       : [NSString stringWithFormat:@"%@ · stored in %@", ns(r.rp_name), ns(r.backend)];
  } else if ([ident isEqualToString:@"account"]) {
    cell.stringValue = account_text(r);
    if (!r.u2f && !r.user_display.empty() && r.user_display != r.user_name) cell.toolTip = ns(r.user_display);
    if (r.u2f) cell.textColor = [NSColor secondaryLabelColor];
  } else if ([ident isEqualToString:@"used"]) {
    cell.stringValue = format_recent(r.last_used_unix);
    cell.toolTip = format_full(r.last_used_unix);
    if (r.last_used_unix == 0) cell.textColor = [NSColor secondaryLabelColor];
  } else if ([ident isEqualToString:@"created"]) {
    cell.stringValue = format_day(r.created_unix);
    cell.toolTip = format_full(r.created_unix);
  } else if ([ident isEqualToString:@"count"]) {
    cell.stringValue = [NSString stringWithFormat:@"%u", r.sign_count];
    cell.alignment = NSTextAlignmentRight;
  }
  return view;
}

- (void)tableViewSelectionDidChange:(NSNotification*)notification {
  [self updateDeleteItem];
}

- (void)updateDeleteItem {
  deleteItem_.enabled = table_.selectedRow >= 0;
}

// Context menu acts on the clicked row; otherwise on the selection.
- (NSInteger)targetRow {
  return table_.clickedRow >= 0 ? table_.clickedRow : table_.selectedRow;
}

- (BOOL)validateMenuItem:(NSMenuItem*)item {
  if (item.action == @selector(deleteSelected:) || item.action == @selector(copySite:)) {
    return [self targetRow] >= 0;
  }
  if (item.action == @selector(focusSearch:)) {
    return keysWindow_.keyWindow;
  }
  return YES;
}

- (void)copySite:(id)sender {
  const NSInteger sel = [self targetRow];
  if (sel < 0 || static_cast<std::size_t>(sel) >= rows_.size()) return;
  [NSPasteboard.generalPasteboard clearContents];
  [NSPasteboard.generalPasteboard setString:ns(rows_[static_cast<std::size_t>(sel)].rp_id)
                                    forType:NSPasteboardTypeString];
}

- (void)deleteSelected:(id)sender {
  const NSInteger sel = [self targetRow];
  if (sel < 0 || static_cast<std::size_t>(sel) >= rows_.size()) return;
  const swpk::ui::KeyRow row = rows_[static_cast<std::size_t>(sel)];
  // Deleting cannot be undone and may lock the user out of the account, so
  // they type the account name (the website for U2F rows, which have none)
  // before Delete turns on.
  const bool by_account = !row.u2f && account_text(row).length > 0;
  NSString* expected = by_account ? account_text(row) : ns(row.rp_id);
  NSAlert* alert = [[NSAlert alloc] init];
  alert.alertStyle = NSAlertStyleWarning;
  alert.messageText = @"Delete This Passkey?";
  alert.informativeText = [NSString stringWithFormat:
      @"You won’t be able to sign in to %@ with it. This can’t be undone.\n\nTo confirm, type %@:",
      ns(row.rp_id), by_account ? @"the account name" : @"the website"];
  NSButton* del = [alert addButtonWithTitle:@"Delete"];
  del.hasDestructiveAction = YES;
  del.enabled = NO;
  [alert addButtonWithTitle:@"Cancel"].keyEquivalent = @"\033";
  NSTextField* field = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 24)];
  field.placeholderString = expected;
  field.accessibilityLabel = by_account ? @"Account name" : @"Website";
  alert.accessoryView = field;
  alert.window.initialFirstResponder = field;
  id observer = [[NSNotificationCenter defaultCenter]
      addObserverForName:NSControlTextDidChangeNotification
                  object:field
                   queue:nil
              usingBlock:^(NSNotification*) {
                NSString* typed = [field.stringValue
                    stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
                del.enabled = [typed isEqualToString:expected];
              }];
  [alert beginSheetModalForWindow:keysWindow_ completionHandler:^(NSModalResponse response) {
    [[NSNotificationCenter defaultCenter] removeObserver:observer];
    if (response != NSAlertFirstButtonReturn || !del.enabled) return;
    [self deleteCredential:row];
  }];
}

- (void)deleteCredential:(const swpk::ui::KeyRow&)row {
  const auto id = unhex(row.cred_id_hex);
  if (!deps_.delete_key || id.size() != 32) {
    return;
  }
  auto r = deps_.delete_key(id);
  if (!r) {
    NSAlert* err = [[NSAlert alloc] init];
    err.alertStyle = NSAlertStyleCritical;
    err.messageText = @"Unable to Delete Passkey";
    err.informativeText =
        @"Try again. If it keeps failing, check the log in ~/Library/Logs/swpasskey.";
    [err beginSheetModalForWindow:keysWindow_ completionHandler:nil];
    swpk::log::warn("menubar_delete_failed",
                    {{"cred_id", row.cred_id_hex.substr(0, 16)},
                     {"error", std::to_string(static_cast<unsigned>(r.error()))}});
  } else {
    swpk::log::warn("menubar_delete", {{"cred_id", row.cred_id_hex.substr(0, 16)}, {"rp", row.rp_id}});
  }
  [self reloadKeys];
}

#pragma mark - Settings window

- (void)showSettings:(id)sender {
  if (settingsWindow_ == nil) {
    [self buildSettingsWindow];
  }
  [self refreshSettings];
  [self present:settingsWindow_];
}

- (void)refreshSettings {
  [self refreshLoginState];
  [self refreshPinState];
  welcomeCheckbox_.state = [[NSUserDefaults standardUserDefaults] boolForKey:@(kHideWelcomeDefault)]
                               ? NSControlStateValueOff
                               : NSControlStateValueOn;
}

- (void)buildSettingsWindow {
  NSTabViewController* tabs = [[NSTabViewController alloc] init];
  tabs.tabStyle = NSTabViewControllerTabStyleToolbar;
  for (NSViewController* vc in @[ [self generalPane], [self securityPane], [self aboutPane] ]) {
    NSTabViewItem* item = [NSTabViewItem tabViewItemWithViewController:vc];
    item.label = vc.title;
    item.image = vc.representedObject;
    [tabs addTabViewItem:item];
  }
  settingsWindow_ = [NSWindow windowWithContentViewController:tabs];
  settingsWindow_.styleMask = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable;
  settingsWindow_.toolbarStyle = NSWindowToolbarStylePreference;
  settingsWindow_.releasedWhenClosed = NO;
  settingsWindow_.delegate = self;
  [settingsWindow_ center];
}

- (NSViewController*)generalPane {
  loginCheckbox_ = [NSButton checkboxWithTitle:@"Open swpasskey at login" target:self action:@selector(toggleLogin:)];
  loginNote_ = note(@"");
  // Indented under the checkbox title (checkbox glyph + gap is about 20 pt).
  [loginNote_.widthAnchor constraintEqualToConstant:kSettingsWidth - 56 - 20].active = YES;
  welcomeCheckbox_ = [NSButton checkboxWithTitle:@"Show the welcome window when swpasskey opens"
                                          target:self
                                          action:@selector(toggleWelcome:)];

  levelPopup_ = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO];
  [levelPopup_.widthAnchor constraintEqualToConstant:240].active = YES;
  for (const auto& l : kLevels) {
    [levelPopup_ addItemWithTitle:l.title];
    levelPopup_.lastItem.representedObject = @(l.key);
    if (l.level == swpk::log::level()) [levelPopup_ selectItem:levelPopup_.lastItem];
  }
  levelPopup_.target = self;
  levelPopup_.action = @selector(changeLogLevel:);
  NSStackView* levelRow = [NSStackView stackViewWithViews:@[ label(@"Log detail:"), levelPopup_ ]];
  levelRow.spacing = 8;
  NSTextField* levelNote = note(@"Saved to ~/Library/Logs/swpasskey. Use Detailed only while troubleshooting.");

  NSViewController* vc = pane(@"General", @"gearshape", @[
    loginCheckbox_, loginNote_, welcomeCheckbox_, separator(), levelRow, levelNote,
  ]);
  NSStackView* stack = vc.view.subviews.firstObject;
  [stack setCustomSpacing:2 afterView:loginCheckbox_];
  [stack setCustomSpacing:14 afterView:loginNote_];
  [stack setCustomSpacing:14 afterView:welcomeCheckbox_];
  [loginNote_.leadingAnchor constraintEqualToAnchor:stack.leadingAnchor constant:28 + 20].active = YES;
  return vc;
}

- (NSViewController*)securityPane {
  pinStatus_ = label(@"");
  pinButton_ = [NSButton buttonWithTitle:@"Set PIN…" target:self action:@selector(setPin:)];
  NSStackView* pinRow = [NSStackView stackViewWithViews:@[ pinStatus_, pinButton_ ]];
  pinRow.distribution = NSStackViewDistributionEqualSpacing;
  [pinRow.widthAnchor constraintEqualToConstant:kSettingsWidth - 56].active = YES;
  NSTextField* pinNote = note(
      @"Some websites ask for a PIN before they accept a passkey. You’ll enter this PIN in the browser. "
      @"Changing it keeps your saved passkeys.");
  NSTextField* presenceNote = note(
      @"swpasskey asks you before a website can create or use a passkey. Requests you don’t answer "
      @"are declined after 30 seconds.");
  return pane(@"Security", @"lock", @[
    heading(@"Security Key PIN"), pinRow, pinNote, separator(), heading(@"Approvals"), presenceNote,
  ]);
}

- (NSViewController*)aboutPane {
  NSImageView* icon = [NSImageView imageViewWithImage:[NSApp applicationIconImage]];
  [icon.widthAnchor constraintEqualToConstant:48].active = YES;
  [icon.heightAnchor constraintEqualToConstant:48].active = YES;
  NSTextField* name = label(@"swpasskey");
  name.font = [NSFont systemFontOfSize:15 weight:NSFontWeightSemibold];
  NSTextField* version = note([NSString stringWithFormat:@"Version %@", ns(deps_.version)]);
  NSStackView* titles = [NSStackView stackViewWithViews:@[ name, version ]];
  titles.orientation = NSUserInterfaceLayoutOrientationVertical;
  titles.alignment = NSLayoutAttributeLeading;
  titles.spacing = 2;
  NSStackView* header = [NSStackView stackViewWithViews:@[ icon, titles ]];
  header.spacing = 12;

  auto key = [](NSString* s) {
    NSTextField* f = label(s);
    [f setContentCompressionResistancePriority:NSLayoutPriorityRequired
                                forOrientation:NSLayoutConstraintOrientationHorizontal];
    return f;
  };
  auto value = [](NSString* s) {
    NSTextField* f = label(s);
    f.selectable = YES;
    f.toolTip = s;
    [f setContentCompressionResistancePriority:NSLayoutPriorityDefaultLow
                                forOrientation:NSLayoutConstraintOrientationHorizontal];
    return f;
  };
  // Folder, not file: shorter, and Finder opens on the thing people look for.
  NSString* folder = [ns(deps_.store_path).stringByDeletingLastPathComponent stringByAbbreviatingWithTildeInPath];
  NSButton* reveal = [NSButton buttonWithImage:[NSImage imageWithSystemSymbolName:@"arrow.right.circle.fill"
                                                         accessibilityDescription:@"Show in Finder"]
                                        target:self
                                        action:@selector(revealStore:)];
  reveal.bordered = NO;
  reveal.contentTintColor = [NSColor secondaryLabelColor];
  reveal.toolTip = @"Show in Finder";
  NSStackView* folderRow = [NSStackView stackViewWithViews:@[ value(folder), reveal ]];
  folderRow.spacing = 4;
  NSGridView* grid = [NSGridView gridViewWithViews:@[
    @[ key(@"Key storage:"), value(ns(deps_.key_backend)) ],
    @[ key(@"Serial number:"), value(ns(deps_.serial)) ],
    @[ key(@"Data folder:"), folderRow ],
  ]];
  grid.rowSpacing = 6;
  grid.columnSpacing = 8;
  [grid columnAtIndex:0].xPlacement = NSGridCellPlacementTrailing;
  for (NSInteger i = 0; i < grid.numberOfRows; ++i) {
    [grid rowAtIndex:i].yPlacement = NSGridCellPlacementCenter;
  }
  NSTextField* disclaimer = note(
      @"swpasskey is a software security key. Secure Enclave and TPM keys can’t be copied off this Mac, "
      @"but any app running as you can ask to use them, so each request needs your approval.");
  return pane(@"About", @"info.circle", @[ header, separator(), grid, separator(), disclaimer ]);
}

- (void)revealStore:(id)sender {
  NSURL* url = [NSURL fileURLWithPath:ns(deps_.store_path)];
  [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[ url ]];
}

- (void)toggleWelcome:(id)sender {
  [[NSUserDefaults standardUserDefaults] setBool:welcomeCheckbox_.state != NSControlStateValueOn
                                          forKey:@(kHideWelcomeDefault)];
}

- (void)refreshPinState {
  if (pinBusy_) return;
  const bool configured = deps_.store != nullptr && deps_.store->pin().hash.has_value();
  pinStatus_.stringValue = configured ? @"A PIN is set." : @"No PIN is set.";
  pinButton_.title = configured ? @"Change PIN…" : @"Set PIN…";
  pinButton_.enabled = static_cast<bool>(deps_.control_request);
}

- (void)setPin:(id)sender {
  if (pinBusy_ || !deps_.control_request) return;
  const bool configured = deps_.store != nullptr && deps_.store->pin().hash.has_value();
  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = configured ? @"Change Security Key PIN" : @"Set Security Key PIN";
  alert.informativeText = @"Use at least 4 characters. Websites that ask for a PIN will use this one.";
  NSButton* save = [alert addButtonWithTitle:configured ? @"Change PIN" : @"Set PIN"];
  [alert addButtonWithTitle:@"Cancel"];
  NSSecureTextField* pin = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 22)];
  pin.placeholderString = @"New PIN";
  pin.accessibilityLabel = @"New PIN";
  NSSecureTextField* repeat = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 22)];
  repeat.placeholderString = @"Confirm PIN";
  repeat.accessibilityLabel = @"Confirm PIN";
  NSStackView* form = [NSStackView stackViewWithViews:@[ pin, repeat ]];
  form.orientation = NSUserInterfaceLayoutOrientationVertical;
  form.spacing = 8;
  form.frame = NSMakeRect(0, 0, 260, 52);
  [pin.widthAnchor constraintEqualToConstant:260].active = YES;
  [repeat.widthAnchor constraintEqualToConstant:260].active = YES;
  pin.nextKeyView = repeat;
  repeat.nextKeyView = save;
  alert.accessoryView = form;
  alert.window.initialFirstResponder = pin;
  [alert beginSheetModalForWindow:settingsWindow_ completionHandler:^(NSModalResponse response) {
    NSString* value = pin.stringValue;
    const BOOL matches = [value isEqualToString:repeat.stringValue];
    pin.stringValue = @"";
    repeat.stringValue = @"";
    if (response != NSAlertFirstButtonReturn || tornDown_) return;
    const NSUInteger bytes = [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    const NSUInteger characters = [value lengthOfBytesUsingEncoding:NSUTF32LittleEndianStringEncoding] / 4;
    if (!matches || characters < 4 || bytes > 63 ||
        [value rangeOfString:[NSString stringWithFormat:@"%C", (unichar)0]].location != NSNotFound) {
      pinStatus_.stringValue = !matches ? @"The PINs don’t match. Try again."
                                        : @"Use 4 to 63 characters (fewer if you use emoji or accents).";
      return;
    }
    NSData* data = [NSJSONSerialization dataWithJSONObject:@{@"op": @"set-pin", @"pin": value} options:0 error:nil];
    if (data == nil) return;
    const std::string request(static_cast<const char*>(data.bytes), data.length);
    const auto send = deps_.control_request;
    pinBusy_ = YES;
    pinButton_.enabled = NO;
    pinStatus_.stringValue = @"Confirm the change in the swpasskey prompt…";
    // The server waits for an AppKit presence prompt: never block the main queue.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
      auto result = send(request);
      BOOL ok = NO;
      if (result) {
        NSData* reply = [NSData dataWithBytes:result->data() length:result->size()];
        id json = [NSJSONSerialization JSONObjectWithData:reply options:0 error:nil];
        ok = [json isKindOfClass:[NSDictionary class]] && [json[@"ok"] isEqual:@YES];
      }
      dispatch_async(dispatch_get_main_queue(), ^{
        if (tornDown_) return;
        pinBusy_ = NO;
        [self refreshPinState];
        if (!ok) pinStatus_.stringValue = @"The PIN wasn’t changed.";
      });
    });
  }];
}

- (void)refreshLoginState {
  if (@available(macOS 13.0, *)) {
    SMAppService* svc = [SMAppService agentServiceWithPlistName:kAgentPlist];
    const char* bundle_path = [[[NSBundle mainBundle] bundlePath] UTF8String];
    swpk::log::debug("menubar_login_item_status",
                     {{"status", std::to_string(static_cast<long>(svc.status))},
                      {"bundle", bundle_path != nullptr ? bundle_path : "?"}});
    loginCheckbox_.enabled = YES;
    switch (svc.status) {
      case SMAppServiceStatusEnabled:
        loginCheckbox_.state = NSControlStateValueOn;
        loginNote_.stringValue = @"swpasskey opens in the menu bar when you log in.";
        break;
      case SMAppServiceStatusRequiresApproval:
        loginCheckbox_.state = NSControlStateValueOn;
        loginNote_.stringValue = @"Allow swpasskey in System Settings › General › Login Items.";
        break;
      case SMAppServiceStatusNotFound:
      case SMAppServiceStatusNotRegistered:
      default:
        loginCheckbox_.state = NSControlStateValueOff;
        loginNote_.stringValue = @"Websites can use swpasskey only while it’s open.";
        break;
    }
  } else {
    loginCheckbox_.state = NSControlStateValueOff;
    loginCheckbox_.enabled = NO;
    loginNote_.stringValue = @"Requires macOS 13 or later.";
  }
}

- (void)toggleLogin:(id)sender {
  if (@available(macOS 13.0, *)) {
    SMAppService* svc = [SMAppService agentServiceWithPlistName:kAgentPlist];
    NSError* err = nil;
    BOOL ok;
    if (loginCheckbox_.state == NSControlStateValueOn) {
      ok = [svc registerAndReturnError:&err];
      swpk::log::info("menubar_login_item", {{"action", "register"}, {"ok", ok ? "true" : "false"}});
    } else {
      ok = [svc unregisterAndReturnError:&err];
      swpk::log::info("menubar_login_item", {{"action", "unregister"}, {"ok", ok ? "true" : "false"}});
    }
    if (!ok) {
      NSAlert* a = [[NSAlert alloc] init];
      a.alertStyle = NSAlertStyleWarning;
      a.messageText = @"Unable to Change Login Setting";
      a.informativeText = err != nil ? err.localizedDescription : @"Try again.";
      [a beginSheetModalForWindow:settingsWindow_ completionHandler:nil];
    }
  }
  [self refreshLoginState];
}

- (void)changeLogLevel:(id)sender {
  NSString* key = levelPopup_.selectedItem.representedObject;
  for (const auto& l : kLevels) {
    if ([key isEqualToString:@(l.key)]) {
      swpk::log::set_level(l.level);
      [[NSUserDefaults standardUserDefaults] setObject:key forKey:@(kLogLevelDefault)];
      swpk::log::info("menubar_log_level", {{"level", l.key}});
      return;
    }
  }
}

- (void)applyLogLevelPreference {
  NSString* saved = [[NSUserDefaults standardUserDefaults] stringForKey:@(kLogLevelDefault)];
  if (saved == nil) return;
  for (const auto& l : kLevels) {
    if ([saved isEqualToString:@(l.key)]) swpk::log::set_level(l.level);
  }
}

@end

namespace swpk::ui {
namespace {

class MacMenuBar final : public MenuBar {
public:
  explicit MacMenuBar(SWPKMenuController* c) : ctrl_(c) {}
  ~MacMenuBar() override {
    @autoreleasepool {
      [ctrl_ teardown];
      ctrl_ = nil;
    }
  }

private:
  SWPKMenuController* ctrl_;
};

}  // namespace

std::unique_ptr<MenuBar> make_menu_bar(MenuBarDeps deps) {
  @autoreleasepool {
    if (![NSThread isMainThread]) {
      log::warn("menubar_not_main_thread");
      return nullptr;
    }
    [NSApplication sharedApplication];  // idempotent; the presence loop configures the policy
    SWPKMenuController* c = [[SWPKMenuController alloc] initWithDeps:std::move(deps)];
    if (c == nil) {
      return nullptr;
    }
    return std::make_unique<MacMenuBar>(c);
  }
}

}  // namespace swpk::ui

#endif  // __APPLE__
