// Linux user-presence prompt: a libnotify notification with Approve / Deny
// action buttons (DESIGN.md K13). Compiled only when SWPASSKEY_LIBNOTIFY.
//
// Threading: libnotify delivers action callbacks over D-Bus through a GLib
// main context, so this class owns a thread that runs a GMainLoop on the
// default context for the life of the daemon. `confirm()` runs on the
// authenticator worker: it posts the "show" onto the loop thread with
// g_idle_add and then waits on a condvar with 50 ms wakeups so a CTAPHID
// CANCEL or the 30 s deadline is honoured promptly (the HID thread keeps
// sending KEEPALIVE/UPNEEDED meanwhile).
#if defined(SWPASSKEY_LIBNOTIFY)

#include "swpasskey/ui/presence.hpp"

#include "presence_util.hpp"
#include "swpasskey/log/log.hpp"

#include <glib-object.h>
#include <glib.h>
#include <libnotify/notify.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace swpk::ui {
namespace {

constexpr auto kPollInterval = std::chrono::milliseconds(50);
constexpr auto kLoopStartTimeout = std::chrono::seconds(2);
constexpr auto kTeardownTimeout = std::chrono::seconds(2);

class NotifyPresence final : public Presence {
public:
  // Returns nullptr when this session cannot show an actionable notification.
  static std::unique_ptr<NotifyPresence> create();

  NotifyPresence() = default;
  ~NotifyPresence() override;
  NotifyPresence(const NotifyPresence&) = delete;
  NotifyPresence& operator=(const NotifyPresence&) = delete;

  Decision confirm(const PresenceRequest& req, ctap::CancelToken& cancel,
                   std::chrono::milliseconds timeout) override;
  const char* name() const override { return "notify"; }

private:
  bool start_loop();
  void stop_loop();
  void decide(Decision d);

  // All of these run on the GLib loop thread.
  static gboolean loop_ready_cb(gpointer data);
  static gboolean show_cb(gpointer data);
  static gboolean close_cb(gpointer data);
  static void action_cb(NotifyNotification* n, char* action, gpointer data);
  static void closed_cb(NotifyNotification* n, gpointer data);

  std::mutex mu_;
  std::condition_variable cv_;
  std::thread loop_thread_;
  GMainLoop* loop_{nullptr};
  std::atomic<bool> loop_exited_{false};
  bool loop_running_{false};
  bool markup_{false};

  // Guarded by mu_.
  bool busy_{false};
  bool decided_{false};
  bool torn_down_{true};
  Decision decision_{Decision::Deny};
  std::string body_;
  NotifyNotification* notif_{nullptr};
};

gboolean NotifyPresence::loop_ready_cb(gpointer data) {
  auto* self = static_cast<NotifyPresence*>(data);
  {
    std::lock_guard<std::mutex> lk(self->mu_);
    self->loop_running_ = true;
  }
  self->cv_.notify_all();
  return G_SOURCE_REMOVE;
}

bool NotifyPresence::start_loop() {
  loop_ = g_main_loop_new(nullptr, FALSE);
  if (loop_ == nullptr) {
    return false;
  }
  loop_thread_ = std::thread([this] {
    g_main_loop_run(loop_);
    loop_exited_.store(true, std::memory_order_release);
  });
  g_idle_add(&NotifyPresence::loop_ready_cb, this);
  std::unique_lock<std::mutex> lk(mu_);
  return cv_.wait_for(lk, kLoopStartTimeout, [this] { return loop_running_; });
}

void NotifyPresence::stop_loop() {
  if (loop_ == nullptr) {
    return;
  }
  // g_main_loop_quit is safe from another thread; retry in case the loop had
  // not entered g_main_loop_run yet (start_loop timed out).
  g_main_loop_quit(loop_);
  g_main_context_wakeup(nullptr);
  for (int i = 0; i < 200 && !loop_exited_.load(std::memory_order_acquire); ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    g_main_loop_quit(loop_);
    g_main_context_wakeup(nullptr);
  }
  if (loop_thread_.joinable()) {
    loop_thread_.join();
  }
  g_main_loop_unref(loop_);
  loop_ = nullptr;
}

NotifyPresence::~NotifyPresence() {
  stop_loop();
  if (notif_ != nullptr) {
    g_object_unref(notif_);
    notif_ = nullptr;
  }
  notify_uninit();
}

void NotifyPresence::decide(Decision d) {
  {
    std::lock_guard<std::mutex> lk(mu_);
    if (decided_) {
      return;  // first answer wins; a later "closed" must not override it
    }
    decided_ = true;
    decision_ = d;
  }
  cv_.notify_all();
}

void NotifyPresence::action_cb(NotifyNotification*, char* action, gpointer data) {
  auto* self = static_cast<NotifyPresence*>(data);
  const bool allow = action != nullptr && std::strcmp(action, "approve") == 0;
  self->decide(allow ? Decision::Allow : Decision::Deny);
}

void NotifyPresence::closed_cb(NotifyNotification*, gpointer data) {
  // Dismissed without pressing a button (or the server expired it): Deny.
  static_cast<NotifyPresence*>(data)->decide(Decision::Deny);
}

gboolean NotifyPresence::show_cb(gpointer data) {
  auto* self = static_cast<NotifyPresence*>(data);
  std::string body;
  {
    std::lock_guard<std::mutex> lk(self->mu_);
    if (self->decided_) {
      return G_SOURCE_REMOVE;  // cancelled before we got scheduled
    }
    body = self->body_;
  }
  NotifyNotification* n = notify_notification_new("swpasskey", body.c_str(), "dialog-password");
  if (n == nullptr) {
    self->decide(Decision::Deny);
    return G_SOURCE_REMOVE;
  }
  notify_notification_set_urgency(n, NOTIFY_URGENCY_CRITICAL);
  notify_notification_set_timeout(n, NOTIFY_EXPIRES_NEVER);
  notify_notification_add_action(n, "approve", "Approve", &NotifyPresence::action_cb, self,
                                 nullptr);
  notify_notification_add_action(n, "deny", "Deny", &NotifyPresence::action_cb, self, nullptr);
  g_signal_connect(n, "closed", G_CALLBACK(&NotifyPresence::closed_cb), self);

  GError* err = nullptr;
  if (notify_notification_show(n, &err) == FALSE) {
    log::warn("presence_notify_show_failed",
              {{"error", err != nullptr && err->message != nullptr ? err->message : "?"}});
    if (err != nullptr) {
      g_error_free(err);
    }
    g_object_unref(n);
    self->decide(Decision::Deny);  // fail closed
    return G_SOURCE_REMOVE;
  }
  {
    std::lock_guard<std::mutex> lk(self->mu_);
    self->notif_ = n;
  }
  return G_SOURCE_REMOVE;
}

gboolean NotifyPresence::close_cb(gpointer data) {
  auto* self = static_cast<NotifyPresence*>(data);
  NotifyNotification* n = nullptr;
  {
    std::lock_guard<std::mutex> lk(self->mu_);
    n = self->notif_;
    self->notif_ = nullptr;
  }
  if (n != nullptr) {
    GError* err = nullptr;
    notify_notification_close(n, &err);
    if (err != nullptr) {
      g_error_free(err);
    }
    g_object_unref(n);
  }
  {
    std::lock_guard<std::mutex> lk(self->mu_);
    self->torn_down_ = true;
  }
  self->cv_.notify_all();
  return G_SOURCE_REMOVE;
}

Decision NotifyPresence::confirm(const PresenceRequest& req, ctap::CancelToken& cancel,
                                 std::chrono::milliseconds timeout) {
  std::string body = std::string("Approve ") + detail::kind_action(req.kind) + " for \"" +
                     detail::clamp_text(req.rp_id) + "\"?";
  if (!req.user_display.empty()) {
    body += "\nUser: " + detail::clamp_text(req.user_display);
  }
  if (markup_) {
    char* escaped = g_markup_escape_text(body.c_str(), -1);
    if (escaped != nullptr) {
      body.assign(escaped);
      g_free(escaped);
    }
  }

  {
    std::lock_guard<std::mutex> lk(mu_);
    if (busy_) {
      // Only one worker exists; be defensive rather than stacking prompts.
      log::warn("presence_notify_busy", {{"rp", req.rp_id}});
      return Decision::Deny;
    }
    busy_ = true;
    decided_ = false;
    torn_down_ = false;
    decision_ = Decision::Deny;
    body_ = std::move(body);
  }
  // Idle sources of equal priority run FIFO, so this always precedes close_cb.
  g_idle_add(&NotifyPresence::show_cb, this);

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  Decision out = Decision::Timeout;
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
    // Latch: a late action/closed callback must not mutate the next request.
    decided_ = true;
    decision_ = out;
  }

  // Withdraw the notification and destroy it on the loop thread.
  g_idle_add(&NotifyPresence::close_cb, this);
  {
    std::unique_lock<std::mutex> lk(mu_);
    if (!cv_.wait_for(lk, kTeardownTimeout, [this] { return torn_down_; })) {
      log::warn("presence_notify_teardown_timeout");
    }
    busy_ = false;
  }
  log::debug("presence_notify_done", {{"rp", req.rp_id},
                                      {"decision", out == Decision::Allow      ? "allow"
                                                   : out == Decision::Deny     ? "deny"
                                                   : out == Decision::Cancelled ? "cancelled"
                                                                                : "timeout"}});
  return out;
}

std::unique_ptr<NotifyPresence> NotifyPresence::create() {
  bool did_init = false;
  if (notify_is_initted() == FALSE) {
    if (notify_init("swpasskey") == FALSE) {
      log::warn("presence_notify_unavailable", {{"reason", "notify_init failed"}});
      return nullptr;
    }
    did_init = true;
  }
  const auto give_up = [did_init](const char* reason) -> std::unique_ptr<NotifyPresence> {
    log::warn("presence_notify_unavailable", {{"reason", reason}});
    if (did_init) {
      notify_uninit();
    }
    return nullptr;
  };

  char* sname = nullptr;
  char* svendor = nullptr;
  char* sversion = nullptr;
  char* sspec = nullptr;
  if (notify_get_server_info(&sname, &svendor, &sversion, &sspec) == FALSE) {
    return give_up("no notification server on the session bus");
  }
  const std::string server = sname != nullptr ? sname : "";
  g_free(sname);
  g_free(svendor);
  g_free(sversion);
  g_free(sspec);

  GList* caps = notify_get_server_caps();
  bool has_actions = false;
  bool has_markup = false;
  for (GList* it = caps; it != nullptr; it = it->next) {
    const char* cap = static_cast<const char*>(it->data);
    if (cap == nullptr) {
      continue;
    }
    if (std::strcmp(cap, "actions") == 0) {
      has_actions = true;
    } else if (std::strcmp(cap, "body-markup") == 0) {
      has_markup = true;
    }
  }
  g_list_free_full(caps, g_free);
  if (!has_actions) {
    return give_up("notification server has no \"actions\" capability");
  }

  auto p = std::make_unique<NotifyPresence>();
  p->markup_ = has_markup;
  if (!p->start_loop()) {
    return give_up("GLib main loop did not start");
  }
  log::info("presence_notify_ready", {{"server", server}});
  return p;
}

}  // namespace

std::unique_ptr<Presence> make_desktop_presence() { return NotifyPresence::create(); }

}  // namespace swpk::ui

#endif  // SWPASSKEY_LIBNOTIFY
