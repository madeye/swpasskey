// Non-GUI presence logic only. These tests must never construct the desktop
// implementation (NotifyPresence / AlertPresence): they would pop a real
// notification or a modal alert on the developer's session. Everything here
// forces the tty path or the testing auto-allow.
#include "swpasskey/ui/presence.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstring>
#include <string>

using namespace swpk;
using namespace std::chrono_literals;

namespace {

ui::PresenceRequest sample_request() {
  ui::PresenceRequest req;
  req.kind = ui::PresenceRequest::Kind::GetAssertion;
  req.rp_id = "example.com";
  req.user_display = "alice";
  return req;
}

}  // namespace

TEST_CASE("make_presence honours prefer=stdin", "[presence]") {
  ui::PresenceConfig cfg;
  cfg.prefer = "stdin";
  cfg.allow_notifications = true;  // must not win over the explicit override
  auto p = ui::make_presence(cfg);
  REQUIRE(p != nullptr);
  REQUIRE(std::strcmp(p->name(), "stdin") == 0);
  REQUIRE_FALSE(p->needs_main_thread());
}

TEST_CASE("make_presence without notifications is the tty prompt", "[presence]") {
  ui::PresenceConfig cfg;
  cfg.allow_notifications = false;
  cfg.prefer = "auto";
  auto p = ui::make_presence(cfg);
  REQUIRE(p != nullptr);
  REQUIRE(std::strcmp(p->name(), "stdin") == 0);
}

TEST_CASE("make_presence with an unknown prefer falls back to the tty prompt", "[presence]") {
  ui::PresenceConfig cfg;
  cfg.allow_notifications = false;  // "auto" without notifications => stdin
  cfg.prefer = "carrier-pigeon";
  auto p = ui::make_presence(cfg);
  REQUIRE(p != nullptr);
  REQUIRE(std::strcmp(p->name(), "stdin") == 0);
}

#if defined(SWPASSKEY_ALLOW_TESTING_PRESENCE)
TEST_CASE("testing=1 auto-allows regardless of prefer", "[presence]") {
  ui::PresenceConfig cfg;
  cfg.testing = true;
  auto p = ui::make_presence(cfg);
  REQUIRE(p != nullptr);
  REQUIRE(std::strcmp(p->name(), "auto-allow") == 0);

  ctap::CancelToken token;
  REQUIRE(p->confirm(sample_request(), token, 100ms) == ui::Decision::Allow);
  token.cancel();
  REQUIRE(p->confirm(sample_request(), token, 100ms) == ui::Decision::Cancelled);
}
#endif

TEST_CASE("StdinPresence times out when nobody answers", "[presence]") {
  ui::StdinPresence p;
  ctap::CancelToken token;
  const auto t0 = std::chrono::steady_clock::now();
  const auto d = p.confirm(sample_request(), token, 100ms);
  const auto elapsed = std::chrono::steady_clock::now() - t0;
  REQUIRE(d == ui::Decision::Timeout);
  REQUIRE(elapsed >= 90ms);
  REQUIRE(elapsed < 3s);
}

TEST_CASE("StdinPresence returns Cancelled promptly on a CTAPHID CANCEL", "[presence]") {
  ui::StdinPresence p;
  ctap::CancelToken token;
  token.cancel();
  const auto t0 = std::chrono::steady_clock::now();
  const auto d = p.confirm(sample_request(), token, 30s);
  const auto elapsed = std::chrono::steady_clock::now() - t0;
  REQUIRE(d == ui::Decision::Cancelled);
  REQUIRE(elapsed < 1s);
}

TEST_CASE("AlwaysDenyPresence never asks", "[presence]") {
  ui::AlwaysDenyPresence p;
  ctap::CancelToken token;
  REQUIRE(p.confirm(sample_request(), token, 1ms) == ui::Decision::Deny);
  REQUIRE_FALSE(p.needs_main_thread());
}
