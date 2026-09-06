#include "swpasskey/ctl/server.hpp"

#include "swpasskey/ctl/json.hpp"
#include "swpasskey/daemon/paths.hpp"
#include "swpasskey/log/log.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/ucred.h>
#endif

#include <cerrno>
#include <chrono>
#include <cstring>

namespace swpk::ctl {
namespace {

std::string hex(std::span<const std::uint8_t> v) {
  static constexpr char kH[] = "0123456789abcdef";
  std::string s;
  for (auto b : v) {
    s.push_back(kH[b >> 4]);
    s.push_back(kH[b & 15]);
  }
  return s;
}

Result<std::vector<std::uint8_t>> unhex(std::string_view s) {
  if (s.size() % 2 != 0) {
    return std::unexpected(Status::InvalidParameter);
  }
  std::vector<std::uint8_t> out;
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < s.size(); i += 2) {
    const int hi = nib(s[i]);
    const int lo = nib(s[i + 1]);
    if (hi < 0 || lo < 0) {
      return std::unexpected(Status::InvalidParameter);
    }
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

const char* backend_name(crypto::BackendKind k) {
  switch (k) {
    case crypto::BackendKind::Software:
      return "software";
    case crypto::BackendKind::Tpm2:
      return "tpm2";
    case crypto::BackendKind::SecureEnclave:
      return "se";
  }
  return "software";
}

std::string error_json(std::string_view msg, std::optional<Status> st = std::nullopt) {
  JsonWriter w;
  w.begin_object().boolean("ok", false).str("error", msg);
  if (st) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%02x", static_cast<unsigned>(*st));
    w.str("status", buf);
  }
  w.end_object();
  return w.finish();
}

std::string status_name(Status s) {
  switch (s) {
    case Status::OperationDenied:
      return "denied";
    case Status::UserActionTimeout:
      return "timeout";
    case Status::KeepaliveCancel:
      return "cancelled";
    case Status::InvalidCredential:
      return "no such credential";
    case Status::PinPolicyViolation:
      return "pin policy violation (4-63 characters)";
    default:
      return "failed";
  }
}

}  // namespace

std::filesystem::path default_socket_path() { return daemon::default_runtime_dir() / "ctl.sock"; }

std::string stats_json(ServerDeps& deps) {
  JsonWriter w;
  w.begin_object().boolean("ok", true);
  w.str("key_backend", deps.key_backend).str("probe", deps.probe_detail);
  if (deps.store != nullptr) {
    const auto by = deps.store->count_by_backend();
    w.object("creds").num("software", by[0]).num("tpm2", by[1]).num("se", by[2]).end_object();
    w.num("store_creds", deps.store->size());
    w.num("remaining", deps.store->remaining());
    w.boolean("pin_set", deps.store->pin().hash.has_value());
    w.num("pin_retries", deps.store->pin().retries);
  }
  if (deps.auth != nullptr) {
    const auto m = deps.auth->metrics();
    w.num("make_cred_ok", m.make_cred_ok).num("make_cred_err", m.make_cred_err);
    w.num("get_assert_ok", m.get_assert_ok).num("get_assert_err", m.get_assert_err);
    w.num("up_allow", m.up_allow).num("up_deny", m.up_deny).num("up_timeout", m.up_timeout);
    w.num("pin_fail", m.pin_fail).num("pin_block", m.pin_block);
    w.object("errors");
    for (std::size_t i = 1; i < m.ctap_status.size(); ++i) {
      if (m.ctap_status[i] != 0) {
        char key[8];
        std::snprintf(key, sizeof(key), "0x%02zx", i);
        w.num(key, m.ctap_status[i]);
      }
    }
    w.end_object();
  }
  if (deps.loop != nullptr) {
    const auto c = deps.loop->device().counters();
    const auto ls = deps.loop->stats();
    w.num("hid_init", c.hid_init).num("hid_error", c.hid_error).num("hid_ping", c.hid_ping);
    w.num("keepalives", ls.keepalives).num("cancels", ls.cancels);
  }
  w.end_object();
  return w.finish();
}

std::string handle_request(std::string_view line, ServerDeps& deps) {
  auto req = parse_flat_json(line);
  if (!req.ok) {
    return error_json("bad request: " + req.error);
  }
  const std::string op = req.get("op");
  if (op == "stats") {
    return stats_json(deps);
  }
  if (op == "list") {
    if (deps.store == nullptr) {
      return error_json("no store");
    }
    JsonWriter w;
    w.begin_object().boolean("ok", true).begin_array("creds");
    for (const auto& c : deps.store->all()) {
      w.begin_object()
          .str("rp", c.rp_id)
          .str("rp_name", c.rp_name)
          .str("user", c.user_name)
          .str("user_display", c.user_display)
          .str("user_id", hex(c.user_id))
          .str("cred_id", hex(c.cred_id))
          .num("sign_count", c.sign_count)
          .str("backend", backend_name(c.backend))
          .num("created", c.created_unix)
          .num("last_used", c.last_used_unix)
          .end_object();
    }
    w.end_array().end_object();
    return w.finish();
  }
  if (op == "delete") {
    if (deps.auth == nullptr) {
      return error_json("no authenticator");
    }
    auto id = unhex(req.get("cred_id"));
    if (!id || id->size() != 32) {
      return error_json("cred_id must be 64 hex chars");
    }
    if (auto r = deps.auth->ctl_delete(*id); !r) {
      return error_json(status_name(r.error()), r.error());
    }
    log::warn("ctl_delete", {{"cred_id", req.get("cred_id").substr(0, 16)}});
    JsonWriter w;
    w.begin_object().boolean("ok", true).end_object();
    return w.finish();
  }
  if (op == "reset") {
    if (deps.auth == nullptr) {
      return error_json("no authenticator");
    }
    ctap::CancelToken tok;
    if (auto r = deps.auth->ctl_reset(tok); !r) {
      return error_json(status_name(r.error()), r.error());
    }
    JsonWriter w;
    w.begin_object().boolean("ok", true).end_object();
    return w.finish();
  }
  if (op == "set-pin") {
    if (deps.auth == nullptr) {
      return error_json("no authenticator");
    }
    const std::string pin = req.get("pin");
    ctap::CancelToken tok;
    if (auto r = deps.auth->ctl_set_pin(pin, tok); !r) {
      return error_json(status_name(r.error()), r.error());
    }
    JsonWriter w;
    w.begin_object().boolean("ok", true).end_object();
    return w.finish();
  }
  if (op == "log-level") {
    const std::string lvl = req.get("level");
    if (lvl == "error") log::set_level(log::Level::Error);
    else if (lvl == "warn") log::set_level(log::Level::Warn);
    else if (lvl == "info") log::set_level(log::Level::Info);
    else if (lvl == "debug") log::set_level(log::Level::Debug);
    else return error_json("level must be error|warn|info|debug");
    JsonWriter w;
    w.begin_object().boolean("ok", true).str("level", lvl).end_object();
    return w.finish();
  }
  if (op == "quit") {
    if (deps.quit) {
      deps.quit();
    }
    JsonWriter w;
    w.begin_object().boolean("ok", true).end_object();
    return w.finish();
  }
  return error_json("unknown op");
}

UnixServer::UnixServer(std::filesystem::path path, ServerDeps deps)
    : path_(std::move(path)), deps_(std::move(deps)) {}

UnixServer::~UnixServer() { stop(); }

Result<void> UnixServer::start() {
  if (auto d = daemon::ensure_dir(path_.parent_path()); !d) {
    return d;
  }
  listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (listen_fd_ < 0) {
    return std::unexpected(Status::Other);
  }
  ::fcntl(listen_fd_, F_SETFD, FD_CLOEXEC);
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  const std::string p = path_.string();
  if (p.size() >= sizeof(addr.sun_path)) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    return std::unexpected(Status::InvalidParameter);
  }
  std::strncpy(addr.sun_path, p.c_str(), sizeof(addr.sun_path) - 1);
  ::unlink(p.c_str());
  const mode_t old = ::umask(0177);
  const int brc = ::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  ::umask(old);
  if (brc != 0 || ::listen(listen_fd_, 4) != 0) {
    log::error("ctl_bind_failed", {{"path", p}, {"errno", std::strerror(errno)}});
    ::close(listen_fd_);
    listen_fd_ = -1;
    return std::unexpected(Status::Other);
  }
  ::chmod(p.c_str(), 0600);
  thread_ = std::thread([this] { run(); });
  log::info("ctl_listening", {{"path", p}});
  return {};
}

void UnixServer::stop() {
  stop_.store(true);
  if (thread_.joinable()) {
    thread_.join();
  }
  if (listen_fd_ >= 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    ::unlink(path_.c_str());
  }
}

void UnixServer::run() {
  auto last_stats = std::chrono::steady_clock::now();
  while (!stop_.load()) {
    pollfd pfd{listen_fd_, POLLIN, 0};
    const int rc = ::poll(&pfd, 1, 250);
    const auto now = std::chrono::steady_clock::now();
    if (now - last_stats >= std::chrono::minutes(5)) {
      last_stats = now;
      log::info("stats", {{"json", stats_json(deps_)}});
    }
    if (rc <= 0) {
      continue;
    }
    const int c = ::accept(listen_fd_, nullptr, nullptr);
    if (c < 0) {
      continue;
    }
    ::fcntl(c, F_SETFD, FD_CLOEXEC);
    // Same-uid check (the socket is 0600, but be explicit where supported).
#if defined(SO_PEERCRED)
    struct ucred cred{};
    socklen_t len = sizeof(cred);
    if (::getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0 && cred.uid != ::getuid()) {
      ::close(c);
      continue;
    }
#elif defined(LOCAL_PEERCRED)
    struct xucred xc{};
    socklen_t len = sizeof(xc);
    if (::getsockopt(c, SOL_LOCAL, LOCAL_PEERCRED, &xc, &len) == 0 && xc.cr_uid != ::getuid()) {
      ::close(c);
      continue;
    }
#endif
    std::string line;
    char buf[512];
    // Read one line (bounded).
    while (line.size() < 64 * 1024) {
      pollfd cp{c, POLLIN, 0};
      if (::poll(&cp, 1, 5000) <= 0) {
        break;
      }
      const ssize_t n = ::read(c, buf, sizeof(buf));
      if (n <= 0) {
        break;
      }
      line.append(buf, static_cast<std::size_t>(n));
      if (line.find('\n') != std::string::npos) {
        break;
      }
    }
    const auto nl = line.find('\n');
    if (nl != std::string::npos) {
      line.resize(nl);
    }
    std::string reply = handle_request(line, deps_) + "\n";
    std::size_t off = 0;
    while (off < reply.size()) {
      const ssize_t n = ::write(c, reply.data() + off, reply.size() - off);
      if (n <= 0) {
        break;
      }
      off += static_cast<std::size_t>(n);
    }
    ::close(c);
  }
}

Result<std::string> request(const std::filesystem::path& path, std::string_view line) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    return std::unexpected(Status::Other);
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  const std::string p = path.string();
  if (p.size() >= sizeof(addr.sun_path)) {
    ::close(fd);
    return std::unexpected(Status::InvalidParameter);
  }
  std::strncpy(addr.sun_path, p.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(fd);
    return std::unexpected(Status::Other);
  }
  std::string msg(line);
  msg.push_back('\n');
  std::size_t off = 0;
  while (off < msg.size()) {
    const ssize_t n = ::write(fd, msg.data() + off, msg.size() - off);
    if (n <= 0) {
      ::close(fd);
      return std::unexpected(Status::Other);
    }
    off += static_cast<std::size_t>(n);
  }
  std::string reply;
  char buf[4096];
  for (;;) {
    pollfd pfd{fd, POLLIN, 0};
    if (::poll(&pfd, 1, 60000) <= 0) {  // reset / set-pin wait for UP
      break;
    }
    const ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n <= 0) {
      break;
    }
    reply.append(buf, static_cast<std::size_t>(n));
    if (reply.find('\n') != std::string::npos) {
      break;
    }
  }
  ::close(fd);
  const auto nl = reply.find('\n');
  if (nl != std::string::npos) {
    reply.resize(nl);
  }
  return reply;
}

}  // namespace swpk::ctl
