// swpasskeyctl — control CLI for swpasskeyd (DESIGN.md "Control socket").
#include "swpasskey/ctl/json.hpp"
#include "swpasskey/ctl/server.hpp"

#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr const char* kUsage =
    "swpasskeyctl — control swpasskeyd over its Unix socket\n"
    "\n"
    "Usage: swpasskeyctl [--socket PATH] <command>\n"
    "  list                 Credentials: rp, user, cred_id, sign_count, backend\n"
    "  delete <cred-id-hex> Delete one credential (destroys the HW key handle)\n"
    "  reset                Factory reset (the daemon asks for user presence)\n"
    "  set-pin              Set the CTAP PIN (prompts; daemon asks for presence)\n"
    "  stats                Counters, key backend, per-backend credential counts\n"
    "  log-level <lvl>      error | warn | info | debug\n"
    "  quit                 Stop the daemon\n"
    "\n"
    "Env: SWPASSKEY_CTL_SOCKET overrides the default socket path.\n";

std::string read_secret(const char* prompt) {
  std::fputs(prompt, stderr);
  std::fflush(stderr);
  termios old{};
  const bool tty = ::isatty(STDIN_FILENO) != 0 && ::tcgetattr(STDIN_FILENO, &old) == 0;
  if (tty) {
    termios noecho = old;
    noecho.c_lflag &= static_cast<tcflag_t>(~ECHO);
    ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho);
  }
  std::string s;
  char buf[256];
  if (std::fgets(buf, sizeof(buf), stdin) != nullptr) {
    s = buf;
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) {
      s.pop_back();
    }
  }
  if (tty) {
    ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    std::fputc('\n', stderr);
  }
  return s;
}

std::string json_str(std::string_view v) {
  std::string out = "\"";
  for (char c : v) {
    if (c == '"' || c == '\\') out.push_back('\\');
    out.push_back(c);
  }
  out.push_back('"');
  return out;
}

// Very small extraction helpers for the list output (values are flat).
std::string field(std::string_view obj, std::string_view key) {
  const std::string k = "\"" + std::string(key) + "\":";
  auto p = obj.find(k);
  if (p == std::string_view::npos) return "";
  p += k.size();
  if (p < obj.size() && obj[p] == '"') {
    auto e = obj.find('"', p + 1);
    return std::string(obj.substr(p + 1, e - p - 1));
  }
  auto e = obj.find_first_of(",}", p);
  return std::string(obj.substr(p, e - p));
}

void print_list(const std::string& reply) {
  auto arr = reply.find("\"creds\":[");
  if (arr == std::string::npos) {
    std::puts(reply.c_str());
    return;
  }
  std::printf("%-28s %-16s %-12s %-6s %-9s %s\n", "rp", "user", "cred_id", "count", "backend", "last_used");
  std::size_t pos = arr;
  int n = 0;
  for (;;) {
    auto s = reply.find('{', pos);
    if (s == std::string::npos) break;
    auto e = reply.find('}', s);
    if (e == std::string::npos) break;
    const std::string obj = reply.substr(s, e - s + 1);
    pos = e + 1;
    if (obj.find("\"cred_id\"") == std::string::npos) continue;
    const std::string lu = field(obj, "last_used");
    char when[32] = "-";
    if (!lu.empty() && lu != "0") {
      const auto t = static_cast<std::time_t>(std::strtoull(lu.c_str(), nullptr, 10));
      std::tm tm{};
      localtime_r(&t, &tm);
      std::strftime(when, sizeof(when), "%Y-%m-%d %H:%M", &tm);
    }
    std::printf("%-28s %-16s %-12s %-6s %-9s %s\n", field(obj, "rp").c_str(), field(obj, "user").c_str(),
                (field(obj, "cred_id").substr(0, 12)).c_str(), field(obj, "sign_count").c_str(),
                field(obj, "backend").c_str(), when);
    ++n;
  }
  std::printf("%d credential%s (full ids: swpasskeyctl list --json)\n", n, n == 1 ? "" : "s");
}

}  // namespace

int main(int argc, char** argv) {
  std::string socket_path;
  if (const char* e = std::getenv("SWPASSKEY_CTL_SOCKET"); e != nullptr && *e != 0) {
    socket_path = e;
  }
  std::vector<std::string> args;
  bool json = false;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a{argv[i]};
    if (a == "--socket" && i + 1 < argc) {
      socket_path = argv[++i];
    } else if (a.starts_with("--socket=")) {
      socket_path = std::string(a.substr(9));
    } else if (a == "--json") {
      json = true;
    } else if (a == "--help" || a == "-h") {
      std::fputs(kUsage, stdout);
      return 0;
    } else {
      args.emplace_back(a);
    }
  }
  if (args.empty()) {
    std::fputs(kUsage, stderr);
    return 2;
  }
  if (socket_path.empty()) {
    socket_path = swpk::ctl::default_socket_path().string();
  }
  const std::string& cmd = args[0];
  std::string line;
  if (cmd == "list" || cmd == "stats" || cmd == "reset" || cmd == "quit") {
    line = "{\"op\":\"" + cmd + "\"}";
  } else if (cmd == "delete") {
    if (args.size() < 2) {
      std::fputs("swpasskeyctl: delete needs a credential id (hex)\n", stderr);
      return 2;
    }
    line = "{\"op\":\"delete\",\"cred_id\":" + json_str(args[1]) + "}";
  } else if (cmd == "log-level") {
    if (args.size() < 2) {
      std::fputs("swpasskeyctl: log-level needs error|warn|info|debug\n", stderr);
      return 2;
    }
    line = "{\"op\":\"log-level\",\"level\":" + json_str(args[1]) + "}";
  } else if (cmd == "set-pin") {
    const std::string pin = args.size() >= 2 ? args[1] : read_secret("New PIN: ");
    if (args.size() < 2) {
      const std::string again = read_secret("Repeat PIN: ");
      if (again != pin) {
        std::fputs("swpasskeyctl: PINs do not match\n", stderr);
        return 2;
      }
    }
    line = "{\"op\":\"set-pin\",\"pin\":" + json_str(pin) + "}";
  } else {
    std::fprintf(stderr, "swpasskeyctl: unknown command '%s'\n", cmd.c_str());
    return 2;
  }
  if (cmd == "reset" || cmd == "set-pin") {
    std::fputs("swpasskeyctl: waiting for user presence on the daemon...\n", stderr);
  }
  auto r = swpk::ctl::request(socket_path, line);
  if (!r) {
    std::fprintf(stderr, "swpasskeyctl: cannot reach swpasskeyd at %s (is it running?)\n",
                 socket_path.c_str());
    return 1;
  }
  const bool ok = r->find("\"ok\":true") != std::string::npos;
  if (cmd == "list" && !json && ok) {
    print_list(*r);
  } else {
    std::puts(r->c_str());
  }
  return ok ? 0 : 1;
}
