// Linux integration test: spawn swpasskeyd on /dev/uhid and drive it with
// libfido2's `fido2-token`. Skips (passes) when UHID or fido2-token is absent.
#include <catch2/catch_test_macros.hpp>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>

namespace {

std::string run(const std::string& cmd) {
  std::string out;
  FILE* p = ::popen((cmd + " 2>&1").c_str(), "r");
  if (p == nullptr) return out;
  char buf[512];
  while (std::fgets(buf, sizeof(buf), p) != nullptr) out += buf;
  ::pclose(p);
  return out;
}

bool have(const char* tool) { return std::system((std::string("command -v ") + tool + " >/dev/null 2>&1").c_str()) == 0; }

}  // namespace

TEST_CASE("fido2-token sees swpasskeyd over UHID", "[itest]") {
#if !defined(__linux__)
  WARN("itest: not Linux, skipping");
  return;
#else
  if (::access("/dev/uhid", W_OK) != 0) {
    WARN("itest: /dev/uhid not writable, skipping");
    return;
  }
  if (!have("fido2-token")) {
    WARN("itest: fido2-token missing, skipping");
    return;
  }
  const std::string bin = std::string(SWPASSKEY_BIN_DIR) + "/swpasskeyd";
  auto tmp = std::filesystem::temp_directory_path() / ("swpk-itest-" + std::to_string(::getpid()));
  std::filesystem::create_directories(tmp);
  const std::string store = (tmp / "credentials.bin").string();
  ::setenv("XDG_RUNTIME_DIR", tmp.c_str(), 1);
  const pid_t pid = ::fork();
  REQUIRE(pid >= 0);
  if (pid == 0) {
    ::execl(bin.c_str(), bin.c_str(), "--testing", "--key-backend=software", "--store", store.c_str(), nullptr);
    ::_exit(127);
  }
  std::string dev;
  for (int i = 0; i < 50 && dev.empty(); ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const std::string ls = run("fido2-token -L");
    auto pos = ls.find("vendor=0x1209");
    if (pos != std::string::npos) {
      auto start = ls.rfind('\n', pos);
      start = start == std::string::npos ? 0 : start + 1;
      auto colon = ls.find(':', start);
      dev = ls.substr(start, colon - start);
    }
  }
  INFO("fido2-token -L: " << run("fido2-token -L"));
  REQUIRE_FALSE(dev.empty());
  const std::string info = run("fido2-token -I " + dev);
  INFO(info);
  REQUIRE(info.find("FIDO_2_0") != std::string::npos);
  REQUIRE(info.find("6fb1dfdd51c043a0a6f2f74812cbf8fb") != std::string::npos);
  REQUIRE(info.find("rk") != std::string::npos);
  ::kill(pid, SIGTERM);
  int st = 0;
  ::waitpid(pid, &st, 0);
  std::filesystem::remove_all(tmp);
#endif
}
