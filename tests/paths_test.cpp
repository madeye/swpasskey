#include "swpasskey/daemon/paths.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

using namespace swpk::daemon;

namespace {
std::filesystem::path tmpdir() {
  auto p = std::filesystem::temp_directory_path() / ("swpk-test-" + std::to_string(::getpid()) + "-" + std::to_string(std::rand()));
  std::filesystem::create_directories(p);
  return p;
}
}  // namespace

TEST_CASE("serial sidecar is created once, 16 hex, 0600", "[paths]") {
  auto d = tmpdir();
  auto s1 = load_or_create_serial(d / "serial");
  REQUIRE(s1.has_value());
  REQUIRE(s1->size() == 16);
  REQUIRE(s1->find_first_not_of("0123456789abcdef") == std::string::npos);
  struct stat st{};
  REQUIRE(::stat((d / "serial").c_str(), &st) == 0);
  REQUIRE((st.st_mode & 0777) == 0600);
  auto s2 = load_or_create_serial(d / "serial");
  REQUIRE(s2.has_value());
  REQUIRE(*s1 == *s2);
  std::filesystem::remove_all(d);
}

TEST_CASE("invalid sidecar is regenerated", "[paths]") {
  auto d = tmpdir();
  { std::ofstream(d / "serial") << "nope\n"; }
  auto s = load_or_create_serial(d / "serial");
  REQUIRE(s.has_value());
  REQUIRE(s->size() == 16);
  std::filesystem::remove_all(d);
}

TEST_CASE("instance lock is exclusive", "[paths]") {
  auto d = tmpdir();
  auto a = InstanceLock::acquire(d / "x.lock");
  REQUIRE(a.has_value());
  REQUIRE(a->held());
  // Same process: flock on a second fd of the same file conflicts.
  auto b = InstanceLock::acquire(d / "x.lock");
  REQUIRE_FALSE(b.has_value());
  { auto released = std::move(*a); }
  auto c = InstanceLock::acquire(d / "x.lock");
  REQUIRE(c.has_value());
  std::filesystem::remove_all(d);
}
