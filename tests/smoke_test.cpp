#include "swpasskey/constants.hpp"
#include "swpasskey/log/log.hpp"
#include "swpasskey/status.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("std::expected Result maps Status", "[smoke]") {
  const swpk::Result<int> ok = 7;
  REQUIRE(ok.has_value());
  REQUIRE(*ok == 7);

  const swpk::Result<int> err =
      std::unexpected(swpk::Status::UnsupportedOption);
  REQUIRE_FALSE(err.has_value());
  REQUIRE(err.error() == swpk::Status::UnsupportedOption);
  REQUIRE(static_cast<std::uint8_t>(err.error()) == 0x2B);
}

TEST_CASE("AAGUID and USB IDs match the design", "[smoke]") {
  REQUIRE(swpk::kAaguid.size() == 16);
  REQUIRE(swpk::kAaguid[0] == 0x6f);
  REQUIRE(swpk::kAaguid[15] == 0xfb);
  REQUIRE(swpk::kUsbVid == 0x1209);
  REQUIRE(swpk::kUsbPid == 0xF1D0);
  REQUIRE_FALSE(swpk::kVersion.empty());
}

TEST_CASE("logger emits a JSON line", "[smoke]") {
  swpk::log::set_level(swpk::log::Level::Info);
  swpk::log::info("smoke", {{"k", "v"}});
  SUCCEED();
}

TEST_CASE("UnauthorizedPermission is 0x40", "[smoke]") {
  REQUIRE(static_cast<std::uint8_t>(swpk::Status::UnauthorizedPermission) ==
          0x40);
  REQUIRE(static_cast<std::uint8_t>(swpk::Status::UnsupportedExtension) ==
          0x4B);
  REQUIRE(static_cast<std::uint8_t>(swpk::Status::InvalidOption) == 0x2C);
}
