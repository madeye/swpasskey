#include "swpasskey/cbor/cbor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

TEST_CASE("canonical uint encoding is shortest", "[cbor]") {
  REQUIRE(swpk::cbor::Writer::encode_uint(0) == std::vector<std::uint8_t>{0x00});
  REQUIRE(swpk::cbor::Writer::encode_uint(23) == std::vector<std::uint8_t>{0x17});
  REQUIRE(swpk::cbor::Writer::encode_uint(24) == (std::vector<std::uint8_t>{0x18, 0x18}));
  REQUIRE(swpk::cbor::Writer::encode_int(-1) == std::vector<std::uint8_t>{0x20});
  REQUIRE(swpk::cbor::Writer::encode_int(-7) == std::vector<std::uint8_t>{0x26});
}

TEST_CASE("map keys are sorted by encoded bytes", "[cbor]") {
  swpk::cbor::Writer w;
  w.write_map({
      {swpk::cbor::Writer::encode_tstr("rk"), swpk::cbor::Writer::encode_bool(true)},
      {swpk::cbor::Writer::encode_tstr("up"), swpk::cbor::Writer::encode_bool(true)},
      {swpk::cbor::Writer::encode_tstr("plat"), swpk::cbor::Writer::encode_bool(false)},
  });
  const auto bytes = w.finish();
  swpk::cbor::Reader r(bytes);
  auto n = r.map();
  REQUIRE(n.has_value());
  REQUIRE(*n == 3);
  // Encoded-key sort, not UTF-8 string sort: 0x62 "rk", 0x62 "up", 0x64 "plat".
  auto k0 = r.tstr();
  REQUIRE(k0.has_value());
  REQUIRE(*k0 == "rk");
  REQUIRE(r.boolean().value() == true);
  auto k1 = r.tstr();
  REQUIRE(*k1 == "up");
  REQUIRE(r.boolean().value() == true);
  auto k2 = r.tstr();
  REQUIRE(*k2 == "plat");
  REQUIRE(r.boolean().value() == false);
}

TEST_CASE("indefinite lengths are rejected", "[cbor]") {
  const std::uint8_t indef[] = {0x5F, 0x41, 0x00, 0xFF};  // indefinite bstr
  swpk::cbor::Reader r(indef);
  auto b = r.bstr();
  REQUIRE_FALSE(b.has_value());
  REQUIRE(b.error() == swpk::Status::InvalidCbor);
}

TEST_CASE("integer map keys round-trip", "[cbor]") {
  swpk::cbor::Writer inner;
  inner.write_map({{swpk::cbor::Writer::encode_uint(1), swpk::cbor::Writer::encode_tstr("packed")},
                   {swpk::cbor::Writer::encode_uint(2), swpk::cbor::Writer::encode_uint(0)}});
  auto bytes = inner.finish();
  swpk::cbor::Reader r(bytes);
  REQUIRE(r.map().value() == 2);
  REQUIRE(r.uint().value() == 1);
  REQUIRE(r.tstr().value() == "packed");
  REQUIRE(r.uint().value() == 2);
  REQUIRE(r.uint().value() == 0);
}
