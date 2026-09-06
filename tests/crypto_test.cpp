#include "swpasskey/crypto/provider.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <vector>

TEST_CASE("sha256 empty", "[crypto]") {
  swpk::crypto::Provider p;
  auto d = p.sha256({});
  // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  REQUIRE(d[0] == 0xe3);
  REQUIRE(d[31] == 0x55);
}

TEST_CASE("aes-gcm round trip", "[crypto]") {
  swpk::crypto::Provider p;
  std::array<std::uint8_t, 32> key{};
  std::array<std::uint8_t, 12> nonce{};
  REQUIRE(p.random(key).has_value());
  REQUIRE(p.random(nonce).has_value());
  const std::uint8_t pt[] = {1, 2, 3, 4, 5};
  const std::uint8_t aad[] = {9};
  auto ct = p.aes256gcm_encrypt(key, nonce, aad, pt);
  REQUIRE(ct.has_value());
  auto back = p.aes256gcm_decrypt(key, nonce, aad, *ct);
  REQUIRE(back.has_value());
  REQUIRE(*back == std::vector<std::uint8_t>(std::begin(pt), std::end(pt)));
}

TEST_CASE("aes-cbc no padding", "[crypto]") {
  swpk::crypto::Provider p;
  std::array<std::uint8_t, 32> key{};
  std::array<std::uint8_t, 16> iv{};
  std::array<std::uint8_t, 16> pt{};
  pt[0] = 0x42;
  auto ct = p.aes256cbc_encrypt(key, iv, pt);
  REQUIRE(ct.has_value());
  auto back = p.aes256cbc_decrypt(key, iv, *ct);
  REQUIRE(back.has_value());
  REQUIRE(*back == std::vector<std::uint8_t>(pt.begin(), pt.end()));
}

TEST_CASE("consttime_equal", "[crypto]") {
  swpk::crypto::Provider p;
  const std::uint8_t a[] = {1, 2, 3};
  const std::uint8_t b[] = {1, 2, 3};
  const std::uint8_t c[] = {1, 2, 4};
  REQUIRE(p.consttime_equal(a, b));
  REQUIRE_FALSE(p.consttime_equal(a, c));
}

TEST_CASE("hmac-sha256 length", "[crypto]") {
  swpk::crypto::Provider p;
  std::array<std::uint8_t, 32> key{};
  auto mac = p.hmac_sha256(key, std::array<std::uint8_t, 1>{1});
  REQUIRE(mac.has_value());
}

TEST_CASE("low-S DER has high-bit padding", "[crypto]") {
  std::array<std::uint8_t, 32> r{};
  std::array<std::uint8_t, 32> s{};
  r[0] = 0x80;
  s[31] = 0x01;
  auto der = swpk::crypto::Provider::ecdsa_p256_rs_to_der_low_s(r, s);
  REQUIRE(der.size() >= 8);
  REQUIRE(der[0] == 0x30);
  REQUIRE(der[2] == 0x02);
  REQUIRE(der[3] >= 33);  // padded INTEGER
}
