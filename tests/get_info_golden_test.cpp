// Golden CTAP2-canonical encoding of the PR3 getInfo snapshot, produced by
// python-fido2 (`fido2.cbor.encode`) and verified to parse as `Info`.
#include "swpasskey/constants.hpp"
#include "swpasskey/ctap/get_info.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace {

std::string hex(const std::vector<std::uint8_t>& v) {
  static constexpr char kH[] = "0123456789abcdef";
  std::string s;
  for (auto b : v) {
    s.push_back(kH[b >> 4]);
    s.push_back(kH[b & 15]);
  }
  return s;
}

}  // namespace

TEST_CASE("getInfo PR3 snapshot matches python-fido2 golden bytes", "[getinfo][golden]") {
  swpk::ctap::GetInfoSnapshot s;
  s.aaguid = swpk::kAaguid;
  s.remaining_discoverable = 100;
  const std::string expected =
      "aa0181684649444f5f325f3003506fb1dfdd51c043a0a6f2f74812cbf8fb04a662726bf5627570f5"
      "64706c6174f468616c776179735576f468637265644d676d74f4706d616b654372656455764e6f74"
      "527164f4051904b007080818200981637573620a81a263616c672664747970656a7075626c69632d"
      "6b65790e01141864";
  REQUIRE(hex(swpk::ctap::encode_get_info(s)) == expected);
}

TEST_CASE("getInfo PR9 snapshot (PIN protocol 2, still FIDO_2_0) golden bytes", "[getinfo][golden]") {
  swpk::ctap::GetInfoSnapshot s;
  s.aaguid = swpk::kAaguid;
  s.options.client_pin = false;
  s.options.pin_uv_auth_token = true;
  s.pin_protocols = {2};
  s.remaining_discoverable = 100;
  const std::string expected =
      "ab0181684649444f5f325f3003506fb1dfdd51c043a0a6f2f74812cbf8fb04a862726bf5627570f564"
      "706c6174f468616c776179735576f468637265644d676d74f469636c69656e7450696ef46e70696e55"
      "7641757468546f6b656ef5706d616b654372656455764e6f74527164f4051904b006810207080818200"
      "981637573620a81a263616c672664747970656a7075626c69632d6b65790e01141864";
  REQUIRE(hex(swpk::ctap::encode_get_info(s)) == expected);
}
