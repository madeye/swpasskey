// Runs against the real login keychain: items are created under random
// install_ids and removed again at the end of each test case.
#include "swpasskey/store/keychain.hpp"

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdio>
#include <random>
#include <string>

using namespace swpk;
using namespace swpk::store;

namespace {

std::string random_install_id() {
  std::random_device rd;
  std::string s;
  char buf[3];
  for (int i = 0; i < 16; ++i) {
    std::snprintf(buf, sizeof buf, "%02x", rd() & 0xff);
    s += buf;
  }
  return s;
}

std::array<std::uint8_t, 32> dek_of(std::uint8_t fill) {
  std::array<std::uint8_t, 32> d{};
  d.fill(fill);
  return d;
}

// Writes the pre-fix item shape: account "dek", install_id in the comment.
void add_legacy_item(const std::string& install_id, std::span<const std::uint8_t, 32> dek) {
  @autoreleasepool {
    NSDictionary* item = @{
      (id)kSecClass : (id)kSecClassGenericPassword,
      (id)kSecAttrService : @"com.tangzixiang.swpasskey",
      (id)kSecAttrAccount : @"dek",
      (id)kSecAttrLabel : @"swpasskey store DEK",
      (id)kSecAttrComment : [NSString stringWithUTF8String:install_id.c_str()],
      (id)kSecValueData : [NSData dataWithBytes:dek.data() length:dek.size()],
    };
    REQUIRE(SecItemAdd((__bridge CFDictionaryRef)item, nullptr) == errSecSuccess);
  }
}

bool legacy_item_exists() {
  @autoreleasepool {
    NSDictionary* q = @{
      (id)kSecClass : (id)kSecClassGenericPassword,
      (id)kSecAttrService : @"com.tangzixiang.swpasskey",
      (id)kSecAttrAccount : @"dek",
    };
    return SecItemCopyMatching((__bridge CFDictionaryRef)q, nullptr) == errSecSuccess;
  }
}

void remove_legacy_item() {
  @autoreleasepool {
    NSDictionary* q = @{
      (id)kSecClass : (id)kSecClassGenericPassword,
      (id)kSecAttrService : @"com.tangzixiang.swpasskey",
      (id)kSecAttrAccount : @"dek",
    };
    (void)SecItemDelete((__bridge CFDictionaryRef)q);
  }
}

}  // namespace

TEST_CASE("macOS keychain: one DEK item per install_id, stores do not clobber each other",
          "[keychain][macos]") {
  auto kc = make_os_keychain();
  REQUIRE(kc);
  const auto a = random_install_id();
  const auto b = random_install_id();
  REQUIRE(kc->store_dek(a, dek_of(0xaa)).has_value());
  REQUIRE(kc->store_dek(b, dek_of(0xbb)).has_value());  // the regression: used to replace a's item

  auto la = kc->load_dek(a);
  REQUIRE(la.has_value());
  REQUIRE(la->has_value());
  REQUIRE(**la == dek_of(0xaa));
  auto lb = kc->load_dek(b);
  REQUIRE(lb.has_value());
  REQUIRE(**lb == dek_of(0xbb));

  // store_dek replaces only its own item.
  REQUIRE(kc->store_dek(a, dek_of(0xa1)).has_value());
  REQUIRE(**kc->load_dek(a) == dek_of(0xa1));
  REQUIRE(**kc->load_dek(b) == dek_of(0xbb));

  // delete_dek removes only its own item.
  REQUIRE(kc->delete_dek(a).has_value());
  REQUIRE_FALSE(kc->load_dek(a)->has_value());
  REQUIRE(**kc->load_dek(b) == dek_of(0xbb));
  REQUIRE(kc->delete_dek(b).has_value());
  REQUIRE_FALSE(kc->load_dek(b)->has_value());
  REQUIRE_FALSE(kc->load_dek(random_install_id())->has_value());
}

TEST_CASE("macOS keychain: legacy 'dek' item is migrated only for its own install_id",
          "[keychain][macos]") {
  // Skip rather than destroy a real legacy item on a developer machine.
  if (legacy_item_exists()) {
    WARN("a legacy swpasskey 'dek' item exists in the login keychain; skipping");
    return;
  }
  auto kc = make_os_keychain();
  const auto mine = random_install_id();
  const auto other = random_install_id();
  add_legacy_item(mine, dek_of(0x11));

  // Another store must not see, migrate or delete it.
  REQUIRE_FALSE(kc->load_dek(other)->has_value());
  REQUIRE(kc->delete_dek(other).has_value());
  REQUIRE(legacy_item_exists());

  // The owning store gets its DEK back and the item moves to the new account.
  auto d = kc->load_dek(mine);
  REQUIRE(d.has_value());
  REQUIRE(d->has_value());
  REQUIRE(**d == dek_of(0x11));
  REQUIRE_FALSE(legacy_item_exists());
  REQUIRE(**kc->load_dek(mine) == dek_of(0x11));

  REQUIRE(kc->delete_dek(mine).has_value());
  REQUIRE_FALSE(kc->load_dek(mine)->has_value());
  remove_legacy_item();
}
