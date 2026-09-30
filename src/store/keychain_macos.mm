// macOS Keychain DEK item: service com.tangzixiang.swpasskey, one generic
// password per store with account "dek.<install_id hex>". The install_id is
// part of the account so that two stores opened with the OS keychain (the real
// one and, say, a test run with --store /tmp/...) never overwrite each other's
// DEK. Before 2026-09-30 the account was the fixed string "dek" with the
// install_id only in the comment; such an item is migrated on first open.
// Uses the login keychain for an unbundled daemon; the data-protection
// keychain + access group need the signed .app (DESIGN.md "Keychain schema").
#if defined(__APPLE__)

#include "swpasskey/store/keychain.hpp"
#include "swpasskey/log/log.hpp"

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <string>

namespace swpk::store {
namespace {

constexpr const char* kService = "com.tangzixiang.swpasskey";
constexpr const char* kLegacyAccount = "dek";
constexpr const char* kLabel = "swpasskey store DEK";

NSString* account_for(std::string_view install_id) {
  return [NSString stringWithUTF8String:("dek." + std::string(install_id)).c_str()];
}

Result<std::optional<NSDictionary*>> copy_matching(NSString* account, bool with_data) {
  NSDictionary* q = @{
    (id)kSecClass : (id)kSecClassGenericPassword,
    (id)kSecAttrService : @(kService),
    (id)kSecAttrAccount : account,
    (id)kSecReturnData : with_data ? @YES : @NO,
    (id)kSecReturnAttributes : @YES,
    (id)kSecMatchLimit : (id)kSecMatchLimitOne,
  };
  CFTypeRef result = nullptr;
  const OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
  if (st == errSecItemNotFound) {
    return std::optional<NSDictionary*>{};
  }
  if (st != errSecSuccess) {
    log::warn("keychain_lookup_failed", {{"osstatus", std::to_string(st)}});
    return std::unexpected(Status::Other);
  }
  return std::optional<NSDictionary*>{(NSDictionary*)CFBridgingRelease(result)};
}

// Looks up one item by account. Returns the 32-byte DEK, nullopt when absent
// (or, for the legacy item, when its comment names another store). The
// ownership check reads attributes only, so another process's item never
// triggers a keychain access prompt.
Result<std::optional<std::array<std::uint8_t, 32>>> lookup(NSString* account,
                                                           std::string_view expect_comment) {
  if (!expect_comment.empty()) {
    auto attrs = copy_matching(account, false);
    if (!attrs) {
      return std::unexpected(attrs.error());
    }
    if (!attrs->has_value()) {
      return std::optional<std::array<std::uint8_t, 32>>{};
    }
    NSString* comment = (**attrs)[(id)kSecAttrComment];
    if (comment == nil || std::string([comment UTF8String]) != std::string(expect_comment)) {
      // The single pre-fix item belongs to some other store; leave it alone.
      log::warn("keychain_legacy_dek_other_install",
                {{"hint", "the legacy 'dek' item belongs to another store; not migrated"}});
      return std::optional<std::array<std::uint8_t, 32>>{};
    }
  }
  auto item = copy_matching(account, true);
  if (!item) {
    return std::unexpected(item.error());
  }
  if (!item->has_value()) {
    return std::optional<std::array<std::uint8_t, 32>>{};
  }
  NSDictionary* attrs = **item;
  NSData* data = attrs[(id)kSecValueData];
  if (data == nil || data.length != 32) {
    log::error("keychain_dek_malformed");
    return std::unexpected(Status::Other);
  }
  std::array<std::uint8_t, 32> dek{};
  memcpy(dek.data(), data.bytes, 32);
  return std::optional<std::array<std::uint8_t, 32>>{dek};
}

Result<void> remove(NSString* account) {
  NSDictionary* q = @{
    (id)kSecClass : (id)kSecClassGenericPassword,
    (id)kSecAttrService : @(kService),
    (id)kSecAttrAccount : account,
  };
  const OSStatus st = SecItemDelete((__bridge CFDictionaryRef)q);
  if (st != errSecSuccess && st != errSecItemNotFound) {
    log::warn("keychain_delete_failed", {{"osstatus", std::to_string(st)}});
    return std::unexpected(Status::Other);
  }
  return {};
}

Result<void> add(NSString* account, std::string_view install_id,
                 std::span<const std::uint8_t, 32> dek) {
  NSDictionary* item = @{
    (id)kSecClass : (id)kSecClassGenericPassword,
    (id)kSecAttrService : @(kService),
    (id)kSecAttrAccount : account,
    (id)kSecAttrLabel : @(kLabel),
    (id)kSecAttrComment : [NSString stringWithUTF8String:std::string(install_id).c_str()],
    (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    (id)kSecValueData : [NSData dataWithBytes:dek.data() length:dek.size()],
  };
  const OSStatus st = SecItemAdd((__bridge CFDictionaryRef)item, nullptr);
  if (st != errSecSuccess) {
    log::warn("keychain_add_failed", {{"osstatus", std::to_string(st)}});
    return std::unexpected(Status::Other);
  }
  return {};
}

class MacKeychain final : public Keychain {
public:
  Result<std::optional<std::array<std::uint8_t, 32>>> load_dek(std::string_view install_id) override {
    @autoreleasepool {
      auto d = lookup(account_for(install_id), "");
      if (!d || d->has_value()) {
        return d;
      }
      // Not under the per-store account: a store created before the account
      // carried the install_id. Migrate its item if it is ours.
      auto legacy = lookup(@(kLegacyAccount), install_id);
      if (!legacy || !legacy->has_value()) {
        return legacy;
      }
      if (auto r = add(account_for(install_id), install_id, **legacy); !r) {
        return std::unexpected(r.error());
      }
      (void)remove(@(kLegacyAccount));
      log::info("keychain_dek_migrated", {{"install_id", std::string(install_id)}});
      return legacy;
    }
  }

  Result<void> store_dek(std::string_view install_id, std::span<const std::uint8_t, 32> dek) override {
    @autoreleasepool {
      (void)remove(account_for(install_id));
      return add(account_for(install_id), install_id, dek);
    }
  }

  Result<void> delete_dek(std::string_view install_id) override {
    @autoreleasepool {
      auto r = remove(account_for(install_id));
      // Also drop a legacy item, but only if it is this store's.
      auto legacy = lookup(@(kLegacyAccount), install_id);
      if (legacy && legacy->has_value()) {
        (void)remove(@(kLegacyAccount));
      }
      return r;
    }
  }

  const char* name() const override { return "macos-keychain"; }
};

}  // namespace

std::unique_ptr<Keychain> make_os_keychain() { return std::make_unique<MacKeychain>(); }

}  // namespace swpk::store

#endif  // __APPLE__
