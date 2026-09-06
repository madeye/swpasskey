// macOS Keychain DEK item: service com.tangzixiang.swpasskey, account dek.
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
constexpr const char* kAccount = "dek";

class MacKeychain final : public Keychain {
public:
  Result<std::optional<std::array<std::uint8_t, 32>>> load_dek(std::string_view install_id) override {
    @autoreleasepool {
      NSDictionary* q = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @(kService),
        (id)kSecAttrAccount : @(kAccount),
        (id)kSecAttrLabel : @"swpasskey store DEK",
        (id)kSecReturnData : @YES,
        (id)kSecReturnAttributes : @YES,
        (id)kSecMatchLimit : (id)kSecMatchLimitOne,
      };
      CFTypeRef result = nullptr;
      const OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
      if (st == errSecItemNotFound) {
        return std::optional<std::array<std::uint8_t, 32>>{};
      }
      if (st != errSecSuccess) {
        log::warn("keychain_lookup_failed", {{"osstatus", std::to_string(st)}});
        return std::unexpected(Status::Other);
      }
      NSDictionary* attrs = CFBridgingRelease(result);
      NSData* data = attrs[(id)kSecValueData];
      NSString* comment = attrs[(id)kSecAttrComment];
      if (comment != nil && std::string([comment UTF8String]) != std::string(install_id)) {
        log::warn("keychain_dek_install_id_mismatch");
        return std::optional<std::array<std::uint8_t, 32>>{};
      }
      if (data == nil || data.length != 32) {
        log::error("keychain_dek_malformed");
        return std::unexpected(Status::Other);
      }
      std::array<std::uint8_t, 32> dek{};
      memcpy(dek.data(), data.bytes, 32);
      return std::optional<std::array<std::uint8_t, 32>>{dek};
    }
  }

  Result<void> store_dek(std::string_view install_id, std::span<const std::uint8_t, 32> dek) override {
    @autoreleasepool {
      (void)delete_dek(install_id);
      NSDictionary* add = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @(kService),
        (id)kSecAttrAccount : @(kAccount),
        (id)kSecAttrLabel : @"swpasskey store DEK",
        (id)kSecAttrComment : [NSString stringWithUTF8String:std::string(install_id).c_str()],
        (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        (id)kSecValueData : [NSData dataWithBytes:dek.data() length:dek.size()],
      };
      const OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, nullptr);
      if (st != errSecSuccess) {
        log::warn("keychain_add_failed", {{"osstatus", std::to_string(st)}});
        return std::unexpected(Status::Other);
      }
      return {};
    }
  }

  Result<void> delete_dek(std::string_view) override {
    @autoreleasepool {
      NSDictionary* q = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @(kService),
        (id)kSecAttrAccount : @(kAccount),
      };
      const OSStatus st = SecItemDelete((__bridge CFDictionaryRef)q);
      if (st != errSecSuccess && st != errSecItemNotFound) {
        return std::unexpected(Status::Other);
      }
      return {};
    }
  }

  const char* name() const override { return "macos-keychain"; }
};

}  // namespace

std::unique_ptr<Keychain> make_os_keychain() { return std::make_unique<MacKeychain>(); }

}  // namespace swpk::store

#endif  // __APPLE__
