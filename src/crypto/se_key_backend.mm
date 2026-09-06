// macOS Secure Enclave KeyBackend (DESIGN.md "macOS Secure Enclave").
// Security.framework C API only. Requires the signed .app with
// keychain-access-groups for the data-protection keychain; from an unsigned
// CLI the probe fails with errSecMissingEntitlement and `auto` falls back to
// software with a loud log (R11).
#if defined(__APPLE__)

#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/log/log.hpp"

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <cstring>
#include <string>

namespace swpk::crypto {
namespace {

constexpr const char* kTagPrefix = "io.github.swpasskey.se.";
constexpr const char* kHmacService = "io.github.swpasskey";
constexpr const char* kHmacAccountPrefix = "hmac.";
constexpr const char* kLabel = "swpasskey";

std::string hex(std::span<const std::uint8_t> v) {
  static constexpr char kH[] = "0123456789abcdef";
  std::string s;
  for (auto b : v) {
    s.push_back(kH[b >> 4]);
    s.push_back(kH[b & 15]);
  }
  return s;
}

std::string cferr(CFErrorRef err) {
  if (err == nullptr) {
    return "unknown";
  }
  NSError* e = (__bridge NSError*)err;
  const char* desc = [[e localizedDescription] UTF8String];
  return std::to_string(e.code) + " " + std::string(desc != nullptr ? desc : "");
}

NSData* tag_data(std::span<const std::uint8_t> handle) {
  return [NSData dataWithBytes:handle.data() length:handle.size()];
}

Result<P256PublicKey> pub_from_seckey(SecKeyRef priv) {
  SecKeyRef pub = SecKeyCopyPublicKey(priv);
  if (pub == nullptr) {
    return std::unexpected(Status::Other);
  }
  CFErrorRef err = nullptr;
  CFDataRef ext = SecKeyCopyExternalRepresentation(pub, &err);
  CFRelease(pub);
  if (ext == nullptr) {
    if (err) CFRelease(err);
    return std::unexpected(Status::Other);
  }
  P256PublicKey out;
  const bool ok = CFDataGetLength(ext) == 65 && CFDataGetBytePtr(ext)[0] == 0x04;
  if (ok) {
    std::memcpy(out.x.data(), CFDataGetBytePtr(ext) + 1, 32);
    std::memcpy(out.y.data(), CFDataGetBytePtr(ext) + 33, 32);
  }
  CFRelease(ext);
  if (!ok) {
    return std::unexpected(Status::Other);
  }
  return out;
}

class SeSigningKey final : public SigningKey {
public:
  SeSigningKey(SecKeyRef key, P256PublicKey pub, std::vector<std::uint8_t> tag)
      : key_(key), pub_(pub), tag_(std::move(tag)) {}
  ~SeSigningKey() override {
    if (key_) CFRelease(key_);
  }
  BackendKind kind() const override { return BackendKind::SecureEnclave; }
  P256PublicKey pub() const override { return pub_; }

  Result<std::vector<std::uint8_t>> sign_der(std::span<const std::uint8_t> message) const override {
    @autoreleasepool {
      CFErrorRef err = nullptr;
      CFDataRef msg = CFDataCreate(kCFAllocatorDefault, message.data(),
                                   static_cast<CFIndex>(message.size()));
      // Message variant: SHA-256 is applied by Security.framework. Do not pre-hash.
      CFDataRef sig = SecKeyCreateSignature(key_, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                            msg, &err);
      CFRelease(msg);
      if (sig == nullptr) {
        log::error("se_sign_failed", {{"err", cferr(err)}});
        if (err) CFRelease(err);
        return std::unexpected(Status::Other);
      }
      std::vector<std::uint8_t> der(CFDataGetBytePtr(sig),
                                    CFDataGetBytePtr(sig) + CFDataGetLength(sig));
      CFRelease(sig);
      return Provider::ecdsa_p256_der_normalize_low_s(der);
    }
  }

  std::vector<std::uint8_t> persist_handle() const override { return tag_; }

private:
  SecKeyRef key_;
  P256PublicKey pub_;
  std::vector<std::uint8_t> tag_;
};

class SecureEnclaveKeyBackend final : public KeyBackend {
public:
  BackendKind kind() const override { return BackendKind::SecureEnclave; }

  Result<std::unique_ptr<SigningKey>> generate() override {
    @autoreleasepool {
      std::uint8_t rnd[32];
      Provider rng;
      if (!rng.random(rnd)) {
        return std::unexpected(Status::Other);
      }
      const std::string tag = std::string(kTagPrefix) + hex(rnd);
      std::vector<std::uint8_t> tag_bytes(tag.begin(), tag.end());
      return create_permanent(tag_bytes);
    }
  }

  Result<std::unique_ptr<SigningKey>> load(std::span<const std::uint8_t> handle,
                                           const P256PublicKey& pub) override {
    @autoreleasepool {
      NSDictionary* q = @{
        (id)kSecClass : (id)kSecClassKey,
        (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrTokenID : (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecAttrApplicationTag : tag_data(handle),
        (id)kSecUseDataProtectionKeychain : @YES,
        (id)kSecReturnRef : @YES,
      };
      CFTypeRef ref = nullptr;
      const OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref);
      if (st != errSecSuccess || ref == nullptr) {
        log::error("se_load_failed", {{"osstatus", std::to_string(st)}});
        return std::unexpected(Status::InvalidCredential);
      }
      SecKeyRef key = (SecKeyRef)ref;
      auto p = pub_from_seckey(key);
      if (!p || p->x != pub.x || p->y != pub.y) {
        CFRelease(key);
        log::error("se_load_pub_mismatch");
        return std::unexpected(Status::InvalidCredential);
      }
      return std::make_unique<SeSigningKey>(key, *p,
                                            std::vector<std::uint8_t>(handle.begin(), handle.end()));
    }
  }

  Result<void> destroy(std::span<const std::uint8_t> handle) override {
    @autoreleasepool {
      if (handle.empty()) {
        return {};
      }
      NSDictionary* q = @{
        (id)kSecClass : (id)kSecClassKey,
        (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrTokenID : (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecAttrApplicationTag : tag_data(handle),
        (id)kSecUseDataProtectionKeychain : @YES,
      };
      const OSStatus st = SecItemDelete((__bridge CFDictionaryRef)q);
      if (st != errSecSuccess && st != errSecItemNotFound) {
        log::warn("se_destroy_failed", {{"osstatus", std::to_string(st)}});
        return std::unexpected(Status::Other);
      }
      return {};
    }
  }

  // Keychain generic-password item (Data Protection class, not SE-wrapped —
  // DESIGN.md is explicit about this gap). Handle = account string.
  Result<std::vector<std::uint8_t>> wrap_secret(std::span<const std::uint8_t> secret) override {
    @autoreleasepool {
      std::uint8_t rnd[16];
      Provider rng;
      if (!rng.random(rnd)) {
        return std::unexpected(Status::Other);
      }
      const std::string account = std::string(kHmacAccountPrefix) + hex(rnd);
      NSDictionary* add = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @(kHmacService),
        (id)kSecAttrAccount : [NSString stringWithUTF8String:account.c_str()],
        (id)kSecAttrLabel : @(kLabel),
        (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        (id)kSecUseDataProtectionKeychain : @YES,
        (id)kSecValueData : [NSData dataWithBytes:secret.data() length:secret.size()],
      };
      const OSStatus st = SecItemAdd((__bridge CFDictionaryRef)add, nullptr);
      if (st != errSecSuccess) {
        log::error("se_wrap_secret_failed", {{"osstatus", std::to_string(st)}});
        return std::unexpected(Status::Other);
      }
      return std::vector<std::uint8_t>(account.begin(), account.end());
    }
  }

  Result<std::vector<std::uint8_t>> unwrap_secret(std::span<const std::uint8_t> wrapped) override {
    @autoreleasepool {
      NSDictionary* q = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @(kHmacService),
        (id)kSecAttrAccount : [[NSString alloc] initWithBytes:wrapped.data()
                                                       length:wrapped.size()
                                                     encoding:NSUTF8StringEncoding],
        (id)kSecUseDataProtectionKeychain : @YES,
        (id)kSecReturnData : @YES,
        (id)kSecMatchLimit : (id)kSecMatchLimitOne,
      };
      CFTypeRef out = nullptr;
      const OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &out);
      if (st != errSecSuccess || out == nullptr) {
        log::error("se_unwrap_secret_failed", {{"osstatus", std::to_string(st)}});
        return std::unexpected(Status::Other);
      }
      NSData* data = CFBridgingRelease(out);
      return std::vector<std::uint8_t>(static_cast<const std::uint8_t*>(data.bytes),
                                       static_cast<const std::uint8_t*>(data.bytes) + data.length);
    }
  }

  // Try-create probe: throwaway permanent key, then delete. Returns the
  // OSStatus / CFError text on failure for the startup log.
  static Result<void> probe(std::string& why) {
    @autoreleasepool {
      SecureEnclaveKeyBackend b;
      const std::string tag = std::string(kTagPrefix) + "probe";
      std::vector<std::uint8_t> tag_bytes(tag.begin(), tag.end());
      auto k = b.create_permanent(tag_bytes, &why);
      (void)b.destroy(tag_bytes);
      if (!k) {
        return std::unexpected(Status::Other);
      }
      return {};
    }
  }

private:
  Result<std::unique_ptr<SigningKey>> create_permanent(const std::vector<std::uint8_t>& tag,
                                                       std::string* why = nullptr) {
    CFErrorRef err = nullptr;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,  // NOT UserPresence / BiometryAny (K22)
        &err);
    if (ac == nullptr) {
      const std::string e = cferr(err);
      if (why) *why = e;
      if (err) CFRelease(err);
      return std::unexpected(Status::Other);
    }
    NSDictionary* attrs = @{
      (id)kSecAttrTokenID : (id)kSecAttrTokenIDSecureEnclave,
      (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
      (id)kSecAttrKeySizeInBits : @256,
      (id)kSecAttrLabel : @(kLabel),
      (id)kSecUseDataProtectionKeychain : @YES,
      (id)kSecPrivateKeyAttrs : @{
        (id)kSecAttrIsPermanent : @YES,
        (id)kSecAttrApplicationTag : tag_data(tag),
        (id)kSecAttrAccessControl : (__bridge id)ac,
      },
    };
    SecKeyRef priv = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &err);
    CFRelease(ac);
    if (priv == nullptr) {
      const std::string e = cferr(err);
      if (why) *why = e;
      log::error("se_generate_failed", {{"err", e}});
      if (err) CFRelease(err);
      return std::unexpected(Status::Other);
    }
    auto pub = pub_from_seckey(priv);
    if (!pub) {
      CFRelease(priv);
      return std::unexpected(Status::Other);
    }
    return std::make_unique<SeSigningKey>(priv, *pub, tag);
  }
};

}  // namespace

std::unique_ptr<KeyBackend> make_se_key_backend(std::string& why) {
  if (auto p = SecureEnclaveKeyBackend::probe(why); !p) {
    return nullptr;
  }
  return std::make_unique<SecureEnclaveKeyBackend>();
}

}  // namespace swpk::crypto

#endif  // __APPLE__
