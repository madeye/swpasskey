#include "swpasskey/crypto/provider.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <cstring>
#include <memory>

namespace swpk::crypto {
namespace {

struct EvpMdCtxDel {
  void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
};
struct EvpCipherCtxDel {
  void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); }
};
struct EvpPkeyDel {
  void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
struct EvpPkeyCtxDel {
  void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
};
struct BnDel {
  void operator()(BIGNUM* p) const { BN_clear_free(p); }
};
struct EvpKdfDel {
  void operator()(EVP_KDF* p) const { EVP_KDF_free(p); }
};
struct EvpKdfCtxDel {
  void operator()(EVP_KDF_CTX* p) const { EVP_KDF_CTX_free(p); }
};

using MdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDel>;
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDel>;
using Pkey = std::unique_ptr<EVP_PKEY, EvpPkeyDel>;
using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDel>;
using Bn = std::unique_ptr<BIGNUM, BnDel>;

constexpr std::uint8_t kP256N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};

Result<Pkey> p256_from_xy(const P256PublicKey& pub) {
  std::uint8_t enc[65];
  enc[0] = 0x04;
  std::memcpy(enc + 1, pub.x.data(), 32);
  std::memcpy(enc + 33, pub.y.data(), 32);
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                       const_cast<char*>("P-256"), 0),
      OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, enc, sizeof(enc)),
      OSSL_PARAM_construct_end()};
  PkeyCtx ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    return std::unexpected(Status::Other);
  }
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
    return std::unexpected(Status::Other);
  }
  return Pkey{raw};
}

}  // namespace

Result<void> Provider::random(std::span<std::uint8_t> out) {
  if (out.empty()) {
    return {};
  }
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    return std::unexpected(Status::Other);
  }
  return {};
}

std::array<std::uint8_t, 32> Provider::sha256(std::span<const std::uint8_t> data) const {
  std::array<std::uint8_t, 32> out{};
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr);
  return out;
}

bool Provider::consttime_equal(std::span<const std::uint8_t> a,
                               std::span<const std::uint8_t> b) const {
  if (a.size() != b.size()) {
    return false;
  }
  if (a.empty()) {
    return true;
  }
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

Result<std::vector<std::uint8_t>> Provider::aes256gcm_encrypt(
    std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
    std::span<const std::uint8_t> aad, std::span<const std::uint8_t> pt) {
  CipherCtx ctx{EVP_CIPHER_CTX_new()};
  if (!ctx) {
    return std::unexpected(Status::Other);
  }
  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
      EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
    return std::unexpected(Status::Other);
  }
  int outl = 0;
  if (!aad.empty() &&
      EVP_EncryptUpdate(ctx.get(), nullptr, &outl, aad.data(), static_cast<int>(aad.size())) != 1) {
    return std::unexpected(Status::Other);
  }
  std::vector<std::uint8_t> out(pt.size() + 16);
  if (!pt.empty() &&
      EVP_EncryptUpdate(ctx.get(), out.data(), &outl, pt.data(), static_cast<int>(pt.size())) != 1) {
    return std::unexpected(Status::Other);
  }
  int fin = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), out.data() + outl, &fin) != 1) {
    return std::unexpected(Status::Other);
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16,
                          out.data() + static_cast<std::size_t>(outl + fin)) != 1) {
    return std::unexpected(Status::Other);
  }
  out.resize(static_cast<std::size_t>(outl + fin) + 16);
  return out;
}

Result<std::vector<std::uint8_t>> Provider::aes256gcm_decrypt(
    std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 12> nonce,
    std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ct_and_tag) {
  if (ct_and_tag.size() < 16) {
    return std::unexpected(Status::Other);
  }
  const auto ct = ct_and_tag.first(ct_and_tag.size() - 16);
  std::array<std::uint8_t, 16> tag{};
  std::memcpy(tag.data(), ct_and_tag.data() + ct.size(), 16);
  CipherCtx ctx{EVP_CIPHER_CTX_new()};
  if (!ctx ||
      EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
      EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
    return std::unexpected(Status::Other);
  }
  int outl = 0;
  if (!aad.empty() &&
      EVP_DecryptUpdate(ctx.get(), nullptr, &outl, aad.data(), static_cast<int>(aad.size())) != 1) {
    return std::unexpected(Status::Other);
  }
  std::vector<std::uint8_t> pt(ct.size());
  if (!ct.empty() &&
      EVP_DecryptUpdate(ctx.get(), pt.data(), &outl, ct.data(), static_cast<int>(ct.size())) != 1) {
    return std::unexpected(Status::Other);
  }
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
    return std::unexpected(Status::Other);
  }
  int fin = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), pt.data() + outl, &fin) != 1) {
    return std::unexpected(Status::Other);
  }
  pt.resize(static_cast<std::size_t>(outl + fin));
  return pt;
}

Result<std::vector<std::uint8_t>> Provider::aes256cbc_encrypt(
    std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> iv,
    std::span<const std::uint8_t> pt) {
  if (pt.size() % 16 != 0) {
    return std::unexpected(Status::InvalidParameter);
  }
  CipherCtx ctx{EVP_CIPHER_CTX_new()};
  if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
    return std::unexpected(Status::Other);
  }
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  std::vector<std::uint8_t> out(pt.size());
  int outl = 0;
  if (!pt.empty() &&
      EVP_EncryptUpdate(ctx.get(), out.data(), &outl, pt.data(), static_cast<int>(pt.size())) != 1) {
    return std::unexpected(Status::Other);
  }
  int fin = 0;
  if (EVP_EncryptFinal_ex(ctx.get(), out.data() + outl, &fin) != 1) {
    return std::unexpected(Status::Other);
  }
  out.resize(static_cast<std::size_t>(outl + fin));
  return out;
}

Result<std::vector<std::uint8_t>> Provider::aes256cbc_decrypt(
    std::span<const std::uint8_t, 32> key, std::span<const std::uint8_t, 16> iv,
    std::span<const std::uint8_t> ct) {
  if (ct.size() % 16 != 0) {
    return std::unexpected(Status::InvalidParameter);
  }
  CipherCtx ctx{EVP_CIPHER_CTX_new()};
  if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
    return std::unexpected(Status::Other);
  }
  EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
  std::vector<std::uint8_t> out(ct.size());
  int outl = 0;
  if (!ct.empty() &&
      EVP_DecryptUpdate(ctx.get(), out.data(), &outl, ct.data(), static_cast<int>(ct.size())) != 1) {
    return std::unexpected(Status::Other);
  }
  int fin = 0;
  if (EVP_DecryptFinal_ex(ctx.get(), out.data() + outl, &fin) != 1) {
    return std::unexpected(Status::Other);
  }
  out.resize(static_cast<std::size_t>(outl + fin));
  return out;
}

Result<std::array<std::uint8_t, 32>> Provider::hkdf_sha256(std::span<const std::uint8_t> ikm,
                                                          std::span<const std::uint8_t> salt,
                                                          std::span<const std::uint8_t> info) {
  std::unique_ptr<EVP_KDF, EvpKdfDel> kdf{EVP_KDF_fetch(nullptr, "HKDF", nullptr)};
  if (!kdf) {
    return std::unexpected(Status::Other);
  }
  std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDel> kctx{EVP_KDF_CTX_new(kdf.get())};
  char digest[] = "SHA256";
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                        const_cast<std::uint8_t*>(ikm.data()), ikm.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                        const_cast<std::uint8_t*>(salt.data()), salt.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                        const_cast<std::uint8_t*>(info.data()), info.size()),
      OSSL_PARAM_construct_end()};
  std::array<std::uint8_t, 32> out{};
  if (EVP_KDF_derive(kctx.get(), out.data(), out.size(), params) <= 0) {
    return std::unexpected(Status::Other);
  }
  return out;
}

Result<std::array<std::uint8_t, 32>> Provider::hmac_sha256(std::span<const std::uint8_t> key,
                                                          std::span<const std::uint8_t> msg) {
  MdCtx ctx{EVP_MD_CTX_new()};
  Pkey mac{EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, key.data(), static_cast<int>(key.size()))};
  if (!ctx || !mac) {
    return std::unexpected(Status::Other);
  }
  if (EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, mac.get()) != 1) {
    return std::unexpected(Status::Other);
  }
  std::array<std::uint8_t, 32> out{};
  std::size_t len = out.size();
  if (EVP_DigestSign(ctx.get(), out.data(), &len, msg.data(), msg.size()) != 1 || len != 32) {
    return std::unexpected(Status::Other);
  }
  return out;
}

Provider::SoftwareEcdhKey::SoftwareEcdhKey(void* pkey) : pkey_(pkey) {}
Provider::SoftwareEcdhKey::~SoftwareEcdhKey() {
  EVP_PKEY_free(static_cast<EVP_PKEY*>(pkey_));
}

P256PublicKey Provider::SoftwareEcdhKey::pub() const {
  P256PublicKey out;
  auto* pkey = static_cast<EVP_PKEY*>(pkey_);
  std::uint8_t enc[65];
  std::size_t len = sizeof(enc);
  if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, enc, sizeof(enc),
                                      &len) != 1 ||
      len != 65 || enc[0] != 0x04) {
    return out;
  }
  std::memcpy(out.x.data(), enc + 1, 32);
  std::memcpy(out.y.data(), enc + 33, 32);
  return out;
}

Result<std::array<std::uint8_t, 32>> Provider::SoftwareEcdhKey::shared_secret_x(
    const P256PublicKey& peer) const {
  auto peer_key = p256_from_xy(peer);
  if (!peer_key) {
    return std::unexpected(peer_key.error());
  }
  PkeyCtx ctx{EVP_PKEY_CTX_new(static_cast<EVP_PKEY*>(pkey_), nullptr)};
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 ||
      EVP_PKEY_derive_set_peer(ctx.get(), peer_key->get()) <= 0) {
    return std::unexpected(Status::Other);
  }
  std::uint8_t secret[32];
  std::size_t len = sizeof(secret);
  if (EVP_PKEY_derive(ctx.get(), secret, &len) <= 0 || len != 32) {
    return std::unexpected(Status::Other);
  }
  std::array<std::uint8_t, 32> out{};
  std::memcpy(out.data(), secret, 32);
  OPENSSL_cleanse(secret, sizeof(secret));
  return out;
}

Result<std::unique_ptr<Provider::SoftwareEcdhKey>> Provider::generate_p256_ephemeral() {
  EVP_PKEY* raw = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
  if (!raw) {
    return std::unexpected(Status::Other);
  }
  return std::make_unique<SoftwareEcdhKey>(raw);
}

Result<std::array<std::uint8_t, 32>> Provider::p256_ecdh_x(
    std::span<const std::uint8_t, 32> our_scalar, const P256PublicKey& peer) {
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>("P-256"), 0),
      OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, const_cast<std::uint8_t*>(our_scalar.data()),
                              our_scalar.size()),
      OSSL_PARAM_construct_end()};
  PkeyCtx ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
  EVP_PKEY* raw = nullptr;
  if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
      EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_KEYPAIR, params) <= 0) {
    return std::unexpected(Status::Other);
  }
  SoftwareEcdhKey ours(raw);
  return ours.shared_secret_x(peer);
}

std::vector<std::uint8_t> Provider::ecdsa_p256_rs_to_der_low_s(
    std::span<const std::uint8_t, 32> r, std::span<const std::uint8_t, 32> s) {
  Bn rb{BN_bin2bn(r.data(), 32, nullptr)};
  Bn sb{BN_bin2bn(s.data(), 32, nullptr)};
  Bn n{BN_bin2bn(kP256N, 32, nullptr)};
  Bn half{BN_new()};
  Bn s2{BN_new()};
  if (!rb || !sb || !n || !half || !s2) {
    return {};
  }
  BN_rshift1(half.get(), n.get());
  if (BN_cmp(sb.get(), half.get()) > 0) {
    BN_sub(s2.get(), n.get(), sb.get());
    sb.swap(s2);
  }
  auto encode_int = [](const BIGNUM* v) {
    std::vector<std::uint8_t> b(static_cast<std::size_t>(BN_num_bytes(v)));
    BN_bn2bin(v, b.data());
    if (b.empty() || (b[0] & 0x80) != 0) {
      b.insert(b.begin(), 0);
    }
    std::vector<std::uint8_t> out;
    out.push_back(0x02);
    out.push_back(static_cast<std::uint8_t>(b.size()));
    out.insert(out.end(), b.begin(), b.end());
    return out;
  };
  auto ri = encode_int(rb.get());
  auto si = encode_int(sb.get());
  std::vector<std::uint8_t> seq;
  seq.push_back(0x30);
  seq.push_back(static_cast<std::uint8_t>(ri.size() + si.size()));
  seq.insert(seq.end(), ri.begin(), ri.end());
  seq.insert(seq.end(), si.begin(), si.end());
  return seq;
}

Result<std::vector<std::uint8_t>> Provider::ecdsa_p256_der_normalize_low_s(
    std::span<const std::uint8_t> der) {
  const unsigned char* p = der.data();
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
  if (!sig) {
    return std::unexpected(Status::Other);
  }
  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);
  std::array<std::uint8_t, 32> rb{}, sb{};
  BN_bn2binpad(r, rb.data(), 32);
  BN_bn2binpad(s, sb.data(), 32);
  ECDSA_SIG_free(sig);
  return ecdsa_p256_rs_to_der_low_s(rb, sb);
}

}  // namespace swpk::crypto
