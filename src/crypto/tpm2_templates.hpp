// Frozen TPM 2.0 templates (DESIGN.md "Linux TPM 2.0"). Format-stable: a
// change here makes every persisted handle unloadable.
#pragma once

#include "swpasskey/status.hpp"

#include <tss2/tss2_tpm2_types.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace swpk::crypto::tpm2 {

inline constexpr char kPrimaryUniqueInfo[] = "swpasskey-ecc-primary-unique";

// Install-bound ECC primary (owner hierarchy). unique.x = HKDF-SHA-256(seed,
// salt=32x00, info=kPrimaryUniqueInfo, L=32); unique.y empty.
Result<TPM2B_PUBLIC> primary_template(std::span<const std::uint8_t, 32> srk_unique_seed);
// Per-credential P-256 ECDSA/SHA-256 signing child (not restricted).
TPM2B_PUBLIC signing_child_template();
// Sealed keyedhash object for hmac-secret credRandom (no SENSITIVEDATAORIGIN).
TPM2B_PUBLIC seal_template();

// Tss2_MU marshalling helpers (never hand-roll TPM2B layout).
Result<std::vector<std::uint8_t>> marshal_public(const TPM2B_PUBLIC& p);
Result<std::vector<std::uint8_t>> marshal_private(const TPM2B_PRIVATE& p);
Result<TPM2B_PUBLIC> unmarshal_public(std::span<const std::uint8_t> b);
Result<TPM2B_PRIVATE> unmarshal_private(std::span<const std::uint8_t> b);

// handle = u16be(pub.size) || pub || u16be(priv.size) || priv
std::vector<std::uint8_t> encode_handle(std::span<const std::uint8_t> pub,
                                        std::span<const std::uint8_t> priv);
Result<std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>> decode_handle(
    std::span<const std::uint8_t> handle);

}  // namespace swpk::crypto::tpm2
