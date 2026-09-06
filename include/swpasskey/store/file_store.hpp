#pragma once

#include "swpasskey/store/credential.hpp"
#include "swpasskey/store/keychain.hpp"

#include <filesystem>
#include <memory>

namespace swpk::crypto {
class Provider;
}

namespace swpk::store {

inline constexpr std::uint16_t kStoreVersion = 1;

// Opens (or creates) the AES-256-GCM credential store at `path`
// (DESIGN.md "File format credentials.bin"). Takes an exclusive flock on
// `<path>.lock` for the life of the returned store; a second daemon fails.
// The DEK is looked up in `keychain` by install_id, generated on first use.
Result<std::unique_ptr<CredentialStore>> open_file_store(const std::filesystem::path& path,
                                                         crypto::Provider& crypto,
                                                         Keychain& keychain);

}  // namespace swpk::store
