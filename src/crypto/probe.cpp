// --key-backend probe order (DESIGN.md "Probe order").
#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/log/log.hpp"

namespace swpk::crypto {

std::unique_ptr<KeyBackend> probe_key_backend(const ProbeOptions& opt, std::string& detail) {
  const std::string_view pref = opt.pref;
  if (pref == "software") {
    detail = "probe=forced_software";
    return std::make_unique<SoftwareKeyBackend>();
  }

  if (pref == "se") {
#if defined(__APPLE__)
    std::string why;
    auto b = make_se_key_backend(why);
    if (!b) {
      detail = "probe=se_unavailable err=" + why;
      log::error("key_backend_unavailable", {{"backend", "se"}, {"err", why}});
      return nullptr;
    }
    detail = "probe=ok";
    return b;
#else
    detail = "probe=se_not_supported_on_this_os";
    log::error("key_backend_unavailable", {{"backend", "se"}, {"err", "macOS only"}});
    return nullptr;
#endif
  }

  if (pref == "tpm") {
#if defined(SWPASSKEY_TPM)
    std::string why;
    auto b = make_tpm2_key_backend(opt, why);
    if (!b) {
      detail = "probe=tpm_unavailable " + why;
      log::error("key_backend_unavailable", {{"backend", "tpm"}, {"err", why}});
      return nullptr;
    }
    detail = "probe=ok " + why;
    return b;
#else
    detail = "probe=tpm_not_built";
    log::error("key_backend_unavailable",
               {{"backend", "tpm"}, {"err", "rebuild with libtss2 (SWPASSKEY_TPM=ON)"}});
    return nullptr;
#endif
  }

  // auto
#if defined(__APPLE__)
  {
    std::string why;
    auto b = make_se_key_backend(why);
    if (b) {
      detail = "probe=ok";
      return b;
    }
    detail = "probe=se_unavailable err=" + why;
    log::warn("key_backend_fallback", {{"wanted", "se"}, {"using", "software"}, {"err", why}});
    return std::make_unique<SoftwareKeyBackend>();
  }
#elif defined(SWPASSKEY_TPM)
  {
    std::string why;
    auto b = make_tpm2_key_backend(opt, why);
    if (b) {
      detail = "probe=ok " + why;
      return b;
    }
    detail = "probe=tpm_unavailable " + why;
    log::warn("key_backend_fallback", {{"wanted", "tpm"}, {"using", "software"}, {"err", why}});
    return std::make_unique<SoftwareKeyBackend>();
  }
#else
  detail = "probe=no_hw_backend_built";
  return std::make_unique<SoftwareKeyBackend>();
#endif
}

std::unique_ptr<KeyBackend> probe_key_backend(std::string_view pref) {
  ProbeOptions opt;
  opt.pref = std::string(pref);
  std::string detail;
  return probe_key_backend(opt, detail);
}

}  // namespace swpk::crypto
