#include "swpasskey/constants.hpp"
#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/daemon/loop.hpp"
#include "swpasskey/daemon/paths.hpp"
#include "swpasskey/hid/transport.hpp"
#include "swpasskey/log/log.hpp"
#include "swpasskey/store/credential.hpp"
#include "swpasskey/ui/presence.hpp"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kUsage =
    "swpasskeyd — software USB-HID FIDO2 authenticator\n"
    "\n"
    "Usage: swpasskeyd [options]\n"
    "  --help                         Show this help\n"
    "  --version                      Print version and exit\n"
    "  --key-backend=auto|se|tpm|software\n"
    "  --store PATH                   Credential store path\n"
    "  --testing                      Enable test-only presence auto-allow\n"
    "                                 (refused in RelWithDebInfo/Release)\n"
    "\n"
    "Env: SWPASSKEY_LOG=error|warn|info|debug, SWPASSKEY_TESTING=1,\n"
    "     SWPASSKEY_TPM_UNSAFE_NOTPMRM=1\n"
    "\n"
    "This is a software authenticator. Hardware engines (TPM / Secure Enclave)\n"
    "protect private scalars from extraction, not from same-uid use. The\n"
    "Approve prompt is daemon UX, not on-chip user presence.\n";

#ifndef SWPASSKEY_VERSION
#define SWPASSKEY_VERSION "0.1.0-dev"
#endif

void print_version() { std::printf("swpasskeyd %s\n", SWPASSKEY_VERSION); }

swpk::daemon::Loop* g_loop = nullptr;

void on_signal(int) {
  if (g_loop != nullptr) {
    g_loop->stop();
  }
}

struct Options {
  std::string key_backend{"auto"};
  std::filesystem::path store;
  bool testing{false};
};

}  // namespace

int main(int argc, char** argv) {
  swpk::log::set_level_from_env();
  Options opt;
  if (const char* t = std::getenv("SWPASSKEY_TESTING"); t != nullptr && std::strcmp(t, "1") == 0) {
    opt.testing = true;
  }

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg{argv[i]};
    if (arg == "--help" || arg == "-h") {
      std::fputs(kUsage.data(), stdout);
      return 0;
    }
    if (arg == "--version" || arg == "-V") {
      print_version();
      return 0;
    }
    if (arg.starts_with("--key-backend=")) {
      opt.key_backend = std::string(arg.substr(std::strlen("--key-backend=")));
      continue;
    }
    if (arg == "--store") {
      if (i + 1 >= argc) {
        std::fputs("swpasskeyd: --store requires a path\n", stderr);
        return 2;
      }
      opt.store = argv[++i];
      continue;
    }
    if (arg.starts_with("--store=")) {
      opt.store = std::string(arg.substr(std::strlen("--store=")));
      continue;
    }
    if (arg == "--testing") {
      opt.testing = true;
      continue;
    }
    std::fprintf(stderr, "swpasskeyd: unknown option '%s'\n", argv[i]);
    return 2;
  }

  if (opt.key_backend != "auto" && opt.key_backend != "se" && opt.key_backend != "tpm" &&
      opt.key_backend != "software") {
    std::fprintf(stderr, "swpasskeyd: --key-backend must be auto|se|tpm|software\n");
    return 2;
  }
  if (opt.store.empty()) {
    opt.store = swpk::daemon::default_store_path();
  }
  const auto data_dir = opt.store.parent_path();
  if (!swpk::daemon::ensure_dir(data_dir)) {
    return 1;
  }

  // Single instance: flock next to the eventual store (PR3: runtime lock).
  auto lock = swpk::daemon::InstanceLock::acquire(
      swpk::daemon::default_runtime_dir() / "swpasskeyd.lock");
  if (!lock) {
    std::fputs("swpasskeyd: already running (lock held)\n", stderr);
    return 1;
  }

  auto serial = swpk::daemon::load_or_create_serial(data_dir / "serial");
  if (!serial) {
    return 1;
  }

  swpk::crypto::Provider crypto;
  auto primary = swpk::crypto::probe_key_backend(opt.key_backend);
  if (!primary) {
    std::fprintf(stderr, "swpasskeyd: key backend '%s' unavailable\n", opt.key_backend.c_str());
    return 1;
  }
  swpk::crypto::SoftwareKeyBackend software;
  swpk::crypto::KeyBackend& software_ref =
      primary->kind() == swpk::crypto::BackendKind::Software ? *primary : software;

  auto store = swpk::store::CredentialStore::open_memory();  // PR5: on-disk
  (void)store->set_serial(*serial);

  swpk::ui::PresenceConfig pcfg;
  pcfg.testing = opt.testing;
  auto presence = swpk::ui::make_presence(pcfg);
  if (!presence) {
    std::fputs("swpasskeyd: --testing is not available in this build\n", stderr);
    return 1;
  }

  swpk::ctap::AuthenticatorConfig acfg;
  swpk::ctap::Authenticator auth(acfg, crypto, *primary, software_ref, *store, *presence);

  swpk::hid::DeviceConfig dcfg;
  dcfg.serial = *serial;
  auto transport = swpk::hid::make_transport(dcfg);
  if (!transport) {
    std::fputs("swpasskeyd: no HID transport on this platform\n", stderr);
    return 1;
  }
  if (!transport->open()) {
    std::fputs("swpasskeyd: failed to create the virtual HID device (see log)\n", stderr);
    return 1;
  }

  swpk::daemon::Loop loop(*transport, auth, crypto);
  g_loop = &loop;
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  std::signal(SIGPIPE, SIG_IGN);

  swpk::log::info("startup", {{"version", SWPASSKEY_VERSION},
                              {"key_backend", auth.primary_backend_name()},
                              {"transport", transport->describe()},
                              {"serial", *serial},
                              {"presence", presence->name()},
                              {"store", "memory"}});
  const bool ok = loop.run();
  g_loop = nullptr;
  transport->close();
  swpk::log::info("shutdown", {{"clean", ok ? "true" : "false"}});
  return ok ? 0 : 1;
}
