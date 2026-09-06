#include "swpasskey/constants.hpp"
#include "swpasskey/crypto/key_backend.hpp"
#include "swpasskey/crypto/provider.hpp"
#include "swpasskey/ctap/authenticator.hpp"
#include "swpasskey/ctl/server.hpp"
#include "swpasskey/daemon/loop.hpp"
#include "swpasskey/daemon/paths.hpp"
#include "swpasskey/hid/transport.hpp"
#include "swpasskey/log/log.hpp"
#include "swpasskey/store/credential.hpp"
#include "swpasskey/store/file_store.hpp"
#include "swpasskey/store/keychain.hpp"
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
    "  --dek-file                     Keep the store DEK in credentials.bin.dek\n"
    "                                 (0600) instead of the OS keychain\n"
    "  --ctl-socket PATH              Control socket for swpasskeyctl\n"
    "\n"
    "Env: SWPASSKEY_LOG=error|warn|info|debug, SWPASSKEY_TESTING=1,\n"
    "     SWPASSKEY_TPM_UNSAFE_NOTPMRM=1, SWPASSKEY_TPM_TCTI=<tcti> (default device:/dev/tpmrm0),\n"
    "     SWPASSKEY_HID_SOCKET=PATH (dev: CTAPHID over a Unix socket, no HID device)\n"
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
  bool dek_file{false};
  std::filesystem::path ctl_socket;
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
    if (arg == "--dek-file") {
      opt.dek_file = true;
      continue;
    }
    if (arg == "--ctl-socket" && i + 1 < argc) {
      opt.ctl_socket = argv[++i];
      continue;
    }
    if (arg.starts_with("--ctl-socket=")) {
      opt.ctl_socket = std::string(arg.substr(std::strlen("--ctl-socket=")));
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

  auto serial = swpk::daemon::load_or_create_serial(data_dir / "serial");
  if (!serial) {
    return 1;
  }

  swpk::crypto::Provider crypto;

  // DEK: OS keychain with a 0600-file fallback (K12). The store takes the
  // single-instance flock (credentials.bin.lock).
  auto file_kc = swpk::store::make_file_keychain(opt.store.string() + ".dek");
  std::unique_ptr<swpk::store::Keychain> keychain =
      opt.dek_file ? std::move(file_kc)
                   : swpk::store::make_fallback_keychain(swpk::store::make_os_keychain(),
                                                         std::move(file_kc));
  auto store_r = swpk::store::open_file_store(opt.store, crypto, *keychain);
  if (!store_r) {
    std::fputs("swpasskeyd: cannot open the credential store (already running, or see log)\n",
               stderr);
    return 1;
  }
  auto& store = *store_r;
  if (!store->set_serial(*serial)) {
    return 1;
  }

  // Key backend probe (after the store: the TPM primary needs the install seed).
  swpk::crypto::ProbeOptions popt;
  popt.pref = opt.key_backend;
  popt.tpm_params = [&]() -> swpk::Result<swpk::crypto::Tpm2Params> {
    auto t = store->tpm_state_or_create(crypto);
    if (!t) {
      return std::unexpected(t.error());
    }
    return swpk::crypto::Tpm2Params{t->srk_unique_seed, t->object_auth};
  };
  if (const char* t = std::getenv("SWPASSKEY_TPM_TCTI"); t != nullptr && *t != 0) {
    popt.tpm_tcti = t;
  }
  if (const char* u = std::getenv("SWPASSKEY_TPM_UNSAFE_NOTPMRM"); u != nullptr && std::strcmp(u, "1") == 0) {
    popt.tpm_allow_notpmrm = true;
  }
  std::string probe_detail;
  auto primary = swpk::crypto::probe_key_backend(popt, probe_detail);
  if (!primary) {
    std::fprintf(stderr, "swpasskeyd: key backend '%s' unavailable (%s)\n", opt.key_backend.c_str(),
                 probe_detail.c_str());
    return 1;
  }
  swpk::crypto::SoftwareKeyBackend software;
  swpk::crypto::KeyBackend& software_ref =
      primary->kind() == swpk::crypto::BackendKind::Software ? *primary : software;

  swpk::ui::PresenceConfig pcfg;
  pcfg.testing = opt.testing;
  auto presence = swpk::ui::make_presence(pcfg);
  if (!presence) {
    std::fputs("swpasskeyd: --testing is not available in this build\n", stderr);
    return 1;
  }

  swpk::ctap::AuthenticatorConfig acfg;
#if defined(SWPASSKEY_ENABLE_U2F) && SWPASSKEY_ENABLE_U2F
  acfg.u2f_enabled = true;  // HID caps become CBOR|WINK; getInfo lists U2F_V2
#endif
  swpk::ctap::Authenticator auth(acfg, crypto, *primary, software_ref, *store, *presence);

  swpk::hid::DeviceConfig dcfg;
  dcfg.serial = *serial;
  std::unique_ptr<swpk::hid::Transport> transport;
  if (const char* sock = std::getenv("SWPASSKEY_HID_SOCKET"); sock != nullptr && *sock != 0) {
    transport = swpk::hid::make_socket_transport(sock);  // development only
  } else {
    transport = swpk::hid::make_transport(dcfg);
  }
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

  // Control socket (swpasskeyctl).
  if (opt.ctl_socket.empty()) {
    if (const char* e = std::getenv("SWPASSKEY_CTL_SOCKET"); e != nullptr && *e != 0) {
      opt.ctl_socket = e;
    } else {
      opt.ctl_socket = swpk::ctl::default_socket_path();
    }
  }
  swpk::ctl::ServerDeps deps;
  deps.auth = &auth;
  deps.store = store.get();
  deps.loop = &loop;
  deps.key_backend = auth.primary_backend_name();
  deps.probe_detail = probe_detail;
  deps.quit = [&loop] { loop.stop(); };
  swpk::ctl::UnixServer ctl(opt.ctl_socket, std::move(deps));
  if (!ctl.start()) {
    std::fputs("swpasskeyd: cannot create the control socket (see log)\n", stderr);
    return 1;
  }
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  std::signal(SIGPIPE, SIG_IGN);

  swpk::log::info("startup", {{"version", SWPASSKEY_VERSION},
                              {"key_backend", auth.primary_backend_name()},
                              {"probe", probe_detail},
                              {"transport", transport->describe()},
                              {"serial", *serial},
                              {"presence", presence->name()},
                              {"store", opt.store.string()},
                              {"keychain", keychain->name()}});
  const bool ok = loop.run();
  g_loop = nullptr;
  ctl.stop();
  transport->close();
  swpk::log::info("shutdown", {{"clean", ok ? "true" : "false"}});
  return ok ? 0 : 1;
}
