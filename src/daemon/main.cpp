#include "swpasskey/log/log.hpp"

#include <cstdio>
#include <cstring>
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
    "This is a software authenticator. Hardware engines (TPM / Secure Enclave)\n"
    "protect private scalars from extraction, not from same-uid use. The\n"
    "Approve prompt is daemon UX, not on-chip user presence.\n";

#ifndef SWPASSKEY_VERSION
#define SWPASSKEY_VERSION "0.1.0-dev"
#endif

void print_version() {
  std::printf("swpasskeyd %s\n", SWPASSKEY_VERSION);
}

}  // namespace

int main(int argc, char** argv) {
  swpk::log::set_level_from_env();

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
    if (arg.starts_with("--key-backend=") || arg == "--store" ||
        arg.starts_with("--store=") || arg == "--testing") {
      // Parsed in later PRs. Accept so `--help`/`--version` stay the only
      // required v1.0 flags and unknown-option tests can wait.
      if (arg == "--store") {
        if (i + 1 >= argc) {
          std::fputs("swpasskeyd: --store requires a path\n", stderr);
          return 2;
        }
        ++i;
      }
      continue;
    }
    std::fprintf(stderr, "swpasskeyd: unknown option '%s'\n", argv[i]);
    return 2;
  }

  print_version();
  swpk::log::info("startup", {{"event_detail", "no-hid-yet"},
                              {"version", SWPASSKEY_VERSION}});
  return 0;
}
