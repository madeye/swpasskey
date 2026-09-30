# swpasskey — implementation status

Last updated: 2026-09-21.

Living tracker. The spec is [`DESIGN.md`](DESIGN.md). Do not treat this file as a protocol reference.

## Snapshot

| | |
| --- | --- |
| **Phase** | **v1 code complete: PR1–PR13 implemented; the hard gate (Chrome + libfido2 on a real OS HID device) passed on macOS** (2026-09-21, signed `.app` with the Apple-granted HID entitlement, Secure Enclave keys); Linux libfido2 half passed on real UHID. Remaining: Chrome on Linux, real TPM (see "Verification gaps"). |
| **Current branch** | `feature/macos-hid-entitlement` (authenticatorSelection, macOS gate results) on top of `main` |
| **`main`** | v1 merged (public repo `madeye/swpasskey`). Never commit to `main`; squash/rebase merges only. |
| **Tests** | 109/109 Catch2 (`debug`, `asan`, `ci` presets; incl. TPM golden + swtpm itest) + python-fido2 end-to-end over the socket transport (getInfo, make/get/getNext, PIN protocol 2, hmac-secret, U2F, reset) on the software and TPM backends |
| **Hard v1 gate** | **macOS: passed.** Signed `.app` → real `IOHIDUserDevice`, keys in the Secure Enclave. libfido2 1.17 (`fido2-token -I/-S/-R`, `fido2-cred -M/-V` with hmac-secret, `fido2-assert -G/-V` allowList / discoverable / hmac-secret), the full python-fido2 suite over the OS HID device, and **Chrome 153 WebAuthn** register (`transports=["usb"]`, packed attestation) + sign-in (UP flag, counter, userHandle) on a localhost RP, run both on the host (macOS 27) and in a clean macOS 26.6 Tart VM. **Linux: libfido2 half passed** on real `/dev/uhid` (Ubuntu 25.10 Lima VM); Chrome on Linux not run. `fido2-token -L` lists the device on Linux only (see gaps) |
| **HID device** | Linux UHID; macOS `IOHIDUserDevice` (signed `.app` with the granted HID entitlement); dev-only Unix-socket transport for tests |

## Branch stack

```
(unborn main)
  └── feature/pr1-cmake-skeleton     3154504  PR1
        └── feature/pr2-hid-cbor-crypto  e1fe6c1  PR2
              └── docs/plan-and-status   e56b0d8  docs
                    └── feature/pr3-hid-getinfo   cb70a07  PR3
                          └── feature/pr4-make-get    dc1e9f5  PR4
                                └── feature/pr5-store     eb944e2  PR5
                                      └── feature/pr7-se        81423c7  PR7
                                            └── feature/pr6-tpm       3ed6228  PR6
                                                  └── feature/pr9-pin       f0ab3ef  PR9
                                                        └── feature/pr10-hmac-secret  249ee8e  PR10
                                                              └── feature/pr11-u2f        ccbd0fe  PR11
                                                                    └── feature/pr12-ctl        b3b47d0  PR12
                                                                          └── feature/pr8-notify      ff786cd  PR8
                                                                                └── feature/pr13-packaging          PR13
```

Each branch is one reviewable commit; merge bottom-up. PR7 landed before PR6 and PR8 after PR12 (all independent); the numbering follows `DESIGN.md`.

## PR board

| PR | Title | Status | Branch / commit |
| --- | --- | --- | --- |
| 1 | CMake skeleton, Catch2, logger, README threat model | done | `feature/pr1-cmake-skeleton` `3154504` |
| 2 | CTAPHID framer, canonical CBOR, OpenSSL 3, `SoftwareKeyBackend` | done | `feature/pr2-hid-cbor-crypto` `e1fe6c1` |
| 3 | UHID + IOHIDUserDevice, two-thread loop, `getInfo`, macOS `.app` files | done (macOS spike blocked on the entitlement) | `feature/pr3-hid-getinfo` `cb70a07` |
| 4 | makeCredential / getAssertion, packed self-attest, stdin UP | done | `feature/pr4-make-get` `dc1e9f5` |
| 5 | AES-256-GCM store, Keychain/libsecret DEK, flock | done | `feature/pr5-store` `eb944e2` |
| 6 | TPM2 ESAPI signing + seal | done (verified against swtpm) | `feature/pr6-tpm` `3ed6228` |
| 7 | Secure Enclave signing | done (code; runtime needs the signed `.app`) | `feature/pr7-se` `81423c7` |
| 8 | Desktop notifications for UP (libnotify / NSAlert) | done (compiled + reviewed; no GUI run in this session) | `feature/pr8-notify` `ff786cd` |
| 9 | PIN protocol 2 | done | `feature/pr9-pin` `f0ab3ef` |
| 10 | hmac-secret dual credRandom → `FIDO_2_1` | done | `feature/pr10-hmac-secret` `249ee8e` |
| 11 | CTAP1/U2F over `CTAPHID_MSG` | done (`SWPASSKEY_ENABLE_U2F`, default ON) | `feature/pr11-u2f` `ccbd0fe` |
| 12 | `swpasskeyctl` list/delete/reset/set-pin/stats | done | `feature/pr12-ctl` `b3b47d0` |
| 13 | udev, systemd `--user` unit, launchd agent, `install()` | done (files; not exercised) | `feature/pr13-packaging` |

v1 done = PR1–PR7 + PR9 + PR12 — all present. Linux Chrome + `libfido2` on real UHID is the release gate (K26) and is the one thing left to run.

## What works today

- **Build:** C++23 CMake 3.28 / Ninja presets (`debug`, `release`, `asan`, `ci`), `-Wall -Wextra -Werror -Wconversion -Wshadow`, ctap core `-fno-exceptions -fno-rtti`. Optional deps auto-detected: tpm2-tss (`SWPASSKEY_TPM`), libsecret (`SWPASSKEY_LIBSECRET`), libnotify (`SWPASSKEY_LIBNOTIFY`); the build never hard-fails without them. `SWPASSKEY_ENABLE_U2F` (ON). `cmake --install` puts the binaries, udev rules and user unit in place on Linux.
- **HID:** `UhidTransport` (`/dev/uhid` → hidraw, 65-byte report-id quirk handled, `GET_REPORT` answered), `IokitTransport` (`IOHIDUserDeviceCreateWithProperties` block API, serial dispatch queue → blocking read), dev-only `SWPASSKEY_HID_SOCKET` transport. `ctap::HidDevice`: CSPRNG CIDs, max 4 with LRU reap, INIT/PING/WINK/CANCEL/ERROR, broadcast INIT mid-assembly, 500 ms inter-packet timeout. `daemon::Loop`: HID I/O thread + one worker, keepalive `PROCESSING`/`UPNEEDED` every 100 ms, CANCEL → `CTAP2_ERR_KEEPALIVE_CANCEL`, `CHANNEL_BUSY`. Caps `CBOR|WINK` (U2F on) or `CBOR|NMSG`.
- **CTAP2:** `getInfo` (`["FIDO_2_1","FIDO_2_0","U2F_V2"]`, `hmac-secret`, `clientPin`, `pinUvAuthToken`, protocols `[2]`, key 20 remaining slots; golden bytes from python-fido2 for the PR3/PR9/PR10 shapes). `makeCredential` (ES256 rk only, packed **self**-attestation with text-key `attStmt`, option-byte policy, excludeList after UP, `credProtect>1` fails closed, `KEY_STORE_FULL` at 100, dual 64-byte credRandom wrapped per credential). `getAssertion`/`getNextAssertion` (discoverable + allowList, MRU order, `user.id`-only when UV=0, `up=false` pre-flight signs without a counter bump, persist-before-send, mixed-backend dispatch, HW rows fail closed). `authenticatorReset` (UP, per-row `destroy`, DEK rotation). `clientPIN` protocol 2 (set/change/getKeyAgreement/getPinToken/…WithPermissions, retries + lockout + delay, token not one-shot, `mc` requires the token, `ga` optional). `hmac-secret` (UV-selected credRandom, one or two salts, through getNextAssertion). CTAP1/U2F register/authenticate/version with a self-signed attestation cert, check-only, don't-enforce.
- **Keys:** `SoftwareKeyBackend` (OpenSSL 3, low-S), `Tpm2KeyBackend` (frozen install-bound primary, wrapped P-256 children, `Esys_Load`+`SetAuth`+`Sign`+`Flush` per assertion, keyedhash seal without `SENSITIVEDATAORIGIN`, `/dev/tpmrm0` only unless `SWPASSKEY_TPM_UNSAFE_NOTPMRM=1`, `SWPASSKEY_TPM_TCTI` override), `SecureEnclaveKeyBackend` (`kSecAccessControlPrivateKeyUsage`, `ECDSASignatureMessageX962SHA256`, Keychain generic-password `wrap_secret`). `--key-backend=auto|se|tpm|software` with hard errors for unavailable explicit backends and a loud fallback for `auto`.
- **Store:** `credentials.bin` v1 (`SWPK`, version, install_id, GCM nonce, AAD = header), canonical CBOR plaintext, tmp+fsync+rename, `credentials.bin.lock` flock, DEK in macOS Keychain / libsecret with the 0600 `credentials.bin.dek` fallback (`--dek-file`), serial sidecar imported.
- **UP:** stdin `y/N` (tty), libnotify Approve/Deny (Linux, GLib loop thread), NSAlert on the main thread (macOS, HID loop moves to a thread), `SWPASSKEY_PRESENCE=stdin|notify|alert|auto`, `--testing` auto-allow in Debug builds only.
- **Control:** `swpasskeyctl list|delete|reset|set-pin|stats|log-level|quit` over a 0600 same-uid Unix socket (`--ctl-socket`, `SWPASSKEY_CTL_SOCKET`); stats also logged every 5 minutes.
- **Packaging:** `packaging/linux/udev/90-swpasskey.rules` (UHID + hidraw only), `packaging/linux/systemd/swpasskeyd.service` (`--user`, graphical session), `packaging/macos/` (`Info.plist`, debug/release entitlements, `make_app.sh`, LaunchAgent plist, app icon + `make_icon.swift`, bundle LaunchAgent for `SMAppService`).
- **macOS menu bar (2026-09-30):** `src/ui/menubar_macos.mm` — `NSStatusItem` (SF Symbol key) with the credential count, **Keys…** (cell-based `NSTableView` over `ui::key_rows()`, Delete with a confirmation sheet → `Authenticator::ctl_delete`), **Preferences…** (Launch at login via `SMAppService` and the plist in `Contents/Library/LaunchAgents`, log level persisted in `NSUserDefaults` `SWPKLogLevel` and applied at start, daemon facts), Quit → `loop.stop()`. Created in `main()` on the main thread right before the presence loop; `ui::key_rows`/formatting are plain C++ (`tests/keys_model_test.cpp`). Verified by UI scripting: menu, Keys list after a `fido2-cred` registration approved through the NSAlert (first time the alert path was exercised), delete, login item register/unregister (`SMAppServiceStatusNotFound` just means "never registered"; registering from that state works).

## Verification gaps (honest)

- **Linux gate, libfido2 half: done** in a Lima VM (Ubuntu 25.10, kernel 6.17, GCC 15, tpm2-tss/libsecret/libnotify all detected). `cmake --preset ci` builds clean, all 110 tests pass including the swtpm itest and `tests/itest/libfido2_itest.cpp` against real UHID; `fido2-token -L` lists `vendor=0x1209, product=0xf1d0`; `-I` prints `FIDO_2_1, FIDO_2_0, U2F_V2`, `hmac-secret`, the AAGUID, `rk`, `pin protocols: 2`; `fido2-cred -M -r -h` + `fido2-cred -V -h` (self-attestation) succeed; `fido2-assert -G/-V` succeed with allowList, discoverable (`-r`) and hmac-secret; `fido2-token -S` sets a PIN, `-R` resets; `python3 tests/e2e/pyfido2_e2e.py hid` prints ALL OK over hidraw. systemd's `fido_id` tags the device (`ID_FIDO_TOKEN=1`, `uaccess`). Found and fixed on the way: the design's udev rule (`ATTRS{idVendor}`) never matches a UHID device — it now matches `KERNELS=="0003:1209:F1D0.*"` — and GCC 15 `-Wformat-truncation` in the stats code.
- **Chrome on Linux: not run** (Chrome has been exercised on macOS instead, see below). The Linux VM is headless; the Chrome half of the gate needs a desktop session (chrome://device-log, register + sign in at a WebAuthn demo site). Everything Chrome does over CTAPHID has been exercised by python-fido2's client over the same hidraw node.
- **TPM verified against swtpm only** (tpm2-tss 4.1.3 built locally on macOS, and Ubuntu's packages in the VM), not a real `/dev/tpmrm0`; the Lima VM has no vTPM.
- **macOS HID half: done (2026-09-21).** Apple granted `com.apple.developer.hid.virtual.device` to team 32B45SMMQL; after ticking it under the App ID's "Additional Capabilities" in the developer portal, a freshly generated Developer ID profile carries the key (the public App Store Connect API cannot enable it, it has no capability type for it). `make_app.sh` keeps the entitlement, AMFI accepts the bundle, and the daemon logs `iohid_created` with `transport=IOHIDUserDevice`, `key_backend=se`. `hidutil list` shows vendor `0x1209` / product `0xf1d0`, usage page `0xF1D0`. Against that device: `fido2-token -I`, `fido2-cred -M -r -h` + `-V -h`, `fido2-assert -G/-V` (allowList, `-r`, hmac-secret), `fido2-token -S`, `-R`, and `python3 tests/e2e/pyfido2_e2e.py hid` (ALL OK, Secure Enclave rows). Caveat: **`fido2-token -L` does not list it** — libfido2's macOS backend only enumerates devices whose IOKit `Transport` property is `USB` (`is_fido()` in `hid_osx.c`, unless built with `FIDO_HID_ANY`), and IOHIDUserDevice forces `Transport=Virtual` even though the daemon passes `kIOHIDTransportKey=USB`; opening by registry path (`fido2-token -I ioreg://<entry-id>`, id from `hidutil list`) works. Chrome uses its own HID enumeration and does not filter on transport.
  - **Chrome half: passed (2026-09-21)** in a clean macOS 26.6.2 Tart VM (`ghcr.io/cirruslabs/macos-tahoe-base`, Chrome 153.0.8010.53, libfido2 1.17.0; the VM even exposes a Secure Enclave, `key_backend=se`). A localhost page (`navigator.credentials.create` with `authenticatorAttachment: cross-platform`, `residentKey: required`, `attestation: direct`; then `get` with the returned id) driven through the DevTools protocol: **register OK** (`transports=["usb"]`, 277-byte attestation object) and **assert OK** (flags `0x01`, counter 2, userHandle `user-1`). The daemon saw exactly Chrome's expected sequence: `getInfo`, `clientPIN` (key agreement + PIN token), `makeCredential`, then `getInfo`, `getAssertion`. Two Chrome behaviours worth knowing: (1) for a discoverable credential Chrome **insists on a client PIN** when the key advertises `clientPin` — with no PIN set it shows "Set up a new PIN for your security key" before touching the key, so the run set one with `fido2-token -S` first and typed it into Chrome's sheet via System Events; (2) Chrome probes `0x40` (bioEnrollment preview) after PIN setup and takes the `INVALID_COMMAND` answer in stride.
  - Found while running Chrome on the host with a YubiKey also plugged in: Chrome sends `authenticatorSelection` (0x0B) to every key that advertises `FIDO_2_1` so the user can touch the one to use; swpasskey answered `CTAP1_ERR_INVALID_COMMAND` and Chrome dropped it. 0x0B is now implemented (UP only, empty response; `tests/pin_test.cpp`), a deviation from DESIGN.md Appendix A ("not v1").
  - Earlier spike (2026-09-07), still true: `cmake --preset app` (static OpenSSL, no TPM) + `packaging/macos/make_app.sh` with the team's Developer ID identity produce a bundle that depends only on system libraries and passes `codesign --verify --strict`.
  - `com.apple.developer.hid.virtual.device` in the signature **without** a profile that grants it → SIGKILL at exec (AMFI), exactly as K26 predicted. A Developer ID profile from the portal grants `keychain-access-groups` (`TEAM.*`) and `com.apple.application-identifier` only; the HID key is not in the portal's capability list and must be requested from Apple. Until then `make_app.sh` strips it and the daemon exits with `iohid_create_failed` on a real launch.
  - **Secure Enclave works in the signed bundle:** with the HID key stripped and `SWPASSKEY_HID_SOCKET` set, `--key-backend=auto` selects `se`, `tests/e2e/pyfido2_e2e.py` prints ALL OK, and a makeCredential/getAssertion round-trip leaves a row with `backend=se` in `swpasskeyctl list`. The **macOS Keychain DEK** path was exercised too (service `com.tangzixiang.swpasskey`, account `dek`, no `--dek-file`).
  - Hardened runtime refuses Homebrew's `libcrypto.3.dylib` (different Team ID); hence `SWPASSKEY_STATIC_OPENSSL` (default ON on macOS) and the `app` preset. The entitlement plists also had `--` inside XML comments, which AMFI's plist parser rejects.
  - Installed at `/Applications/swpasskeyd.app` (with `swpasskeyctl` in `Contents/MacOS`), rebuilt 2026-09-21 with the HID entitlement. The LaunchAgent is still **not** loaded (NSAlert presence untested). Not notarized (local install only; `spctl` says "Unnotarized Developer ID").
- **libsecret / libnotify** now compile for real in the VM (`SWPASSKEY_LIBSECRET=ON`, `SWPASSKEY_LIBNOTIFY=ON`) but were not exercised at runtime: the VM has no session keyring or notification daemon, so the gate runs used `--dek-file` and `--testing`.
- **NSAlert presence** was never displayed (unattended session; the signed-bundle runs used `SWPASSKEY_PRESENCE=stdin` under a pty); compiled and reviewed only.
- CI workflow (`.github/workflows/ci.yml`) has not run on GitHub yet (`main` has no remote history). It installs tss2/libsecret/swtpm/fido2 on Ubuntu, runs the swtpm itest, and builds a no-TPM variant.

## Deviations from DESIGN.md (accepted)

| Design said | What shipped | Why |
| --- | --- | --- |
| FetchContent **tinycbor** | In-tree CTAP2 subset encoder/decoder (`src/cbor/cbor.cpp`) with `skip()` and `write_raw()` | Canonical sort and definite-length rules are small; avoids a C dep under `-Werror` |
| `EVP_PKEY_fromdata` for software reload | `EC_KEY` + `EVP_PKEY_assign_EC_KEY` (`-Wno-deprecated-declarations` on two files) | OpenSSL 3 `fromdata` with priv+pub segfaulted in tests |
| `Transport::read()` blocking, no argument | `read(std::chrono::milliseconds timeout)` → `Result<optional<Report>>` | The HID thread must wake for keepalives and the 500 ms timer without a second writer thread |
| `IOHIDUserDeviceCreate` + callbacks | `IOHIDUserDeviceCreateWithProperties` + block API + `SetDispatchQueue`/`Activate` | The callback API is not in the current SDK header |
| All CBOR through the worker; "getInfo produces no keepalives" | Same — the first keepalive fires 100 ms after dispatch; pinned by `tests/keepalive_loop_test.cpp` | One dispatch path |
| `MemoryStore` in PR4, `CredentialStore::open(path, …)` in PR5 | One `CredentialStore` (`open_memory()` / `open_with(plaintext, Persister)`) + `open_file_store()` | No ctor rewrite between PRs |
| `flock` on `credentials.bin` | `flock` on `credentials.bin.lock` | tmp+rename replaces the inode; a lock on the data file stops being exclusive |
| macOS DEK in the data-protection keychain + access group | Login-keychain item (verified from the signed `.app`) | Works without an access group; revisit if the DEK should be SE-bound |
| UP timeout → `ACTION_TIMEOUT` (0x3A) in the makeCredential diagram | `USER_ACTION_TIMEOUT` (0x2F) | CTAP 2.1 names 0x2F for a UP timeout; clients treat both as timeout |
| getAssertion with zero credentials prompts UP first | Immediate `NO_CREDENTIALS` (design step 2) | Matches the design text |
| Byte-exact packed-attestation golden | authData + map shape pinned with a placeholder signature; `PackedAttestation.verify` runs in the e2e | ECDSA is randomised |
| No socket transport | `SWPASSKEY_HID_SOCKET` dev transport | Lets python-fido2 drive the real loop without UHID / the entitlement; logged as a warning |
| `if(UNIX AND NOT APPLE)` gate on tss2 | pkg-config probe on every OS | Enables the swtpm test on macOS; `auto` on macOS still prefers SE |
| `KeyBackend::load` does `Esys_Load` | `load` only decodes the blob and checks the public point; TPM work happens in `sign_der` | One TPM load per assertion instead of two |
| `NotifyPresence` / UN notifications on macOS | libnotify on Linux; **NSAlert** on macOS (design allows it); `Presence` gained `needs_main_thread()` / `run_main_loop()` | UN actionable categories need the signed bundle |
| `probe_key_backend(pref)` | `probe_key_backend(ProbeOptions, detail)` with a TPM-params hook; store opens before the probe | The TPM primary needs the install seed generated by the store |
| U2F status for invalid P1 unspecified | `0x6A86` (INCORRECT_P1P2); store full → `0x6F00` | ISO 7816-4 |
| `authenticatorSelection` (0x0B) "not v1" (Appendix A) | Implemented: UP prompt, empty response; deny → `OPERATION_DENIED`, timeout → `USER_ACTION_TIMEOUT` | Chrome sends it to every `FIDO_2_1` key when more than one is plugged in and drops keys that reject it |
| `rk=false` → `UnsupportedOption` (0x2B) | Kept as designed (Open Question 8) | A post-implementation review noted CTAP 2.1 would rather create the discoverable credential anyway; Chrome and python-fido2 omit the key, so no known client is affected |

## Post-implementation review fixes (on top of PR13)

- **macOS Keychain DEK clobbering (fixed 2026-09-30).** The Keychain DEK item used a fixed account (`dek`) with the install_id only in the comment, so opening *any* store with the OS keychain (e.g. a test run with `--store /tmp/...` and no `--dek-file`) replaced the real store's DEK and the next open failed with `keychain_dek_install_id_mismatch` / `dek_missing`. The account is now `dek.<install_id>` (one item per store, like the libsecret schema), a legacy `dek` item is migrated on first open when its comment matches, and `delete_dek` only touches items for its own install_id. `tests/keychain_macos_test.mm` covers two stores side by side and the migration against the real login keychain.

A high-effort code review of the whole stack produced ten findings; nine were fixed in `fix: address code-review findings`: bounded CBOR `skip()` nesting (stack overflow from a hostile map value), PIN retry counter decremented and persisted **before** the compare (fail closed if the flush fails), TPM primary rebuilt after `authenticatorReset` (`KeyBackend::reinit_after_reset`), U2F rows marked `rk=false` and excluded from discoverable enumeration (and never emit an empty `user.id`), makeCredential replaces an existing credential with the same rp.id + user.id, Secure Enclave `destroy_secret` deletes the hmac-secret Keychain item, store `put`/`erase` roll back on flush failure, allowList duplicates de-duplicated, and any non-getNextAssertion command clears the pending assertion list. The tenth (`rk=false`) is the accepted deviation above.

## Verify

```bash
cmake --preset debug && cmake --build --preset debug
ctest --preset debug --output-on-failure            # 102 tests
SWPASSKEY_ITEST_TPM=1 ctest --preset debug -R tpm   # needs tpm2-tss + swtpm
cmake --preset asan && cmake --build --preset asan && ctest --preset asan

# Linux gate as executed (Ubuntu VM, user in plugdev; see packaging/linux/udev):
sudo modprobe uhid && sudo cp packaging/linux/udev/90-swpasskey.rules /etc/udev/rules.d/ && sudo udevadm control --reload-rules
./build/ci/swpasskeyd --testing --dek-file --key-backend=auto &
fido2-token -L && fido2-token -I /dev/hidrawN
python3 tests/e2e/pyfido2_e2e.py hid          # apt install python3-fido2; prints ALL OK

# End to end with python-fido2 (no HID device, no entitlement needed):
python3 -m venv .venv && .venv/bin/pip install fido2
SWPASSKEY_HID_SOCKET=/tmp/swpk.sock ./build/debug/swpasskeyd --testing --dek-file \
    --key-backend=software --store /tmp/swpk/credentials.bin --ctl-socket /tmp/swpk-ctl.sock &
.venv/bin/python tests/e2e/pyfido2_e2e.py /tmp/swpk.sock      # prints ALL OK
./build/debug/swpasskeyctl --socket /tmp/swpk-ctl.sock stats

# macOS gate as executed (signed .app with the HID entitlement, see README "Run (macOS)"):
SWPASSKEY_PRESENCE=stdin /Applications/swpasskeyd.app/Contents/MacOS/swpasskeyd --key-backend=auto   # in a terminal; answer y to the prompts
hidutil list | grep swpasskey                       # RegistryID column, e.g. 0x1002b4026
fido2-token -I ioreg://$(printf %d 0x1002b4026)     # -L does not list it (libfido2 filters Transport=USB)
python3 tests/e2e/pyfido2_e2e.py hid                # python-fido2 enumerates it; prints ALL OK
```
