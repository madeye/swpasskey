# swpasskey — implementation status

Last updated: 2026-09-06.

Living tracker. The spec is [`DESIGN.md`](DESIGN.md). Do not treat this file as a protocol reference.

## Snapshot

| | |
| --- | --- |
| **Phase** | PR7 (Secure Enclave) complete. Next is PR6 (TPM2). |
| **Current branch** | `feature/pr7-se` stacked on `feature/pr5-store` (PR7 landed before PR6; they are independent) |
| **`main`** | Still unborn — no commits. Never commit to `main`. |
| **Tests** | 70/70 Catch2 + python-fido2 e2e (`tests/e2e/pyfido2_e2e.py`) passing locally |
| **Hard v1 gate** | Code complete; **not yet run on a real Linux box** (see "Verification gaps") |
| **HID device** | Linux: UHID transport implemented. macOS: `IOHIDUserDeviceCreateWithProperties` returns NULL without the entitlement (K26, expected) |

## Branch stack

```
(unborn main)
  └── feature/pr1-cmake-skeleton     3154504  PR1
        └── feature/pr2-hid-cbor-crypto  e1fe6c1  PR2
              └── docs/plan-and-status   e56b0d8  docs
                    └── feature/pr3-hid-getinfo   cb70a07  PR3
                          └── feature/pr4-make-get    dc1e9f5  PR4
                                └── feature/pr5-store     eb944e2  PR5
                                      └── feature/pr7-se              PR7
```

## PR board

| PR | Title | Status | Branch / commit |
| --- | --- | --- | --- |
| 1 | CMake skeleton, Catch2, logger, README threat model | **done** | `feature/pr1-cmake-skeleton` `3154504` |
| 2 | CTAPHID framer, canonical CBOR, OpenSSL 3, `SoftwareKeyBackend` | **done** | `feature/pr2-hid-cbor-crypto` `e1fe6c1` |
| 3 | UHID + IOHIDUserDevice, two-thread loop, `getInfo`, macOS `.app` spike | **done** (macOS spike blocked on entitlement) | `feature/pr3-hid-getinfo` |
| 4 | makeCredential / getAssertion, packed self-attest, stdin UP | **done** | `feature/pr4-make-get` |
| 5 | AES-256-GCM store, Keychain/libsecret DEK, flock | **done** | `feature/pr5-store` |
| 6 | TPM2 ESAPI signing + seal | **next** | — |
| 7 | Secure Enclave signing | **done** (code; runtime needs the signed `.app`) | `feature/pr7-se` |
| 8 | Desktop notifications for UP | pending | — |
| 9 | PIN protocol 2 (`FIDO_2_0`) | pending | — |
| 10 | hmac-secret dual credRandom (`FIDO_2_1`) | pending | — |
| 11 | CTAP1/U2F (optional) | pending | — |
| 12 | `swpasskeyctl` list/delete/reset/stats | pending | — |
| 13 | systemd --user / launchd (optional) | pending | — |

v1 done = PR1–PR7 + PR9 + PR12. Linux Chrome + `libfido2` is the release gate (K26).

## What works today

- C++23 CMake 3.28 / Ninja presets (`debug`, `release`, `asan`, `ci`)
- `swpasskeyd --help` / `--version`; JSON-line logger on stderr (`SWPASSKEY_LOG`)
- CTAPHID INIT/CONT framing: ChannelBusy, SEQ gaps, BCNT limit, cancel, CID 0
- Canonical CBOR (definite lengths, shortest ints, map keys sorted by **encoded** bytes)
- OpenSSL 3: SHA-256, AES-256-GCM, AES-256-CBC (no padding), HKDF, HMAC, low-S ECDSA DER
- `SoftwareKeyBackend`: generate ES256, `sign_der`, export scalar, reload from scalar+pub
- `probe_key_backend("software")`; `"tpm"` / `"se"` return null until PR6/PR7
- `hid::Transport` with `UhidTransport` (Linux, `/dev/uhid` → hidraw) and `IokitTransport` (macOS, `IOHIDUserDevice` block API + serial dispatch queue → blocking `read`)
- `ctap::HidDevice`: CID allocation (CSPRNG, max 4, LRU reap), INIT / PING / WINK / CANCEL / ERROR, broadcast INIT mid-assembly, 500 ms inter-packet timeout
- `daemon::Loop`: HID I/O thread + single worker, in-flight slot, keepalive `PROCESSING` / `UPNEEDED` every 100 ms, CANCEL → `CTAP2_ERR_KEEPALIVE_CANCEL`, `CHANNEL_BUSY` for a second transaction
- `authenticatorGetInfo` PR3 snapshot (`FIDO_2_0`, key 20 remaining slots); golden bytes cross-checked with python-fido2
- Serial sidecar (`serial`, 0600, 16 hex), `flock` instance lock, XDG / Application Support paths
- `swpasskeyd` runs the real loop: `--key-backend`, `--store`, `--testing`, SIGINT/SIGTERM clean shutdown
- Packaging: `packaging/linux/udev/90-swpasskey.rules`, macOS entitlements (debug/release), `Info.plist`, `make_app.sh`
- `makeCredential`: ES256 resident keys, packed **self**-attestation (text-key `attStmt`), option-byte policy (`up=false`→0x2C, `rk=false`→0x2B, `uv=true`→0x2C, `credProtect>1`→0x4B), excludeList after UP (Deny/Timeout still 0x19), `KEY_STORE_FULL` at 100, dual 64-byte credRandom wrapped per credential
- `getAssertion` / `getNextAssertion`: discoverable + allowList, MRU ordering, `user.id`-only when UV=0, pre-flight `up=false` signs without bumping the counter, persist-before-send, 30 s next-assertion state, mixed-backend `load()` dispatch on the row's `backend` (HW rows fail closed when the probed backend differs)
- `authenticatorReset`: UP required; `KeyBackend::destroy` per row
- `credentials.bin` v1 envelope (`SWPK`, version, install_id, GCM nonce, AAD = 24-byte header), canonical-CBOR plaintext, tmp + fsync + rename, refuse bad magic / unknown version / truncation / tamper; DEK in macOS Keychain (login keychain, service `io.github.swpasskey`, account `dek`) or libsecret (`io.github.swpasskey.dek`, `install_id`), with the 0600 `credentials.bin.dek` fallback and a loud warning; `--dek-file` forces the file
- Factory reset zero-overwrites the file, rotates the DEK, writes a fresh store; serial sidecar imported into the store
- `SecureEnclaveKeyBackend`: `SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave`, `kSecAccessControlPrivateKeyUsage` only, `ECDSASignatureMessageX962SHA256` → low-S DER, handle = application tag, `wrap_secret` = data-protection generic-password item; try-create probe with OSStatus in the startup log
- `probe_key_backend(ProbeOptions)`: `software|se|tpm|auto`, hard errors for `se` on Linux / `tpm` when not built / unavailable; `auto` falls back to software with `key_backend_fallback`
- Dev transport `SWPASSKEY_HID_SOCKET=PATH`: CTAPHID over a Unix socket so python-fido2 can drive the real loop (`tests/e2e/pyfido2_e2e.py`): INIT, PING across CONT packets, getInfo, make/get, `PackedAttestation.verify` → SELF, reset

## What does not work yet

- Secure Enclave from the unsigned CLI: the key is generated inside the SE but `SecKeyCreateRandomKey` with `kSecAttrIsPermanent` returns **-34018 (errSecMissingEntitlement)** when adding it to the data-protection keychain, so `auto` logs `key_backend_fallback` and uses software. The public C API refuses `SecKeyCopyExternalRepresentation` on SE keys ("export not implemented"), so there is no keychain-free persistence path; the signed `.app` with `keychain-access-groups` is required (R11), as designed
- macOS Keychain DEK path is compiled but was not exercised interactively (an unsigned CLI's login-keychain item prompts per code signature); the file fallback is what the e2e runs used (`--dek-file`)
- libsecret path is compiled only when `pkg-config libsecret-1` is found (`SWPASSKEY_LIBSECRET`); not yet built on a Linux box
- No PIN, hmac-secret, U2F, TPM, or Secure Enclave
- User presence is stdin/tty only (PR8 adds notifications)
- macOS HID needs a paid-team profile carrying `com.apple.developer.hid.virtual.device`; without it the daemon logs `iohid_create_failed` and exits 1
- CI workflow exists but has not been run on GitHub (`main` has no remote history)

## Verification gaps (honest)

- The Linux gate (`fido2-token -L` / `-I` against a real `/dev/uhid`) has **not been executed** yet. Development happened on macOS; the local Docker VM's disk was full, so no Linux container could be provisioned. The Linux TUs were syntax-checked with GCC 13 `-Werror` in a container. Run `tests/itest/libfido2_itest.cpp` (`cmake --preset ci`) on a Linux box with `uhid` loaded.
- The macOS `.app` spike is blocked on Apple granting the HID virtual-device entitlement to the team profile (Open Question 3 / R1).

## Deviations from DESIGN.md (accepted)

| Design said | What shipped | Why |
| --- | --- | --- |
| FetchContent **tinycbor** | In-tree CTAP2 subset encoder/decoder (`src/cbor/cbor.cpp`) | Canonical sort and definite-length rules are small; avoids a C dep under `-Werror` |
| `src/crypto/probe.cpp` | `probe_key_backend` in `software_key_backend.cpp` | Software-only probe is a few lines; split out when TPM/SE land |
| `EVP_PKEY_fromdata` for software reload | `EC_KEY_set_private_key` + `EVP_PKEY_assign_EC_KEY` (`-Wno-deprecated-declarations` on that file) | OpenSSL 3 `fromdata` with priv+pub segfaulted in tests; reload is covered by Catch2 |
| `Transport::read()` blocking, no argument | `read(std::chrono::milliseconds timeout)` → `Result<optional<Report>>` | The HID thread must wake every 100 ms for keepalives and the 500 ms inter-packet timer without a second writer thread |
| `IOHIDUserDeviceCreate` + `RegisterSetReportCallback` | `IOHIDUserDeviceCreateWithProperties` + `RegisterSetReportBlock` / `SetDispatchQueue` / `Activate` | The callback API is gone from the current SDK header (`IOKit/hidsystem/IOHIDUserDevice.h`); the block API is the only one shipped |
| `getInfo` answered without touching the worker | All CBOR goes through the worker; the first keepalive fires 100 ms after dispatch, so `getInfo` still produces zero keepalives | One dispatch path; `tests/keepalive_loop_test.cpp` pins "zero keepalives for getInfo" |
| `Authenticator` ctor introduced in PR4 with `MemoryStore` | `store::CredentialStore` (single class, `open_memory()` now, `open_with(plaintext, Persister)` for PR5) and `ui::Presence` land in PR3 | Avoids rewriting the public ctor in PR4/PR5; the loop test needs a `Presence` shape anyway |
| UP timeout → `ACTION_TIMEOUT` (0x3A) in the makeCredential diagram | `USER_ACTION_TIMEOUT` (0x2F) for make/get/reset | CTAP 2.1 §6.1.2/§6.2.2 name 0x2F for a UP timeout; 0x3A is the generic action timeout. Chrome/libfido2 treat both as timeout |
| getAssertion with zero eligible credentials prompts UP first (CTAP 2.1 privacy note) | Immediate `NO_CREDENTIALS`, as the design's step 2 says | Matches the design; revisit if an RP-enumeration concern is raised |
| `tests/packed_self_attest_golden_test.cpp` pins a full response | Pins authData + the two-layer map with a fixed placeholder signature (ECDSA is randomised); the live response shape is asserted byte-by-byte and python-fido2's `PackedAttestation.verify` runs in the e2e script | A byte-exact golden of a real signature is impossible without a deterministic nonce |
| `flock` on `credentials.bin` itself | `flock` on `credentials.bin.lock` (never renamed over) | tmp+rename replaces the inode, so a lock on the data file would silently stop being exclusive after the first flush |
| macOS DEK in the data-protection keychain with `kSecAttrAccessGroup` | Login keychain item (`kSecClassGenericPassword`, no access group) until the signed `.app` exists; `install_id` kept in `kSecAttrComment` | Access groups need the `keychain-access-groups` entitlement; an unbundled CLI cannot use them |
| No socket transport in the design | `make_socket_transport` (env `SWPASSKEY_HID_SOCKET`) | Lets the real loop be driven by python-fido2 on a machine without UHID / the macOS entitlement. Not a HID device; logged as a warning at startup |
| `tests/get_info_golden_test.cpp` vector "accepted by python-fido2 / libfido2" | Golden hex generated by `fido2.cbor.encode` and parsed back with `fido2.ctap2.Info`; libfido2 check pending the Linux run | Same canonical rule (keys sorted by encoded bytes ⇒ shorter text keys first) |

## Next up (PR6 / PR7)

1. `tpm2_key_backend.cpp` (frozen primary template, wrapped P-256 children, seal without `SENSITIVEDATAORIGIN`), `cmake/FindTss2.cmake`, golden template test without a TPM.
2. `se_key_backend.mm` (`SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave`, `ECDSASignatureMessageX962SHA256`), Keychain generic-password `wrap_secret`.
3. `src/crypto/probe.cpp` with the auto order; hard errors for `--key-backend=tpm|se` when not built / wrong OS.

## Verify

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
./build/debug/swpasskeyd --version

# End to end with python-fido2 (no HID device needed):
python3 -m venv .venv && .venv/bin/pip install fido2
SWPASSKEY_HID_SOCKET=/tmp/swpk.sock ./build/debug/swpasskeyd --testing --key-backend=software --store /tmp/swpk/credentials.bin &
.venv/bin/python tests/e2e/pyfido2_e2e.py /tmp/swpk.sock
```

On Apple Silicon, CMake picks Homebrew `openssl@3` automatically. Override with `-DOPENSSL_ROOT_DIR=...` if needed.
