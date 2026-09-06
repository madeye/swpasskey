# swpasskey — implementation status

Last updated: 2026-09-06.

Living tracker. The spec is [`DESIGN.md`](DESIGN.md). Do not treat this file as a protocol reference.

## Snapshot

| | |
| --- | --- |
| **Phase** | PR3 complete. Next is PR4 (makeCredential / getAssertion). |
| **Current branch** | `feature/pr3-hid-getinfo` stacked on `docs/plan-and-status` |
| **`main`** | Still unborn — no commits. Never commit to `main`. |
| **Tests** | 46/46 passing locally (`cmake --preset debug && ctest --preset debug`) |
| **Hard v1 gate** | Code complete; **not yet run on a real Linux box** (see "Verification gaps") |
| **HID device** | Linux: UHID transport implemented. macOS: `IOHIDUserDeviceCreateWithProperties` returns NULL without the entitlement (K26, expected) |

## Branch stack

```
(unborn main)
  └── feature/pr1-cmake-skeleton     3154504  PR1
        └── feature/pr2-hid-cbor-crypto  e1fe6c1  PR2
              └── docs/plan-and-status   e56b0d8  docs
                    └── feature/pr3-hid-getinfo     PR3
```

## PR board

| PR | Title | Status | Branch / commit |
| --- | --- | --- | --- |
| 1 | CMake skeleton, Catch2, logger, README threat model | **done** | `feature/pr1-cmake-skeleton` `3154504` |
| 2 | CTAPHID framer, canonical CBOR, OpenSSL 3, `SoftwareKeyBackend` | **done** | `feature/pr2-hid-cbor-crypto` `e1fe6c1` |
| 3 | UHID + IOHIDUserDevice, two-thread loop, `getInfo`, macOS `.app` spike | **done** (macOS spike blocked on entitlement) | `feature/pr3-hid-getinfo` |
| 4 | makeCredential / getAssertion, packed self-attest, stdin UP | **next** | — |
| 5 | AES-256-GCM store, Keychain/libsecret DEK, flock | pending | — |
| 6 | TPM2 ESAPI signing + seal | pending | — |
| 7 | Secure Enclave signing | pending | — |
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

## What does not work yet

- No CTAP make / get (PR4) — the device enumerates and answers `getInfo` only
- Store is in-memory only (PR5 adds the AES-GCM file + keychain DEK)
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
| `tests/get_info_golden_test.cpp` vector "accepted by python-fido2 / libfido2" | Golden hex generated by `fido2.cbor.encode` and parsed back with `fido2.ctap2.Info`; libfido2 check pending the Linux run | Same canonical rule (keys sorted by encoded bytes ⇒ shorter text keys first) |

## Next up (PR4)

1. `make_credential.cpp` / `get_assertion.cpp` / `auth_data.cpp` against `KeyBackend` (software).
2. Packed self-attestation with **text** keys in `attStmt`; golden hex.
3. excludeList after UP; Deny + hit → `0x19`; only HID CANCEL → `0x2D`.
4. Pre-flight `up=false` still signs, no counter bump. Option-byte policy per DESIGN.md.
5. `getNextAssertion` state (30 s).

## Verify

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
./build/debug/swpasskeyd --version
```

On Apple Silicon, CMake picks Homebrew `openssl@3` automatically. Override with `-DOPENSSL_ROOT_DIR=...` if needed.
