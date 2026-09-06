# swpasskey — implementation status

Last updated: 2026-09-06.

Living tracker. The spec is [`DESIGN.md`](DESIGN.md). Do not treat this file as a protocol reference.

## Snapshot

| | |
| --- | --- |
| **Phase** | PR2 complete. Next is PR3 (virtual HID + `getInfo`). |
| **Current branch** | `docs/plan-and-status` (docs) stacked on `feature/pr2-hid-cbor-crypto` |
| **`main`** | Still unborn — no commits. Never commit to `main`. |
| **Tests** | 25/25 passing locally (`cmake --preset debug && ctest --preset debug`) |
| **Hard v1 gate** | Not yet: `fido2-token -L` needs PR3 |
| **HID device** | Not enumerated. Daemon still `--help` / `--version` / startup log then exit |

## Branch stack

```
(unborn main)
  └── feature/pr1-cmake-skeleton     3154504  PR1
        └── feature/pr2-hid-cbor-crypto  e1fe6c1  PR2
              └── docs/plan-and-status            this docs update
```

## PR board

| PR | Title | Status | Branch / commit |
| --- | --- | --- | --- |
| 1 | CMake skeleton, Catch2, logger, README threat model | **done** | `feature/pr1-cmake-skeleton` `3154504` |
| 2 | CTAPHID framer, canonical CBOR, OpenSSL 3, `SoftwareKeyBackend` | **done** | `feature/pr2-hid-cbor-crypto` `e1fe6c1` |
| 3 | UHID + IOHIDUserDevice, two-thread loop, `getInfo`, macOS `.app` spike | **next** | — |
| 4 | makeCredential / getAssertion, packed self-attest, stdin UP | pending | — |
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

## What does not work yet

- No UHID / IOHIDUserDevice — browsers and `fido2-token` cannot see a device
- No CTAP `getInfo` / make / get
- No on-disk store, PIN, hmac-secret, U2F, TPM, or Secure Enclave
- No user-presence UI
- CI workflow exists but has not been run on GitHub (`main` has no remote history)

## Deviations from DESIGN.md (accepted)

| Design said | What shipped | Why |
| --- | --- | --- |
| FetchContent **tinycbor** | In-tree CTAP2 subset encoder/decoder (`src/cbor/cbor.cpp`) | Canonical sort and definite-length rules are small; avoids a C dep under `-Werror` |
| `src/crypto/probe.cpp` | `probe_key_backend` in `software_key_backend.cpp` | Software-only probe is a few lines; split out when TPM/SE land |
| `EVP_PKEY_fromdata` for software reload | `EC_KEY_set_private_key` + `EVP_PKEY_assign_EC_KEY` (`-Wno-deprecated-declarations` on that file) | OpenSSL 3 `fromdata` with priv+pub segfaulted in tests; reload is covered by Catch2 |

## Next up (PR3)

1. `hid::Transport`: Linux `UhidTransport`, macOS `IokitTransport` (callback → blocking `read` on a dedicated queue).
2. HID I/O thread ≠ authenticator worker; keepalive `PROCESSING` / `UPNEEDED`; CANCEL.
3. `authenticatorGetInfo` snapshot: `FIDO_2_0` only, remaining slots at key **20**.
4. Linux udev (UHID + hidraw only). Serial sidecar + instance lock.
5. macOS: tiny `.app` + debug/release entitlements. **Not** `codesign --sign -`.
6. Gate: `fido2-token -L` / `-I` on Linux. macOS Chrome is best-effort (K26).

## Verify

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
./build/debug/swpasskeyd --version
```

On Apple Silicon, CMake picks Homebrew `openssl@3` automatically. Override with `-DOPENSSL_ROOT_DIR=...` if needed.
