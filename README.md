# swpasskey

**This is a software authenticator.** Same-uid malware cannot *copy* TPM- or
Secure Enclave-backed private keys, but it **can sign with them without the
Approve click**. The Approve prompt is daemon UX, not on-chip user presence
(not a YubiKey button). Attestation is packed **self-attestation** only: the
AAGUID `6fb1dfdd-51c0-43a0-a6f2-f74812cbf8fb` is not in the FIDO MDS. Relying
parties that require certified hardware attestation will reject this device.
Do not treat swpasskey as a hardware security key.

swpasskey is a C++23 daemon that enumerates as a **USB HID FIDO** authenticator
(usage page `0xF1D0`) on Linux (UHID) and macOS (`IOHIDUserDevice`). Unmodified
Chrome, `libfido2`, and `ssh-sk` speak CTAP2 to it.

v1 platforms: **Linux and macOS**. Windows is out. Linux Chrome + `libfido2` is
the hard release gate; macOS HID needs a signed `.app` and a restricted
entitlement and is best-effort.

Credential private keys use a hardware engine when one is available (Linux TPM
2.0, macOS Secure Enclave) with OpenSSL 3 P-256 as the fallback. See
[`DESIGN.md`](DESIGN.md) for the full design.

## Status

**PR1 and PR2 are implemented** on feature branches (`feature/pr1-cmake-skeleton` → `feature/pr2-hid-cbor-crypto`). The daemon still does not enumerate a HID device. Next is PR3: UHID / `IOHIDUserDevice` + `authenticatorGetInfo` so `fido2-token -L` can see it on Linux.

See [`STATUS.md`](STATUS.md) for the PR board, deviations, and what does not work yet.

## Build

Requires CMake ≥ 3.28, Ninja, a C++23 compiler (`std::expected`), OpenSSL 3.

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --output-on-failure
./build/debug/swpasskeyd --help
```

On macOS, CMake runs `brew --prefix openssl@3` when `OPENSSL_ROOT_DIR` is unset. Override if your OpenSSL 3 lives elsewhere:

```bash
cmake --preset debug -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

Presets: `debug`, `release`, `asan`, `ci`.

## Threat model (short)

| Attacker | Residual |
| --- | --- |
| Remote RP | Standard WebAuthn origin binding |
| Same-uid malware | Can **use** HW keys (TPM/SE sign) and **extract** software keys |
| Disk theft without TPM/SE | HW creds inert; software creds depend on the OS keychain DEK |

User presence is required on the HID/CTAP path. It is **not** enforced by the
TPM object policy or the Secure Enclave ACL in v1.

## License

All rights reserved until a license is chosen.
