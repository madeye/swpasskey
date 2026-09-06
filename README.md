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

**PR1–PR5 are implemented** on stacked feature branches. `swpasskeyd` creates the
virtual HID device (Linux UHID; macOS `IOHIDUserDevice` when the entitlement is
present), runs the two-thread CTAPHID loop with keepalives, and implements
`getInfo`, discoverable ES256 `makeCredential` / `getAssertion` /
`getNextAssertion` with packed self-attestation, `reset`, and an AES-256-GCM
credential store whose DEK lives in the OS keychain. Next: TPM 2.0 and Secure
Enclave key backends.

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

## Run (Linux)

```bash
sudo modprobe uhid
sudo cp packaging/linux/udev/90-swpasskey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG plugdev $USER   # re-login
./build/debug/swpasskeyd --key-backend=software
# other terminal
fido2-token -L                   # vendor=0x1209 product=0xf1d0
fido2-token -I /dev/hidrawN
```

User presence is a `y/N` prompt on the daemon's terminal until desktop
notifications land (PR8). The credential store is
`$XDG_DATA_HOME/swpasskey/credentials.bin` (macOS: `~/Library/Application
Support/swpasskey/`); its key is kept in libsecret / the macOS Keychain, or in
`credentials.bin.dek` (0600) with `--dek-file` or when no keychain is available. `--testing` (or `SWPASSKEY_TESTING=1`) auto-approves
and is only available in Debug builds.

## Run (macOS)

`IOHIDUserDevice` requires the restricted entitlement
`com.apple.developer.hid.virtual.device`, which only a paid-team provisioning
profile can grant. Build the bundle with `packaging/macos/make_app.sh` and a
real signing identity; ad-hoc `codesign --sign -` is not supported. Without the
profile the daemon logs `iohid_create_failed` and exits (K26: Linux is the v1
gate).

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
