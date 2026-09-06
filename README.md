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

**v1 code complete (PR1–PR13)** on stacked feature branches; see
[`STATUS.md`](STATUS.md) for the board, verification gaps and accepted
deviations from the design. What `swpasskeyd` does today:

- enumerates as a FIDO HID device (Linux UHID; macOS `IOHIDUserDevice` once the
  `.app` is signed with the HID entitlement) and runs the two-thread CTAPHID
  loop with keepalives and cancel;
- CTAP 2.1 subset: `getInfo`, discoverable ES256 `makeCredential` /
  `getAssertion` / `getNextAssertion` with packed self-attestation,
  `clientPIN` protocol 2, `hmac-secret` (dual credRandom), `reset`; CTAP1/U2F
  over `CTAPHID_MSG`;
- credential keys in the TPM 2.0 (Linux) or Secure Enclave (macOS, signed
  `.app` only) with OpenSSL P-256 as the fallback;
- AES-256-GCM credential store whose DEK lives in libsecret / the macOS
  Keychain (0600 file fallback);
- user presence via libnotify (Linux), an NSAlert (macOS) or a `y/N` prompt on
  the daemon's terminal;
- `swpasskeyctl list | delete | reset | set-pin | stats` over a 0600 Unix socket.

Verified on Linux against a real `/dev/uhid` device with libfido2
(`fido2-token`, `fido2-cred`, `fido2-assert`) and the python-fido2 suite;
Chrome has not been exercised yet. 110 unit tests, a swtpm integration test
and the python-fido2 end-to-end run back the rest.

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

Presets: `debug`, `release`, `asan`, `ci`. Optional dependencies are detected
with pkg-config and never required: `tss2-esys`/`tss2-tctildr`/`tss2-mu`/
`tss2-rc` (TPM backend, `SWPASSKEY_TPM`), `libsecret-1` (DEK storage),
`libnotify` (presence). `SWPASSKEY_ENABLE_U2F=OFF` disables CTAP1.

## Run (Linux)

```bash
sudo modprobe uhid
sudo cp packaging/linux/udev/90-swpasskey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG plugdev $USER   # re-login
./build/debug/swpasskeyd --key-backend=auto     # tpm2 if /dev/tpmrm0 works, else software
# other terminal
fido2-token -L                   # vendor=0x1209 product=0xf1d0
fido2-token -I /dev/hidrawN      # FIDO_2_1 FIDO_2_0 U2F_V2, aaguid 6fb1dfdd-...
./build/debug/swpasskeyctl stats # key_backend=tpm2|software
```

User presence: libnotify Approve/Deny when a notification daemon with actions
is running, otherwise a `y/N` prompt on the daemon's terminal
(`SWPASSKEY_PRESENCE=stdin|notify|auto`). `--testing` / `SWPASSKEY_TESTING=1`
auto-approves and exists only in Debug builds. The store is
`$XDG_DATA_HOME/swpasskey/credentials.bin` (macOS: `~/Library/Application
Support/swpasskey/`); its key is kept in libsecret / the macOS Keychain, or in
`credentials.bin.dek` (0600) with `--dek-file` or when no keychain is available.
For the TPM add yourself to `tss` (distro udev rules; we ship none for the TPM).
A `systemd --user` unit is in `packaging/linux/systemd/`.

## Try it without a HID device

```bash
SWPASSKEY_HID_SOCKET=/tmp/swpk.sock ./build/debug/swpasskeyd --testing --dek-file \
    --key-backend=software --store /tmp/swpk/credentials.bin &
python3 -m venv .venv && .venv/bin/pip install fido2
.venv/bin/python tests/e2e/pyfido2_e2e.py /tmp/swpk.sock   # full CTAP2/PIN/hmac/U2F run
``` `--testing` (or `SWPASSKEY_TESTING=1`) auto-approves
and is only available in Debug builds.

## Run (macOS)

`IOHIDUserDevice` requires the restricted entitlement
`com.apple.developer.hid.virtual.device`, and Secure Enclave key persistence
requires `keychain-access-groups`; only a paid-team provisioning profile can
grant them. Build the bundle with `packaging/macos/make_app.sh` and a real
signing identity; ad-hoc `codesign --sign -` is not supported. Without the
profile the daemon logs `iohid_create_failed` and exits, and `--key-backend=auto`
falls back to software keys (K26: Linux is the v1 gate). A LaunchAgent plist
is in `packaging/macos/`. Presence is an NSAlert (`SWPASSKEY_PRESENCE=alert`).

## Threat model (short)

| Attacker | Residual |
| --- | --- |
| Remote RP | Standard WebAuthn origin binding |
| Same-uid malware | Can **use** HW keys (TPM/SE sign) and **extract** software keys |
| Disk theft without TPM/SE | HW creds inert; software creds depend on the OS keychain DEK |

User presence is required on the HID/CTAP path. It is **not** enforced by the
TPM object policy or the Secure Enclave ACL in v1.

## License

[MIT](LICENSE) — Copyright (c) 2026 Max Lv.
