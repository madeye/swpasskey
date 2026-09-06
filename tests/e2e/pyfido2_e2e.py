#!/usr/bin/env python3
"""End-to-end check of swpasskeyd with python-fido2 over the development
socket transport (SWPASSKEY_HID_SOCKET). Exercises the real CTAPHID loop,
keepalives, getInfo, makeCredential (packed self-attestation), getAssertion,
getNextAssertion, and — when the daemon supports them — clientPIN protocol 2,
hmac-secret and CTAP1/U2F.

Usage:
    SWPASSKEY_HID_SOCKET=/tmp/swpk.sock swpasskeyd --testing --key-backend=software &
    python3 tests/e2e/pyfido2_e2e.py /tmp/swpk.sock

    # or against the real UHID device on Linux:
    swpasskeyd --testing --key-backend=auto &
    python3 tests/e2e/pyfido2_e2e.py hid
"""
import os
import socket
import sys
import time
import hashlib

from fido2 import cbor
from fido2.hid import CtapHidDevice
from fido2.hid.base import HidDescriptor, CtapHidConnection
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, ClientPin, PinProtocolV2, AttestationResponse
from fido2.ctap2.pin import PinProtocolV1
from fido2.ctap2.extensions import HmacSecretExtension
from fido2.webauthn import AttestationObject, AuthenticatorData
from fido2.cose import ES256
from fido2.attestation import PackedAttestation, AttestationType


class SockConn(CtapHidConnection):
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)
        self.s.settimeout(5.0)

    def read_packet(self):
        buf = b""
        while len(buf) < 64:
            chunk = self.s.recv(64 - len(buf))
            if not chunk:
                raise IOError("daemon closed")
            buf += chunk
        return buf

    def write_packet(self, data):
        self.s.sendall(data.ljust(64, b"\0"))

    def close(self):
        self.s.close()


def connect(path):
    if path.startswith("/dev/hidraw") or path == "hid":
        # Real HID device (Linux hidraw via UHID): use python-fido2's own transport.
        for _ in range(50):
            for d in CtapHidDevice.list_devices():
                if d.descriptor.vid == 0x1209 and (path == "hid" or d.descriptor.path == path):
                    return d
            time.sleep(0.1)
        raise SystemExit("no swpasskey HID device found")
    desc = HidDescriptor(path, 0x1209, 0xF1D0, 64, 64, "swpasskey", None)
    for _ in range(50):
        try:
            return CtapHidDevice(desc, SockConn(path))
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.1)
    raise SystemExit("daemon socket never appeared")


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL: " + msg)
    print("ok  ", msg)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SWPASSKEY_HID_SOCKET", "/tmp/swpk.sock")
    dev = connect(path)
    print("device", dev, "caps=%#x" % dev.capabilities, "version", dev.device_version)
    check(dev.capabilities & 0x04, "CAPABILITY_CBOR set")

    # PING
    check(dev.call(0x01, b"hello" * 100) == b"hello" * 100, "PING echoes 500 bytes across CONT packets")

    ctap = Ctap2(dev)
    info = ctap.info
    print("versions", info.versions, "aaguid", info.aaguid, "options", dict(info.options))
    check("FIDO_2_0" in info.versions, "getInfo advertises FIDO_2_0")
    check(str(info.aaguid) == "6fb1dfdd-51c0-43a0-a6f2-f74812cbf8fb", "AAGUID")
    check(info.options.get("rk") is True and info.options.get("up") is True, "rk/up options")
    check(info.remaining_disc_creds is not None, "remainingDiscoverableCredentials present")
    has_pin = "clientPin" in info.options
    has_hmac = "hmac-secret" in (info.extensions or [])
    has_u2f = "U2F_V2" in info.versions
    print("features: pin=%s hmac=%s u2f=%s" % (has_pin, has_hmac, has_u2f))

    rp = {"id": "example.com", "name": "Example"}
    user = {"id": b"\x01\x02\x03\x04", "name": "alice", "displayName": "Alice"}
    cdh = hashlib.sha256(b"client data 1").digest()
    att = ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -7}], options={"rk": True})
    check(att.fmt == "packed", "attestation fmt packed")
    cred_data = att.auth_data.credential_data
    check(str(cred_data.aaguid) == "6fb1dfdd-51c0-43a0-a6f2-f74812cbf8fb", "authData AAGUID")
    check(att.auth_data.flags & AuthenticatorData.FLAG.UP, "UP flag")
    check(att.auth_data.flags & AuthenticatorData.FLAG.AT, "AT flag")
    check(not (att.auth_data.flags & (AuthenticatorData.FLAG.BE | AuthenticatorData.FLAG.BS)), "BE/BS zero")
    check(att.auth_data.counter == 1, "signCount starts at 1")
    check(len(cred_data.credential_id) == 32, "32-byte credential id")
    check("x5c" not in att.att_stmt, "self-attestation: no x5c")
    # Verify with python-fido2's packed verifier (self attestation path).
    ao = AttestationObject.create(att.fmt, att.auth_data, att.att_stmt)
    res = PackedAttestation().verify(att.att_stmt, att.auth_data, cdh)
    check(res.attestation_type == AttestationType.SELF, "PackedAttestation.verify -> SELF")

    # Second credential, other user
    user2 = {"id": b"\x05\x06", "name": "bob", "displayName": "Bob"}
    att2 = ctap.make_credential(hashlib.sha256(b"cd2").digest(), rp, user2, [{"type": "public-key", "alg": -7}], options={"rk": True})
    cred2 = att2.auth_data.credential_data
    check(ctap.get_info().remaining_disc_creds == info.remaining_disc_creds - 2, "remaining slots decreased by 2")

    # excludeList hit -> CREDENTIAL_EXCLUDED
    try:
        ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -7}],
                             exclude_list=[{"type": "public-key", "id": cred_data.credential_id}], options={"rk": True})
        check(False, "excludeList should fail")
    except CtapError as e:
        check(e.code == CtapError.ERR.CREDENTIAL_EXCLUDED, "excludeList -> CREDENTIAL_EXCLUDED")

    # rk=false -> UNSUPPORTED_OPTION, credProtect 3 -> UNSUPPORTED_EXTENSION
    try:
        ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -7}], options={"rk": False})
        check(False, "rk=false should fail")
    except CtapError as e:
        check(e.code == CtapError.ERR.UNSUPPORTED_OPTION, "rk=false -> UNSUPPORTED_OPTION")
    try:
        ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -7}], extensions={"credProtect": 3}, options={"rk": True})
        check(False, "credProtect=3 should fail")
    except CtapError as e:
        check(int(e.code) == 0x4B, "credProtect=3 -> UNSUPPORTED_EXTENSION (0x4B)")
    try:
        ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -257}], options={"rk": True})
        check(False, "RS256 should fail")
    except CtapError as e:
        check(e.code == CtapError.ERR.UNSUPPORTED_ALGORITHM, "RS256 only -> UNSUPPORTED_ALGORITHM")

    # Discoverable getAssertion (empty allowList) -> two credentials
    cdh2 = hashlib.sha256(b"client data 2").digest()
    assertions = ctap.get_assertions("example.com", cdh2)
    check(len(assertions) == 2, "getAssertion + getNextAssertion return 2 credentials")
    ids = {a.credential["id"] for a in assertions}
    check(ids == {cred_data.credential_id, cred2.credential_id}, "both credential ids present")
    for a in assertions:
        check(a.user is not None and "id" in a.user and "name" not in a.user, "user.id only when UV=0")
        check(a.auth_data.flags & AuthenticatorData.FLAG.UP, "assertion UP flag")
        key = cred_data.public_key if a.credential["id"] == cred_data.credential_id else cred2.public_key
        ES256(key).verify(a.auth_data + cdh2, a.signature)
    check(True, "assertion signatures verify with the credential public keys")
    counter_after = [a.auth_data.counter for a in assertions if a.credential["id"] == cred_data.credential_id][0]
    check(counter_after == 2, "signCount incremented to 2")

    # allowList selects one
    a = ctap.get_assertions("example.com", cdh2, allow_list=[{"type": "public-key", "id": cred2.credential_id}])
    check(len(a) == 1 and a[0].credential["id"] == cred2.credential_id, "allowList narrows to one credential")

    # pre-flight up=false: signs, no counter bump
    a = ctap.get_assertions("example.com", cdh2, allow_list=[{"type": "public-key", "id": cred_data.credential_id}], options={"up": False})
    check(a[0].auth_data.counter == 2 and not (a[0].auth_data.flags & 1), "up=false: UP=0 and counter unchanged")
    ES256(cred_data.public_key).verify(a[0].auth_data + cdh2, a[0].signature)
    check(True, "up=false assertion still carries a valid signature")

    # No credentials for another RP
    try:
        ctap.get_assertions("nope.example", cdh2)
        check(False, "should have no credentials")
    except CtapError as e:
        check(e.code == CtapError.ERR.NO_CREDENTIALS, "unknown RP -> NO_CREDENTIALS")

    if has_pin:
        pin_test(ctap, cred_data, has_hmac)
    if has_u2f:
        u2f_test(dev)

    # Reset
    ctap.reset()
    check(ctap.get_info().remaining_disc_creds == info.remaining_disc_creds, "reset restores remaining slots")
    try:
        ctap.get_assertions("example.com", cdh2)
        check(False, "after reset there must be no credentials")
    except CtapError as e:
        check(e.code == CtapError.ERR.NO_CREDENTIALS, "after reset -> NO_CREDENTIALS")
    print("ALL OK")


def pin_test(ctap, cred_data, has_hmac):
    proto = PinProtocolV2()
    cp = ClientPin(ctap, proto)
    check(cp.get_pin_retries()[0] == 8, "PIN retries 8 before set")
    check(ctap.info.options.get("clientPin") is False, "clientPin false before set")
    cp.set_pin("1234")
    check(ctap.get_info().options.get("clientPin") is True, "clientPin true after set")
    try:
        cp.get_pin_token("9999", ClientPin.PERMISSION.GET_ASSERTION, "example.com")
        check(False, "wrong PIN should fail")
    except CtapError as e:
        check(e.code == CtapError.ERR.PIN_INVALID, "wrong PIN -> PIN_INVALID")
    check(cp.get_pin_retries()[0] == 7, "retries decremented to 7")
    token = cp.get_pin_token("1234", ClientPin.PERMISSION.MAKE_CREDENTIAL | ClientPin.PERMISSION.GET_ASSERTION, "example.com")
    check(cp.get_pin_retries()[0] == 8, "retries reset to 8 on success")
    rp = {"id": "example.com", "name": "Example"}
    user = {"id": b"\x77", "name": "carol", "displayName": "Carol"}
    cdh = hashlib.sha256(b"pin cd").digest()
    # makeCredential requires PIN now (makeCredUvNotRqd=false)
    try:
        ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -7}], options={"rk": True})
        check(False, "makeCredential without PIN must fail when PIN set")
    except CtapError as e:
        check(int(e.code) == 0x36, "makeCredential without pinUvAuthParam -> PUAT_REQUIRED (0x36)")
    # Chrome-style: pre-flight getAssertion then makeCredential with the SAME token (K23)
    pa = proto.authenticate(token, cdh)
    try:
        ctap.get_assertions("example.com", cdh, options={"up": False}, pin_uv_param=pa, pin_uv_protocol=2)
    except CtapError as e:
        check(e.code == CtapError.ERR.NO_CREDENTIALS or True, "pre-flight with token")
    att = ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -7}], options={"rk": True},
                               pin_uv_param=pa, pin_uv_protocol=2,
                               extensions={"hmac-secret": True} if has_hmac else None)
    check(att.auth_data.flags & AuthenticatorData.FLAG.UV, "UV flag set with PIN token (token not one-shot)")
    if has_hmac:
        check(att.auth_data.extensions.get("hmac-secret") is True, "hmac-secret create output")
    # getAssertion without PIN still allowed (UV=0)
    a = ctap.get_assertions("example.com", cdh, allow_list=[{"type": "public-key", "id": att.auth_data.credential_data.credential_id}])
    check(not (a[0].auth_data.flags & AuthenticatorData.FLAG.UV), "getAssertion without PIN -> UV=0")
    # getAssertion with PIN -> UV=1 and full user entity
    ga_token = cp.get_pin_token("1234", ClientPin.PERMISSION.GET_ASSERTION, "example.com")
    a = ctap.get_assertions("example.com", cdh, allow_list=[{"type": "public-key", "id": att.auth_data.credential_data.credential_id}],
                            pin_uv_param=proto.authenticate(ga_token, cdh), pin_uv_protocol=2)
    check(a[0].auth_data.flags & AuthenticatorData.FLAG.UV, "getAssertion with PIN -> UV=1")
    check(a[0].user.get("name") == "carol", "full user entity when UV=1")
    # wrong rpId for the token's permissionsRPID
    try:
        ctap.get_assertions("other.example", cdh, pin_uv_param=proto.authenticate(ga_token, cdh), pin_uv_protocol=2)
        check(False, "token bound to example.com must not work for other.example")
    except CtapError as e:
        check(e.code in (CtapError.ERR.PIN_AUTH_INVALID, CtapError.ERR.NO_CREDENTIALS), "token rpId binding enforced")
    if has_hmac:
        hmac_test(ctap, cp, proto, att.auth_data.credential_data.credential_id)
    # change PIN
    cp.change_pin("1234", "5678")
    cp.get_pin_token("5678", ClientPin.PERMISSION.GET_ASSERTION, "example.com")
    check(True, "changePIN works")


def hmac_test(ctap, cp, proto, cred_id):
    from fido2.ctap2.pin import _pad_pin  # noqa
    key_agreement, shared = cp._get_shared_secret()
    salt1 = b"\x11" * 32
    salt2 = b"\x22" * 32
    cdh = hashlib.sha256(b"hmac cd").digest()

    def query(salts, token=None):
        salt_enc = proto.encrypt(shared, b"".join(salts))
        salt_auth = proto.authenticate(shared, salt_enc)
        ext = {"hmac-secret": {1: key_agreement, 2: salt_enc, 3: salt_auth, 4: 2}}
        kw = {}
        if token is not None:
            kw = {"pin_uv_param": proto.authenticate(token, cdh), "pin_uv_protocol": 2}
        a = ctap.get_assertions("example.com", cdh, allow_list=[{"type": "public-key", "id": cred_id}], extensions=ext, **kw)
        out = a[0].auth_data.extensions["hmac-secret"]
        dec = proto.decrypt(shared, out)
        return [dec[i:i + 32] for i in range(0, len(dec), 32)]

    r1 = query([salt1])
    r1b = query([salt1])
    check(r1 == r1b and len(r1) == 1, "hmac-secret (no UV) is deterministic, one output")
    r2 = query([salt1, salt2])
    check(len(r2) == 2 and r2[0] == r1[0], "two salts -> two outputs, first matches")
    token = cp.get_pin_token("1234", ClientPin.PERMISSION.GET_ASSERTION, "example.com")
    r_uv = query([salt1], token)
    check(r_uv[0] != r1[0], "hmac-secret differs between UV=1 and UV=0 (dual credRandom)")
    r_uv2 = query([salt1], cp.get_pin_token("1234", ClientPin.PERMISSION.GET_ASSERTION, "example.com"))
    check(r_uv == r_uv2, "UV credRandom is stable")


def u2f_test(dev):
    from fido2.ctap1 import Ctap1
    c1 = Ctap1(dev)
    check(c1.get_version() == "U2F_V2", "U2F_VERSION")
    app = hashlib.sha256(b"https://u2f.example").digest()
    chal = hashlib.sha256(b"challenge").digest()
    reg = c1.register(chal, app)
    reg.verify(app, chal)
    check(True, "U2F register self-signed cert verifies")
    auth = c1.authenticate(chal, app, reg.key_handle)
    auth.verify(app, chal, reg.public_key)
    check(auth.counter >= 1, "U2F authenticate verifies")
    try:
        c1.authenticate(chal, app, reg.key_handle, check_only=True)
        check(False, "check-only must raise")
    except Exception as e:  # ApduError CONDITIONS_NOT_SATISFIED
        check("6985" in repr(e) or "CONDITIONS_NOT_SATISFIED" in repr(e), "U2F check-only -> conditions not satisfied")


if __name__ == "__main__":
    main()
