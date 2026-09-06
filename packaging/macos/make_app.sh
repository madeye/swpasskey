#!/bin/sh
# Assemble and sign swpasskeyd.app (macOS HID/SE/notifications need a bundle).
#
#   packaging/macos/make_app.sh <build-dir> [<signing identity>] [debug|release]
#
# The restricted entitlements (HID virtual device, keychain-access-groups)
# require a provisioning profile from a paid team. Drop that profile at
#   packaging/macos/embedded.provisionprofile
# before running. Any Developer ID profile grants keychain-access-groups
# (Secure Enclave, Keychain DEK); com.apple.developer.hid.virtual.device is
# only present once Apple has granted it to the team. Entitlements the
# profile does not grant are stripped, because AMFI SIGKILLs a process at exec
# when its signature carries a restricted entitlement no profile covers.
# `codesign --sign -` (ad-hoc) is NOT supported for the same reason.
#
# Build with `cmake --preset app` (static OpenSSL, no TPM): the hardened
# runtime refuses to load Homebrew dylibs signed by another Team ID.
set -eu
BUILD_DIR=${1:?build dir}
IDENTITY=${2:-}
MODE=${3:-debug}
HERE=$(cd "$(dirname "$0")" && pwd)
APP="$BUILD_DIR/swpasskeyd.app"
PROFILE="$HERE/embedded.provisionprofile"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$HERE/swpasskeyd.app/Contents/Info.plist" "$APP/Contents/Info.plist"
cp "$BUILD_DIR/swpasskeyd" "$APP/Contents/MacOS/swpasskeyd"
if [ -x "$BUILD_DIR/swpasskeyctl" ]; then
  cp "$BUILD_DIR/swpasskeyctl" "$APP/Contents/MacOS/swpasskeyctl"
fi

if otool -L "$APP/Contents/MacOS/swpasskeyd" | grep -E '^\s+/(opt|usr/local|private|Users|Volumes)/' ; then
  echo "warning: non-system dylibs above will be rejected by the hardened runtime; use 'cmake --preset app'" >&2
fi

if [ "$MODE" = "release" ]; then
  ENT_SRC="$HERE/swpasskeyd.entitlements"
else
  ENT_SRC="$HERE/swpasskeyd.debug.entitlements"
fi
ENT="$BUILD_DIR/swpasskeyd.entitlements.plist"
cp "$ENT_SRC" "$ENT"

TEAM=""
if [ -f "$PROFILE" ]; then
  cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
  PLIST=$(security cms -D -i "$PROFILE")
  TEAM=$(printf '%s' "$PLIST" | plutil -extract Entitlements.com\\.apple\\.developer\\.team-identifier raw -o - - 2>/dev/null || true)
  if ! printf '%s' "$PLIST" | grep -q 'com.apple.developer.hid.virtual.device'; then
    echo "warning: profile does not grant com.apple.developer.hid.virtual.device; stripping it (IOHIDUserDevice will fail, K26)" >&2
    plutil -remove 'com\.apple\.developer\.hid\.virtual\.device' "$ENT"
  fi
else
  echo "warning: no embedded.provisionprofile; stripping restricted entitlements (HID and SE will fail, K26)" >&2
  plutil -remove 'com\.apple\.developer\.hid\.virtual\.device' "$ENT"
  plutil -remove 'keychain-access-groups' "$ENT"
fi
if [ -z "$TEAM" ] && [ -n "$IDENTITY" ]; then
  TEAM=$(printf '%s' "$IDENTITY" | sed -n 's/.*(\([A-Z0-9]*\))$/\1/p')
fi
# codesign does not expand $(AppIdentifierPrefix); Xcode does.
sed -i '' "s/\$(AppIdentifierPrefix)/${TEAM}./g" "$ENT"
plutil -lint "$ENT" >/dev/null

if [ -n "$IDENTITY" ]; then
  if [ -x "$APP/Contents/MacOS/swpasskeyctl" ]; then
    codesign --force --options runtime --timestamp --sign "$IDENTITY" "$APP/Contents/MacOS/swpasskeyctl"
  fi
  codesign --force --options runtime --timestamp --entitlements "$ENT" --sign "$IDENTITY" "$APP"
  codesign -dv --entitlements - "$APP" 2>&1 | grep -E 'Authority=|TeamIdentifier|\[Key\]|\[String\]'
else
  echo "not signed (no identity given). Do not use 'codesign --sign -' with these entitlements." >&2
fi
echo "$APP"
