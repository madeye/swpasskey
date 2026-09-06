#!/bin/sh
# Assemble and sign swpasskeyd.app (macOS HID/SE/notifications need a bundle).
#
#   packaging/macos/make_app.sh <build-dir> [<signing identity>] [debug|release]
#
# The restricted entitlements (HID virtual device, keychain-access-groups)
# require a provisioning profile from a paid team that has been granted
# com.apple.developer.hid.virtual.device. Drop that profile at
#   packaging/macos/embedded.provisionprofile
# before running. `codesign --sign -` (ad-hoc) is NOT supported: AMFI kills
# a process carrying restricted entitlements without a matching profile.
set -eu
BUILD_DIR=${1:?build dir}
IDENTITY=${2:-}
MODE=${3:-debug}
HERE=$(cd "$(dirname "$0")" && pwd)
APP="$BUILD_DIR/swpasskeyd.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$HERE/swpasskeyd.app/Contents/Info.plist" "$APP/Contents/Info.plist"
cp "$BUILD_DIR/swpasskeyd" "$APP/Contents/MacOS/swpasskeyd"
if [ -f "$HERE/embedded.provisionprofile" ]; then
  cp "$HERE/embedded.provisionprofile" "$APP/Contents/embedded.provisionprofile"
else
  echo "warning: no embedded.provisionprofile; IOHIDUserDevice creation will fail (K26)" >&2
fi
if [ "$MODE" = "release" ]; then
  ENT="$HERE/swpasskeyd.entitlements"
else
  ENT="$HERE/swpasskeyd.debug.entitlements"
fi
if [ -n "$IDENTITY" ]; then
  codesign --force --options runtime --timestamp --entitlements "$ENT" --sign "$IDENTITY" "$APP"
  codesign -dv --entitlements - "$APP" 2>&1 | head -30
else
  echo "not signed (no identity given). Do not use 'codesign --sign -' with these entitlements." >&2
fi
echo "$APP"
