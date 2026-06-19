#!/usr/bin/env bash
# Build the BLE peripheral example and run it from inside a minimal .app
# bundle. The Info.plist is required: macOS silently refuses
# `CBPeripheralManager.addService:` for binaries with no
# NSBluetoothAlwaysUsageDescription, with no error and no callback.
set -euo pipefail

cd "$(dirname "$0")"
WORKSPACE_ROOT="$(cd ../../.. && pwd)"

PROFILE="${PROFILE:-release}"
case "$PROFILE" in
    release) CARGO_FLAGS="--release" ;;
    debug)   CARGO_FLAGS="" ;;
    *) echo "PROFILE must be 'release' or 'debug', got '$PROFILE'" >&2; exit 1 ;;
esac

cargo build $CARGO_FLAGS -p example-ble-macos

APP_DIR="$WORKSPACE_ROOT/target/$PROFILE/BleMacos.app"
mkdir -p "$APP_DIR/Contents/MacOS"
cp Info.plist "$APP_DIR/Contents/Info.plist"
cp "$WORKSPACE_ROOT/target/$PROFILE/ble-macos" "$APP_DIR/Contents/MacOS/ble-macos"

echo "Launching $APP_DIR/Contents/MacOS/ble-macos"
echo "(grant Bluetooth permission via System Settings → Privacy & Security → Bluetooth"
echo " when prompted; without it CoreBluetooth silently refuses to advertise.)"
echo
exec "$APP_DIR/Contents/MacOS/ble-macos" "$@"
