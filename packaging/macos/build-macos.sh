#!/usr/bin/env bash
# Build LLM Vault.app and a DMG on macOS (universal: arm64 + x86_64).
# Optional signing / notarization via environment variables:
#   MACOS_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
#   MACOS_NOTARY_PROFILE=<keychain profile created with `xcrun notarytool store-credentials`>
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"(.+)".*/\1/')
APP="dist/LLM Vault.app"
echo "LLM Vault $VERSION (macOS)"

rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
cargo build --release --bins --target aarch64-apple-darwin
cargo build --release --bins --target x86_64-apple-darwin

rm -rf "$APP" && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
for bin in llmvault llmvault-server; do
  lipo -create -output "$APP/Contents/MacOS/$bin" \
    "target/aarch64-apple-darwin/release/$bin" "target/x86_64-apple-darwin/release/$bin"
done

# Icon (.icns) from the 512 px PNG
ICONSET=$(mktemp -d)/llmvault.iconset && mkdir -p "$ICONSET"
for s in 16 32 64 128 256 512; do
  sips -z $s $s assets/icon-512.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2)); [ $d -le 512 ] && sips -z $d $d assets/icon-512.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/llmvault.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>LLM Vault</string>
  <key>CFBundleDisplayName</key><string>LLM Vault</string>
  <key>CFBundleIdentifier</key><string>com.bestin-it.llmvault</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleExecutable</key><string>llmvault</string>
  <key>CFBundleIconFile</key><string>llmvault</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>NSHumanReadableCopyright</key><string>Apache-2.0 - bestin-it.com</string>
</dict></plist>
PLIST
cp LICENSE README.md "$APP/Contents/Resources/"

if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$APP/Contents/MacOS/llmvault-server"
  codesign --force --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" "$APP"
  codesign --verify --deep --strict "$APP"
fi

DMG="dist/LLM-Vault-$VERSION-macos-universal.dmg"
rm -f "$DMG"
STAGE=$(mktemp -d) && cp -R "$APP" "$STAGE/" && ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "LLM Vault" -srcfolder "$STAGE" -ov -format UDZO "$DMG"

if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then
  codesign --timestamp --sign "$MACOS_SIGN_IDENTITY" "$DMG"
  if [ -n "${MACOS_NOTARY_PROFILE:-}" ]; then
    xcrun notarytool submit "$DMG" --keychain-profile "$MACOS_NOTARY_PROFILE" --wait
    xcrun stapler staple "$DMG"
  fi
fi
shasum -a 256 "$DMG"
