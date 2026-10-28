#!/usr/bin/env bash
# Build LLM Vault for Linux: AppImage, .deb and .rpm (x86_64).
# Requires: cargo-deb, cargo-generate-rpm (cargo install cargo-deb cargo-generate-rpm),
#           appimagetool in PATH, and the Slint/winit build deps:
#           sudo apt install libfontconfig1-dev libxkbcommon-dev libwayland-dev libx11-dev
# Optional signing: GPG_KEY_ID=<key> signs the checksums file (detached .asc).
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"(.+)".*/\1/')
mkdir -p dist

cargo build --release --bins

# .deb and .rpm (metadata in Cargo.toml: [package.metadata.deb] / [package.metadata.generate-rpm])
cargo deb --no-build --output "dist/llm-vault_${VERSION}_amd64.deb"
cargo generate-rpm --output "dist/llm-vault-${VERSION}-1.x86_64.rpm"

# AppImage
APPDIR=$(mktemp -d)/LLMVault.AppDir
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp target/release/llmvault target/release/llmvault-server "$APPDIR/usr/bin/"
cp packaging/linux/llm-vault.desktop "$APPDIR/usr/share/applications/"
cp packaging/linux/llm-vault.desktop "$APPDIR/"
cp assets/icon-256.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/llm-vault.png"
cp assets/icon-256.png "$APPDIR/llm-vault.png"
cat > "$APPDIR/AppRun" <<'RUN'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/llmvault" "$@"
RUN
chmod +x "$APPDIR/AppRun"
ARCH=x86_64 appimagetool "$APPDIR" "dist/LLM-Vault-${VERSION}-x86_64.AppImage"

(cd dist && sha256sum * > SHA256SUMS.txt)
if [ -n "${GPG_KEY_ID:-}" ]; then
  gpg --batch --yes --local-user "$GPG_KEY_ID" --armor --detach-sign dist/SHA256SUMS.txt
fi
cat dist/SHA256SUMS.txt
