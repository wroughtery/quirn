#!/bin/sh
# Quirn installer — downloads a released binary, verifies its checksum, installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/wroughtery/quirn/main/scripts/install.sh | sh
#
# Env overrides:
#   QUIRN_VERSION      tag to install (default: latest release)
#   QUIRN_INSTALL_DIR  install directory (default: /usr/local/bin, else ~/.local/bin)
#
# POSIX sh, no dependencies beyond curl/uname/sha256 tooling. Linux and macOS;
# on Windows use `go install` or Scoop.
set -eu

REPO="wroughtery/quirn"
BOLD="$(printf '\033[1m')"; DIM="$(printf '\033[2m')"; RST="$(printf '\033[0m')"
say() { printf '%s\n' "$*" >&2; }
die() { printf '%serror:%s %s\n' "$(printf '\033[31m')" "$RST" "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required."

# --- platform ---
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin) ;;
  *) die "unsupported OS '$os' — use 'go install github.com/$REPO@latest' or Scoop on Windows." ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported architecture '$arch'." ;;
esac
asset="quirn_${os}_${arch}"

# --- version ---
version="${QUIRN_VERSION:-}"
if [ -z "$version" ]; then
  say "${DIM}resolving latest release…${RST}"
  version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  [ -n "$version" ] || die "could not resolve the latest release tag (set QUIRN_VERSION)."
fi
base="https://github.com/$REPO/releases/download/$version"

# --- download to a temp dir ---
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t quirn)
trap 'rm -rf "$tmp"' EXIT INT TERM
say "${BOLD}quirn $version${RST}  ($os/$arch)"
curl -fSL --progress-bar "$base/$asset" -o "$tmp/quirn" \
  || die "download failed: $base/$asset"

# --- verify checksum (best effort: the release ships checksums_sha256.txt) ---
if curl -fsSL "$base/checksums_sha256.txt" -o "$tmp/sums" 2>/dev/null; then
  want=$(grep " ${asset}\$" "$tmp/sums" | awk '{print $1}' | head -1)
  if [ -n "$want" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      got=$(sha256sum "$tmp/quirn" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
      got=$(shasum -a 256 "$tmp/quirn" | awk '{print $1}')
    else
      got=""; say "${DIM}no sha256 tool found — skipping checksum verification${RST}"
    fi
    if [ -n "$got" ]; then
      [ "$got" = "$want" ] || die "checksum mismatch — refusing to install (expected $want, got $got)."
      say "${DIM}checksum verified${RST}"
    fi
  fi
else
  say "${DIM}no checksums file on this release — skipping verification${RST}"
fi
chmod +x "$tmp/quirn"

# --- choose an install dir we can actually write to ---
dir="${QUIRN_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then dir=/usr/local/bin
  elif command -v sudo >/dev/null 2>&1 && [ -d /usr/local/bin ]; then dir=/usr/local/bin
  else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir" 2>/dev/null || true

if [ -w "$dir" ]; then
  mv "$tmp/quirn" "$dir/quirn"
elif command -v sudo >/dev/null 2>&1; then
  say "${DIM}installing to $dir (needs sudo)${RST}"; sudo mv "$tmp/quirn" "$dir/quirn"
else
  die "cannot write to $dir — set QUIRN_INSTALL_DIR to a writable path."
fi

say ""
say "${BOLD}installed:${RST} $dir/quirn"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "${DIM}note: $dir is not on your PATH — add it to run 'quirn' directly.${RST}" ;;
esac
"$dir/quirn" version 2>/dev/null || true
say "next: ${BOLD}quirn scan --target <your-endpoint>${RST}"
