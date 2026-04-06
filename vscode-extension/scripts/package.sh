#!/usr/bin/env bash
#
# Build the guardian binary for one or more platforms and package the
# VS Code extension into a .vsix file.
#
# Usage:
#   ./scripts/package.sh                 # current platform only
#   ./scripts/package.sh --all           # linux, macOS, windows (amd64 + arm64)
#   ./scripts/package.sh --target linux-x64   # single target
#
# The resulting .vsix files are placed in the vscode-extension/ directory.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$EXT_DIR/.." && pwd)"
POLICIES_SRC="$ROOT_DIR/policies"

# ── helpers ──────────────────────────────────────────────────────
log()  { echo "==> $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

build_binary() {
  local goos="$1" goarch="$2" out="$3"
  log "Building guardian for ${goos}/${goarch} -> ${out}"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w" -o "$out" "$ROOT_DIR/cmd/guardian"
}

ensure_tools() {
  command -v go   >/dev/null 2>&1 || die "go is not installed"
  command -v node >/dev/null 2>&1 || die "node is not installed"
  command -v npm  >/dev/null 2>&1 || die "npm is not installed"
}

# Map vsce --target names to GOOS/GOARCH pairs.
declare -A TARGET_MAP=(
  ["linux-x64"]="linux amd64"
  ["linux-arm64"]="linux arm64"
  ["darwin-x64"]="darwin amd64"
  ["darwin-arm64"]="darwin arm64"
  ["win32-x64"]="windows amd64"
  ["win32-arm64"]="windows arm64"
)

binary_name() {
  local goos="$1"
  if [[ "$goos" == "windows" ]]; then echo "guardian.exe"; else echo "guardian"; fi
}

current_target() {
  local os arch
  case "$(uname -s)" in
    Linux*)  os=linux  ;;
    Darwin*) os=darwin ;;
    MINGW*|MSYS*|CYGWIN*|Windows*) os=win32 ;;
    *)       die "unsupported OS: $(uname -s)" ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64)  arch=x64   ;;
    aarch64|arm64) arch=arm64 ;;
    *)             die "unsupported arch: $(uname -m)" ;;
  esac
  echo "${os}-${arch}"
}

# ── compile TypeScript ───────────────────────────────────────────
compile_extension() {
  log "Installing npm dependencies"
  (cd "$EXT_DIR" && npm ci --ignore-scripts)
  log "Compiling TypeScript"
  (cd "$EXT_DIR" && npm run compile)
}

# ── bundle policies ─────────────────────────────────────────────
bundle_policies() {
  log "Bundling policies -> bin/policies/"
  mkdir -p "$EXT_DIR/bin/policies"
  cp "$POLICIES_SRC"/*.rego "$EXT_DIR/bin/policies/"
}

# ── package for a single target ─────────────────────────────────
package_target() {
  local target="$1"
  local pair="${TARGET_MAP[$target]:-}"
  [[ -n "$pair" ]] || die "unknown target: $target  (valid: ${!TARGET_MAP[*]})"

  local goos goarch
  read -r goos goarch <<< "$pair"
  local bin_name
  bin_name="$(binary_name "$goos")"

  mkdir -p "$EXT_DIR/bin"
  build_binary "$goos" "$goarch" "$EXT_DIR/bin/$bin_name"
  bundle_policies

  log "Packaging VSIX for target ${target}"
  (cd "$EXT_DIR" && npx @vscode/vsce package --target "$target" --no-git-tag-version --no-update-package-json)

  # Clean binary so the next target starts fresh.
  rm -f "$EXT_DIR/bin/$bin_name"
}

# ── package universal (no binary bundled) ────────────────────────
package_universal() {
  bundle_policies

  log "Packaging universal VSIX (no bundled binary)"
  (cd "$EXT_DIR" && npx @vscode/vsce package --no-git-tag-version --no-update-package-json)
}

# ── main ─────────────────────────────────────────────────────────
main() {
  ensure_tools
  compile_extension

  case "${1:-}" in
    --all)
      for target in "${!TARGET_MAP[@]}"; do
        package_target "$target"
      done
      ;;
    --target)
      [[ -n "${2:-}" ]] || die "usage: $0 --target <target>"
      package_target "$2"
      ;;
    --universal)
      package_universal
      ;;
    "")
      local target
      target="$(current_target)"
      log "Detected current platform: $target"
      package_target "$target"
      ;;
    *)
      echo "Usage: $0 [--all | --target <target> | --universal]"
      echo ""
      echo "Targets: ${!TARGET_MAP[*]}"
      exit 1
      ;;
  esac

  log "Done! VSIX files:"
  ls -1 "$EXT_DIR"/*.vsix 2>/dev/null || echo "  (none found)"
}

main "$@"
