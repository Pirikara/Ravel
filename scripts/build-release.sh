#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || ! "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-beta\.[0-9]+$ ]]; then
  echo "usage: $0 vX.Y.Z-beta.N OUTPUT_DIR|--check" >&2
  exit 2
fi

release_version="$1"
release_mode="$2"
if [[ "$release_mode" != "--check" && ( ! -f LICENSE || ! -f NOTICE ) ]]; then
  echo "release archives require LICENSE and NOTICE" >&2
  exit 1
fi
if [[ "$release_mode" != "--check" ]]; then
  if [[ "$(git rev-parse "refs/tags/$release_version^{commit}" 2>/dev/null)" != "$(git rev-parse HEAD)" ]] ||
     [[ -n "$(git status --porcelain)" ]]; then
    echo "release archives require a clean checkout at the matching tag" >&2
    exit 1
  fi
  if [[ -d "$release_mode" && -n "$(ls -A "$release_mode")" ]]; then
    echo "release output directory must be empty" >&2
    exit 1
  fi
fi

release_tmp="$(mktemp -d)"
trap 'rm -rf "$release_tmp"' EXIT

release_targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)
release_modules="$release_tmp/modules.txt"
: > "$release_modules"
for target in "${release_targets[@]}"; do
  release_os="${target%/*}"
  release_arch="${target#*/}"
  CGO_ENABLED=0 GOOS="$release_os" GOARCH="$release_arch" \
    go list -deps -f '{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}' \
    ./cmd/ravel >> "$release_modules"
done

release_license_dir="$release_tmp/THIRD_PARTY_LICENSES"
mkdir -p "$release_license_dir"
shopt -s nullglob
sort -u "$release_modules" | while IFS='|' read -r module_path module_version module_dir; do
  if [[ -z "$module_path" || "$module_path" == "github.com/Pirikara/Ravel" ]]; then
    continue
  fi
  release_license_files=("$module_dir"/LICENSE* "$module_dir"/LICENCE* "$module_dir"/COPYING* "$module_dir"/NOTICE*)
  if [[ ${#release_license_files[@]} -eq 0 ]]; then
    echo "missing license for $module_path $module_version" >&2
    exit 1
  fi
  release_module_dir="$release_license_dir/$module_path@$module_version"
  mkdir -p "$release_module_dir"
  cp "${release_license_files[@]}" "$release_module_dir/"
  printf '%s %s\n' "$module_path" "$module_version" >> "$release_license_dir/MODULES.txt"
done
shopt -u nullglob

if [[ "$release_mode" != "--check" ]]; then
  mkdir -p "$release_mode"
  release_output="$(cd "$release_mode" && pwd -P)"
fi

release_archives=()
for target in "${release_targets[@]}"; do
  release_os="${target%/*}"
  release_arch="${target#*/}"
  release_name="ravel_${release_version}_${release_os}_${release_arch}"
  release_dir="$release_tmp/$release_name"
  mkdir -p "$release_dir"
  release_binary="ravel"
  if [[ "$release_os" == "windows" ]]; then
    release_binary="ravel.exe"
  fi

  echo "building $target" >&2
  CGO_ENABLED=0 GOOS="$release_os" GOARCH="$release_arch" \
    go build -trimpath -ldflags="-s -w -X main.version=$release_version" \
    -o "$release_dir/$release_binary" ./cmd/ravel

  if [[ "$release_mode" == "--check" ]]; then
    continue
  fi

  cp README.md LICENSE NOTICE THIRD_PARTY_NOTICES.md "$release_dir/"
  cp -R "$release_license_dir" "$release_dir/"
  if [[ "$release_os" == "windows" ]]; then
    (cd "$release_tmp" && zip -q -r "$release_output/$release_name.zip" "$release_name")
    release_archives+=("$release_name.zip")
  else
    tar -C "$release_tmp" -czf "$release_output/$release_name.tar.gz" "$release_name"
    release_archives+=("$release_name.tar.gz")
  fi
  rm -rf "$release_dir"
done

if [[ "$release_mode" != "--check" ]]; then
  (cd "$release_output" && shasum -a 256 "${release_archives[@]}" > SHA256SUMS)
  echo "wrote $release_output" >&2
fi
