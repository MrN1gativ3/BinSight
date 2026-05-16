#!/usr/bin/env sh
set -eu

version="${1:-5.1.1}"
dest_root="${BINSIGHT_UPX_DIR:-tools/upx}"
case "$(uname -m)" in
  x86_64|amd64)
    default_platform="amd64_linux"
    ;;
  i386|i686)
    default_platform="i386_linux"
    ;;
  aarch64|arm64)
    default_platform="arm64_linux"
    ;;
  armv7l|armv7*)
    default_platform="arm_linux"
    ;;
  *)
    echo "fetch-upx: unsupported machine '$(uname -m)'; set BINSIGHT_UPX_ASSET" >&2
    exit 1
    ;;
esac
platform="${BINSIGHT_UPX_PLATFORM:-$default_platform}"
asset="${BINSIGHT_UPX_ASSET:-upx-${version}-${platform}.tar.xz}"
url="${BINSIGHT_UPX_URL:-https://github.com/upx/upx/releases/download/v${version}/${asset}}"

tmp_dir="$(mktemp -d)"
archive="${tmp_dir}/${asset}"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

mkdir -p "${dest_root}/${version}"

if command -v curl >/dev/null 2>&1; then
  curl -fL "$url" -o "$archive"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$archive" "$url"
else
  echo "fetch-upx: curl or wget is required" >&2
  exit 1
fi

tar -xf "$archive" -C "$tmp_dir"
upx_bin="$(find "$tmp_dir" -type f -name upx -perm -111 | head -n 1)"
if [ -z "$upx_bin" ]; then
  echo "fetch-upx: archive did not contain an executable named upx" >&2
  exit 1
fi

cp "$upx_bin" "${dest_root}/${version}/upx"
chmod 0755 "${dest_root}/${version}/upx"

echo "installed UPX ${version} at ${dest_root}/${version}/upx"
