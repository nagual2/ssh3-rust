#!/bin/sh
# Copyright 2026 The nagual2 ssh3 Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Build the Debian package of the Rust SSH3 server (`ssh3-rust-server`).
#
# The package carries the server binary, the systemd unit, the environment
# file, the license and the README. It is built from the artifacts of the
# release pipeline, so the binary is never rebuilt here: the package contains
# exactly the bits that were published for the platform.
#
# The control file of the package is the template
# `packaging/ssh3-rust-server.control.in`, whose placeholders are
# substituted here:
#
#   @VERSION@        - the upstream version of the release (the version of
#                      the package is `<version>-1`);
#   @ARCH@           - the Debian architecture (amd64 / arm64);
#   @INSTALLED_SIZE@ - the size of the installed tree in kilobytes.
#
# Usage:
#   packaging/build-deb.sh --binary <path> --arch <amd64|arm64> \
#       --version <version> --output-dir <dir> [--source-date-epoch <epoch>]
#
# The script is POSIX sh and runs on a Debian based builder (the `deb` job of
# the release pipeline). `dpkg-deb` builds the package.

set -eu

usage() {
  echo "usage: $0 --binary <path> --arch <amd64|arm64> --version <version> --output-dir <dir> [--source-date-epoch <epoch>]" >&2
  exit 2
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

binary=""
arch=""
version=""
output_dir=""
source_date_epoch=""

while [ $# -gt 0 ]; do
  case "$1" in
    --binary)
      binary="${2:-}"
      shift 2
      ;;
    --arch)
      arch="${2:-}"
      shift 2
      ;;
    --version)
      version="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --source-date-epoch)
      source_date_epoch="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      ;;
    *)
      echo "error: unknown argument '$1'" >&2
      usage
      ;;
  esac
done

[ -n "$binary" ] || usage
[ -n "$arch" ] || usage
[ -n "$version" ] || usage
[ -n "$output_dir" ] || usage

case "$arch" in
  amd64 | arm64) ;;
  *)
    echo "error: unsupported architecture '$arch' (want amd64 or arm64)" >&2
    exit 2
    ;;
esac

if [ ! -f "$binary" ]; then
  echo "error: the server binary '$binary' does not exist" >&2
  exit 1
fi

if [ -z "$source_date_epoch" ]; then
  # The fallback keeps the package buildable outside the release pipeline.
  source_date_epoch=$(date -u +%s)
fi

command -v dpkg-deb >/dev/null 2>&1 || {
  echo "error: dpkg-deb is not installed" >&2
  exit 1
}

pkg_root=$(mktemp -d)
trap 'rm -rf "$pkg_root"' EXIT

# `mktemp -d` creates the directory with the mode 0700; the root of the
# package has to be readable for the users of the system.
chmod 0755 "$pkg_root"

install -d -m 0755 "$pkg_root/DEBIAN"
install -d -m 0755 "$pkg_root/usr/bin"
install -d -m 0755 "$pkg_root/usr/lib/systemd/system"
install -d -m 0755 "$pkg_root/etc/ssh3"
install -d -m 0755 "$pkg_root/usr/share/doc/ssh3-rust-server"

# The payload.
install -m 0755 "$binary" "$pkg_root/usr/bin/ssh3-rust-server"
install -m 0644 "$repo_root/packaging/ssh3-rust-server.service" \
  "$pkg_root/usr/lib/systemd/system/ssh3-rust-server.service"
install -m 0644 "$repo_root/packaging/ssh3-rust-server.env" \
  "$pkg_root/etc/ssh3/ssh3-rust-server.env"

# The documentation.
install -m 0644 "$repo_root/LICENSE" "$pkg_root/usr/share/doc/ssh3-rust-server/LICENSE"
install -m 0644 "$repo_root/NOTICE" "$pkg_root/usr/share/doc/ssh3-rust-server/NOTICE"
install -m 0644 "$repo_root/README.md" "$pkg_root/usr/share/doc/ssh3-rust-server/README.md"

# The Debian changelog of the package.
changelog_date=$(date -u -d "@$source_date_epoch" "+%a, %d %b %Y %H:%M:%S +0000")
cat >"$pkg_root/usr/share/doc/ssh3-rust-server/changelog.Debian" <<EOF
ssh3-rust-server ($version-1) unstable; urgency=medium

  * Release $version of the Rust implementation of the SSH3 server:
    the server binary, the systemd unit and the environment file.

 -- nagual2 <912140+nagual2@users.noreply.github.com>  $changelog_date
EOF
gzip -n -9 -c "$pkg_root/usr/share/doc/ssh3-rust-server/changelog.Debian" \
  >"$pkg_root/usr/share/doc/ssh3-rust-server/changelog.Debian.gz"
rm -f "$pkg_root/usr/share/doc/ssh3-rust-server/changelog.Debian"

# The control file.
installed_size=$(du -sk --exclude=DEBIAN "$pkg_root" | cut -f1)
sed -e "s/@VERSION@/$version/g" \
  -e "s/@ARCH@/$arch/g" \
  -e "s/@INSTALLED_SIZE@/$installed_size/g" \
  "$repo_root/packaging/ssh3-rust-server.control.in" >"$pkg_root/DEBIAN/control"

# The maintainer scripts.
install -m 0755 "$repo_root/packaging/ssh3-rust-server.postinst" "$pkg_root/DEBIAN/postinst"
install -m 0755 "$repo_root/packaging/ssh3-rust-server.prerm" "$pkg_root/DEBIAN/prerm"

# A reproducible package: every file of the tree carries the timestamp of the
# released commit, and the ownership is fixed to root:root.
find "$pkg_root" -exec touch -h -d "@$source_date_epoch" {} +

mkdir -p "$output_dir"
package_name="ssh3-rust-server_${version}-1_${arch}.deb"
package_path="$output_dir/$package_name"

# `dpkg-deb` honours SOURCE_DATE_EPOCH: the timestamps of the members of the
# archive and of the gzip streams are taken from it, so the package is
# reproducible.
SOURCE_DATE_EPOCH="$source_date_epoch"
export SOURCE_DATE_EPOCH

dpkg-deb --root-owner-group --build "$pkg_root" "$package_path" >/dev/null

echo "built $package_path"
dpkg-deb --info "$package_path" >/dev/null
