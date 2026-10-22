#!/usr/bin/env bash
#
# Verify that the vendored h3 shim is reproducible from the upstream crate.
#
# The workspace overrides the crates.io `h3` crate with a local path dependency
# (`[patch.crates-io] h3 = { path = "vendor/h3" }`). The vendored tree is the
# pristine crates.io release plus the two edits recorded in
# `patches/h3-0.0.8.patch`.
#
# This script proves that claim: it fetches the pristine upstream crate,
# checks its checksum, applies the patch and compares the result with the
# vendored tree. A drift between the vendored tree and the patch makes the
# script fail, which is what keeps the shim auditable across `h3` upgrades.
#
# Environment variables:
#   H3_CRATE   path to a local `h3-<version>.crate` file; when unset the
#              script looks in the cargo registry cache and falls back to
#              downloading the crate from crates.io.
#   H3_VERSION upstream h3 version to verify (default: 0.0.8).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
H3_VERSION="${H3_VERSION:-0.0.8}"
H3_SHA256="10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be"
H3_URL="https://static.crates.io/crates/h3/h3-${H3_VERSION}.crate"

PATCH_FILE="${REPO_ROOT}/patches/h3-${H3_VERSION}.patch"
VENDOR_DIR="${REPO_ROOT}/vendor/h3"

fail() {
    echo "verify-h3-shim: $*" >&2
    exit 1
}

[ -f "${PATCH_FILE}" ] || fail "patch file not found: ${PATCH_FILE}"
[ -d "${VENDOR_DIR}" ] || fail "vendored crate not found: ${VENDOR_DIR}"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

# --- 1. Obtain the pristine upstream crate -------------------------------
CRATE_FILE="${WORK_DIR}/h3-${H3_VERSION}.crate"

if [ -n "${H3_CRATE:-}" ]; then
    [ -f "${H3_CRATE}" ] || fail "H3_CRATE does not exist: ${H3_CRATE}"
    cp "${H3_CRATE}" "${CRATE_FILE}"
else
    CACHE_DIR="${CARGO_HOME:-${HOME}/.cargo}/registry/cache"
    FOUND=""
    if [ -d "${CACHE_DIR}" ]; then
        for candidate in "${CACHE_DIR}"/*/h3-"${H3_VERSION}".crate; do
            if [ -f "${candidate}" ]; then
                FOUND="${candidate}"
                break
            fi
        done
    fi
    if [ -n "${FOUND}" ]; then
        echo "verify-h3-shim: using cached crate ${FOUND}"
        cp "${FOUND}" "${CRATE_FILE}"
    else
        echo "verify-h3-shim: downloading ${H3_URL}"
        curl -fsSL --max-time 120 -o "${CRATE_FILE}" "${H3_URL}" \
            || fail "failed to download ${H3_URL}"
    fi
fi

# --- 2. Check the crate checksum -----------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL="$(sha256sum "${CRATE_FILE}" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL="$(shasum -a 256 "${CRATE_FILE}" | cut -d' ' -f1)"
else
    ACTUAL=""
    echo "verify-h3-shim: warning: no sha256 tool found, checksum not verified" >&2
fi

if [ -n "${ACTUAL}" ] && [ "${ACTUAL}" != "${H3_SHA256}" ]; then
    fail "checksum mismatch for h3-${H3_VERSION}.crate: ${ACTUAL} != ${H3_SHA256}"
fi

# --- 3. Extract and apply the patch --------------------------------------
tar xzf "${CRATE_FILE}" -C "${WORK_DIR}"
SRC_DIR="${WORK_DIR}/h3-${H3_VERSION}"
[ -d "${SRC_DIR}" ] || fail "unexpected crate layout in ${CRATE_FILE}"

echo "verify-h3-shim: applying ${PATCH_FILE}"
patch --batch --forward -p1 -d "${SRC_DIR}" < "${PATCH_FILE}" \
    || fail "the patch does not apply cleanly to h3-${H3_VERSION}"

# --- 4. Compare the patched upstream crate with the vendored tree ---------
# The vendored tree is checked out on Windows with CRLF line endings, while
# the upstream crate uses LF. `--strip-trailing-cr` compares the content of
# both trees and ignores that checkout artefact only.
echo "verify-h3-shim: comparing the patched crate with vendor/h3"
if ! diff -r --strip-trailing-cr -x '.cargo-ok' "${SRC_DIR}" "${VENDOR_DIR}"; then
    fail "vendor/h3 drifted from h3-${H3_VERSION} + patches/h3-${H3_VERSION}.patch"
fi

# --- 5. Check that the dependency pins still match the base ---------------
# The patch applies to one specific h3 release, and the published h3-quinn
# releases depend on exactly that version of h3 (0.0.10 on h3 0.0.8). A
# dependency bump that moves the base must rebase the shim first, so the
# gate fails until the manifest, the lockfile and the recorded base agree.
MANIFEST="${REPO_ROOT}/ssh3-h3/Cargo.toml"
LOCKFILE="${REPO_ROOT}/Cargo.lock"

[ -f "${MANIFEST}" ] || fail "manifest not found: ${MANIFEST}"
[ -f "${LOCKFILE}" ] || fail "lockfile not found: ${LOCKFILE}"

MANIFEST_REQUIREMENT="$(awk -F'"' '/^h3 = / { print $2; exit }' "${MANIFEST}")"
[ -n "${MANIFEST_REQUIREMENT}" ] || fail "no h3 requirement found in ${MANIFEST}"
if [ "${MANIFEST_REQUIREMENT}" != "${H3_VERSION}" ]; then
    fail "ssh3-h3 requires h3 ${MANIFEST_REQUIREMENT}, but the shim is recorded for h3 ${H3_VERSION}"
fi

LOCKED_VERSION="$(awk '
    /^name = "h3"$/ { in_h3 = 1; next }
    in_h3 && /^version = / { gsub(/"/, "", $3); print $3; exit }
' "${LOCKFILE}")"
[ -n "${LOCKED_VERSION}" ] || fail "no h3 package found in ${LOCKFILE}"
if [ "${LOCKED_VERSION}" != "${H3_VERSION}" ]; then
    fail "the lockfile resolves h3 ${LOCKED_VERSION}, but the shim is recorded for h3 ${H3_VERSION}"
fi

if ! awk '
    /^name = "h3-quinn"$/ { in_h3quinn = 1; next }
    in_h3quinn && /^ "h3",$/ { found = 1; exit }
    in_h3quinn && /^\[\[package\]\]/ { exit }
    END { exit found ? 0 : 1 }
' "${LOCKFILE}"; then
    fail "h3-quinn does not depend on h3 in ${LOCKFILE}: the h3-quinn and h3 versions must stay in sync"
fi

echo "verify-h3-shim: OK - vendor/h3 matches h3-${H3_VERSION} + the recorded patch"
