#!/usr/bin/env bash
#
# Regenerate patches/h3-0.0.8.patch from the pristine upstream crate and the
# vendored tree.
#
# The patch must turn the pristine crates.io release into the vendored tree,
# byte for byte (the line endings of the checkout are ignored). Run it after
# every edit of vendor/h3 and check the result with
# scripts/verify-h3-shim.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${TMPDIR:-/tmp}/h3-patch-$$"
H3_VERSION="0.0.8"

cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

mkdir -p "${WORK_DIR}"

CACHE_DIR="${CARGO_HOME:-${HOME}/.cargo}/registry/cache"
CRATE_FILE="$(ls "${CACHE_DIR}"/*/h3-"${H3_VERSION}".crate 2>/dev/null | head -1 || true)"
if [ -z "${CRATE_FILE}" ]; then
    CRATE_FILE="${WORK_DIR}/h3-${H3_VERSION}.crate"
    curl -fsSL --max-time 120 -o "${CRATE_FILE}" \
        "https://static.crates.io/crates/h3/h3-${H3_VERSION}.crate"
fi
echo "using crate ${CRATE_FILE}"

tar xzf "${CRATE_FILE}" -C "${WORK_DIR}"
PRISTINE="${WORK_DIR}/h3-${H3_VERSION}"
PATCHED="${WORK_DIR}/h3-patched"
cp -r "${PRISTINE}" "${PATCHED}"

# The vendored tree is checked out with CRLF line endings on Windows: the
# comparison and the patch are done on the LF form.
cp -r "${REPO_ROOT}/vendor/h3/." "${PATCHED}/"
# The pristine archive carries the bookkeeping file of the registry, the
# vendored tree does not: it is not part of the patch.
rm -f "${PATCHED}/.cargo-ok"
find "${PATCHED}" -type f -name '*.rs' -exec sed -i 's/\r$//' {} +
find "${PRISTINE}" -type f -name '*.rs' -exec sed -i 's/\r$//' {} +

cd "${WORK_DIR}"
diff -ruN --strip-trailing-cr "h3-${H3_VERSION}" "h3-patched" > "${WORK_DIR}/h3.diff" || true

# Rewrite the paths of the diff so that the patch applies with -p1.
sed -e "s|^--- h3-${H3_VERSION}/|--- a/|" -e "s|^+++ h3-patched/|+++ b/|" \
    "${WORK_DIR}/h3.diff" > "${WORK_DIR}/h3.patch"

cat > "${REPO_ROOT}/patches/h3-${H3_VERSION}.patch" <<'HEADER'
Shim patch for the crates.io h3 0.0.8 crate.

The workspace pins h3 through a [patch.crates-io] path override to
vendor/h3. The vendored tree is the upstream crates.io h3 0.0.8 release
with three local edits applied:

  * src/ext.rs            - the closed 'Protocol' enumeration is replaced by
                            an open 'Cow<str>' token, so that the SSH3 extended
                            CONNECT ':protocol' value ('ssh3') can be carried
                            on the wire. Upstream h3 only knows 'webtransport'
                            and 'connect-udp'.
  * src/proto/headers.rs  - 'ext.get::<Protocol>().copied()' becomes
                            '.cloned()', because the open Protocol token is no
                            longer Copy.
  * src/client/connection.rs - the client driver no longer refuses a
                            server-initiated bidirectional stream with the
                            H3_STREAM_CREATION_ERROR connection error of
                            RFC 9114, section 6.1. The SSH3 protocol carries
                            its own channels on those streams (the reverse
                            forwarding bridges the server opens towards the
                            client), and the SSH3 layer accepts them on the
                            raw QUIC connection, exactly like the reference
                            implementation does: the HTTP/3 layer must not
                            consume them, and it must not kill the connection
                            because of them.

Apply with: patch -p1 -d <h3-0.0.8 source tree> < h3-0.0.8.patch
Verify with: scripts/verify-h3-shim.sh

HEADER

cat "${WORK_DIR}/h3.patch" >> "${REPO_ROOT}/patches/h3-${H3_VERSION}.patch"
echo "--- wrote patches/h3-${H3_VERSION}.patch ---"
