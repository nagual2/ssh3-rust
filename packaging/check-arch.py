#!/usr/bin/env python3
# Copyright 2026 The nagual2 ssh3 Authors.
# SPDX-License-Identifier: Apache-2.0
"""Check that the release binaries are built for the expected target.

The release matrix cross compiles part of the targets, so a mistake in the
toolchain of a leg (a stale toolchain, a wrong linker, a target that was not
installed) would publish a binary of the wrong architecture under a name
that promises another one. The script reads the machine type out of the
header of the binary (ELF, PE or Mach-O) and compares it with the target of
the matrix leg.

Usage:
    packaging/check-arch.py <target> <directory>
"""

from __future__ import annotations

import os
import struct
import sys

# The expected (format, machine) pair of every target of the release matrix.
# The machine numbers are the ones of the respective headers: ELF e_machine,
# the IMAGE_FILE_MACHINE_* values of PE and the cputype of Mach-O.
EXPECTED: dict[str, tuple[str, int]] = {
    "x86_64-unknown-linux-gnu": ("elf", 62),
    "aarch64-unknown-linux-gnu": ("elf", 183),
    "x86_64-pc-windows-msvc": ("pe", 0x8664),
    "x86_64-apple-darwin": ("macho", 0x01000007),
    "aarch64-apple-darwin": ("macho", 0x0100000C),
}

BINARIES = ("ssh3", "ssh3-rust-server")


def detect(path: str) -> tuple[str, int]:
    """Returns the (format, machine) pair of the binary at `path`."""
    with open(path, "rb") as handle:
        head = handle.read(64)
        if head[:4] == b"\x7fELF":
            return "elf", struct.unpack_from("<H", head, 18)[0]
        if head[:2] == b"MZ":
            offset = struct.unpack_from("<I", head, 0x3C)[0]
            handle.seek(offset + 4)
            return "pe", struct.unpack_from("<H", handle.read(2), 0)[0]
        if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
            return "macho", struct.unpack_from("<I", head, 4)[0]
    return "unknown", 0


def main(argv: list[str]) -> int:
    """Checks the binaries of the given target."""
    if len(argv) != 3:
        print(f"usage: {argv[0]} <target> <directory>", file=sys.stderr)
        return 2

    target, directory = argv[1], argv[2]
    if target not in EXPECTED:
        print(f"error: unknown target '{target}'", file=sys.stderr)
        return 2

    expected_format, expected_machine = EXPECTED[target]
    for name in BINARIES:
        path = ""
        for candidate in (os.path.join(directory, name), os.path.join(directory, f"{name}.exe")):
            if os.path.isfile(candidate):
                path = candidate
                break
        if not path:
            print(f"error: {name} is missing in {directory}", file=sys.stderr)
            return 1

        image_format, machine = detect(path)
        if (image_format, machine) != (expected_format, expected_machine):
            print(
                f"error: {path} is a {image_format} binary for the machine {machine:#x}, "
                f"but {target} needs a {expected_format} binary for {expected_machine:#x}",
                file=sys.stderr,
            )
            return 1
        print(f"{path}: {image_format} {machine:#x} (as expected for {target})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
