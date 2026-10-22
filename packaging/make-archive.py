#!/usr/bin/env python3
# Copyright 2026 The nagual2 ssh3 Authors.
# SPDX-License-Identifier: Apache-2.0
"""Build a reproducible release archive (tar.gz or zip).

The archives of a release must be bit-for-bit reproducible: the same commit,
built twice, has to produce the same archive. The script therefore fixes
every variable that a packer would otherwise take from the environment:

  * the modification time of every entry (the commit time of the tag, passed
    as `--source-date-epoch`);
  * the owner and the group of every entry (root);
  * the permissions of every entry (0755 for the executables, 0644 for the
    rest);
  * the order of the entries (the order of the command line);
  * the gzip header of the tarball (the epoch, not the wall clock).

The archives carry a single top level directory, so that an extraction does
not scatter the files over the current directory.
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import stat
import tarfile
import time
import zipfile
from pathlib import Path

EXECUTABLE_MODE = 0o755
REGULAR_MODE = 0o644


def _is_executable(path: Path) -> bool:
    """Tells whether the file is executable by its owner."""
    return bool(path.stat().st_mode & stat.S_IXUSR)


def build_tar_gz(output: Path, root_dir: str, files: list[Path], epoch: int) -> None:
    """Writes a deterministic gzip compressed tarball."""
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as gz:
        with tarfile.open(mode="w", fileobj=gz, format=tarfile.PAX_FORMAT) as tar:
            for path in files:
                info = tar.gettarinfo(str(path), arcname=f"{root_dir}/{path.name}")
                info.mtime = epoch
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mode = EXECUTABLE_MODE if _is_executable(path) else REGULAR_MODE
                with path.open("rb") as handle:
                    tar.addfile(info, handle)
    output.write_bytes(raw.getvalue())


def build_zip(output: Path, root_dir: str, files: list[Path], epoch: int) -> None:
    """Writes a deterministic zip archive."""
    date_time = time.gmtime(epoch)[:6]
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            info = zipfile.ZipInfo(filename=f"{root_dir}/{path.name}", date_time=date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # unix
            mode = EXECUTABLE_MODE if _is_executable(path) else REGULAR_MODE
            info.external_attr = (mode & 0xFFFF) << 16
            info.external_attr |= 0o100000 << 16  # regular file
            archive.writestr(info, path.read_bytes())


def main() -> int:
    """Parses the command line and writes the archive."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", required=True, choices=("tar.gz", "zip"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--root-dir", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()

    missing = [str(path) for path in args.files if not path.is_file()]
    if missing:
        parser.error(f"missing input files: {', '.join(missing)}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "tar.gz":
        build_tar_gz(args.output, args.root_dir, args.files, args.source_date_epoch)
    else:
        build_zip(args.output, args.root_dir, args.files, args.source_date_epoch)
    print(f"built {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
