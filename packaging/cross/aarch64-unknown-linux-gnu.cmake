# Copyright 2026 The nagual2 ssh3 Authors.
# SPDX-License-Identifier: Apache-2.0
#
# CMake toolchain file for the aarch64-unknown-linux-gnu cross build.
#
# The release pipeline cross compiles the aarch64 Linux artifacts on the
# x86_64 runner. The workspace depends on `aws-lc-sys`, which builds the TLS
# library from the C sources with cmake, so the cross toolchain has to be
# visible to cmake as well and not only to the Rust linker.
#
# The pipeline exports this file through `CMAKE_TOOLCHAIN_FILE`; the
# `aws-lc-sys` build script picks the variable up and configures cmake with
# it.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
set(CMAKE_AR aarch64-linux-gnu-ar)
set(CMAKE_RANLIB aarch64-linux-gnu-ranlib)
set(CMAKE_STRIP aarch64-linux-gnu-strip)

# The sysroot of the cross toolchain: the headers and the libraries of the
# target are not in the directories of the host.
set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)

# The programs (cmake, perl, nasm, ...) are the ones of the host, the
# libraries and the headers are the ones of the target.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
