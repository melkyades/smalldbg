#!/usr/bin/env bash
# Builds smalldbg in Release into a directory, the way the README says.
#
#   .github/build.sh <dir> <conan arch> [<Visual Studio platform>]
#
# The Visual Studio platform is given on Windows only; elsewhere the build
# uses Ninja.
set -euo pipefail

dir=$1
conan_arch=$2
vs_platform=${3:-}

conan install . --output-folder="$dir" --build=missing \
    -s build_type=Release -s arch="$conan_arch"

if [ -n "$vs_platform" ]; then
    cmake -S . -B "$dir" -A "$vs_platform" \
        -DCMAKE_TOOLCHAIN_FILE="$dir/conan_toolchain.cmake"
else
    cmake -S . -B "$dir" -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$dir/conan_toolchain.cmake" \
        -DCMAKE_BUILD_TYPE=Release
fi
cmake --build "$dir" --config Release --parallel
