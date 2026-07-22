#!/usr/bin/env bash
#
# Put TTD-capable dbgeng DLLs where smalldbg can load them, by copying them out
# of an installed WinDbg.
#
# Background: dbgeng.dll cannot be loaded in-process directly from the installed
# WinDbg (its MSIX package dir is ACL-blocked — ERROR_ACCESS_DENIED), but the
# package files are readable and can be copied to a normal directory. smalldbg
# looks for a loadable dbgeng in this order (first hit wins):
#   1. $SMALLDBG_DBGENG_DIR
#   2. <exe_dir>/windbg_dlls/<arch>
#   3. %LOCALAPPDATA%/smalldbg/windbg_dlls/<arch>
#
# Default action: install the DLLs into (3) for the current user — run this once
# on a machine that has WinDbg and TTD works everywhere for that user.
# With --zip: instead build a portable bundle matching (2), to unpack next to a
# smalldbg executable on a machine that has no WinDbg of its own.
#
# Runs under Git Bash / MSYS2 on Windows. Usage:
#   tools/pack_windbg_dlls.sh [-a amd64|arm64|x86] [--zip [out.zip]] [-d <windbg-dir>]
#
#   -a  Architecture to copy (default amd64). Must match the smalldbg exe.
#   --zip [out.zip]  Build a bundle zip instead of installing for the user.
#   -d  Explicit WinDbg install dir (the folder containing the amd64/ arm64/
#       subfolders). If omitted, it is auto-detected via Get-AppxPackage.
set -euo pipefail

arch="amd64"
mode="install"
out=""
windbg_dir=""

while [ $# -gt 0 ]; do
    case "$1" in
        -a|--arch) arch="$2"; shift 2 ;;
        -z|--zip)
            mode="zip"; shift
            if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then out="$1"; shift; fi ;;
        -d|--windbg-dir) windbg_dir="$2"; shift 2 ;;
        -h|--help) grep '^#' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

case "$arch" in amd64|arm64|x86) ;; *) echo "invalid --arch: $arch" >&2; exit 2 ;; esac

command -v cygpath >/dev/null 2>&1 || { echo "cygpath not found — run this under Git Bash / MSYS2." >&2; exit 1; }

# Resolve the WinDbg install directory.
if [ -z "$windbg_dir" ]; then
    win=$(powershell.exe -NoProfile -NonInteractive -Command \
        "(Get-AppxPackage Microsoft.WinDbg | Select-Object -First 1).InstallLocation" 2>/dev/null | tr -d '\r')
    [ -n "$win" ] || { echo "WinDbg not found (no Microsoft.WinDbg AppX package). Install it from the Microsoft Store, or pass -d <windbg-dir>." >&2; exit 1; }
    windbg_dir=$(cygpath -u "$win")
fi
echo "WinDbg install: $windbg_dir"

arch_dir="$windbg_dir/$arch"
[ -f "$arch_dir/dbgeng.dll" ] || { echo "dbgeng.dll not found under $arch_dir (this WinDbg may not ship $arch binaries)." >&2; exit 1; }

# copy_engine <dest-dir>: copy the engine DLLs + ttd/ replay subtree into dest.
copy_engine() {
    local dest="$1"
    mkdir -p "$dest"
    local name
    for name in dbgeng.dll dbgcore.dll dbghelp.dll dbgmodel.dll msdia140.dll symsrv.dll; do
        if [ -f "$arch_dir/$name" ]; then
            cp "$arch_dir/$name" "$dest/"
            echo "  + $arch/$name"
        fi
    done
    if [ -d "$arch_dir/ttd" ]; then
        cp -r "$arch_dir/ttd" "$dest/"
        echo "  + $arch/ttd/ ($(find "$arch_dir/ttd" -type f | wc -l | tr -d ' ') files)"
    else
        echo "  ! no ttd/ folder under $arch_dir — supports normal debugging but not TTD replay." >&2
    fi
}

if [ "$mode" = "install" ]; then
    lap=$(cygpath -u "${LOCALAPPDATA:?LOCALAPPDATA not set}")
    dest="$lap/smalldbg/windbg_dlls/$arch"
    rm -rf "$dest"
    copy_engine "$dest"
    echo ""
    echo "Installed to $dest"
    echo "smalldbg will now load TTD dbgeng from there for your user account."
    exit 0
fi

# --zip: stage into <tmp>/windbg_dlls/<arch> so the archive's top entry matches
# smalldbg's <exe_dir>/windbg_dlls/<arch> layout.
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
copy_engine "$stage/windbg_dlls/$arch"

[ -n "$out" ] || out="windbg_dlls-$arch.zip"
out_dir=$(cd "$(dirname "$out")" && pwd)
out_abs="$out_dir/$(basename "$out")"
rm -f "$out_abs"

# Prefer 'zip'; fall back to the in-box system bsdtar (tar.exe), which can write
# zip archives on Windows 10+.
if command -v zip >/dev/null 2>&1; then
    ( cd "$stage" && zip -qr "$out_abs" windbg_dlls )
else
    bsdtar="$(cygpath -u "${WINDIR:-C:\\Windows}")/System32/tar.exe"
    [ -x "$bsdtar" ] || { echo "neither 'zip' nor the system tar.exe (bsdtar) is available to create the archive." >&2; exit 1; }
    "$bsdtar" -c -f "$(cygpath -w "$out_abs")" --format=zip -C "$(cygpath -w "$stage")" windbg_dlls
fi

echo ""
echo "Wrote $out_abs"
echo "Unpack it next to your smalldbg executable so <exe_dir>/windbg_dlls/$arch/dbgeng.dll exists."
