#!/usr/bin/env bash
# Build the IP Scan ACAP (.eap) for every Axis camera family from one source.
#
#   ./build.sh               # all four packages (default)
#   ./build.sh aarch64       # ARTPEC-8/9, CV25 ...        AXIS OS 10 - 12+
#   ./build.sh armv7hf       # ARTPEC-6/7, S2L/S5L ...     AXIS OS 9 - 12+
#   ./build.sh artpec4|artpec5                             AXIS OS 9.x (classic, MIPS)
#   ./build.sh test          # vet + unit tests + qemu tests of every binary and launcher
#
# Output: dist/ipscan_<ver>_<target>.eap
#
# Every package is "dual mode", like the ones the official SDK produces:
#   * manifest.json  -> used by AXIS OS 10.6+ (systemd, reverseProxy/fastCgi)
#   * package.conf   -> used by older AXIS OS (classic init scripts); the
#     postinstall.sh then wires Apache mod_proxy_http to the daemon's socket.
# The package-root binary is always a tiny ET_DYN (PIE) launcher that execve()s
# the static Go daemon in bin/, because the classic start scripts refuse to run
# anything that isn't ET_DYN, and Go can only emit a PIE on arm/mips with cgo.
#
# Requirements:
#   - Go >= 1.24.1 (the MIPS build needs the golang/go#71591 fix). Stdlib only.
#   - cross gcc/binutils for the launchers (Debian/Ubuntu packages):
#       gcc-aarch64-linux-gnu  gcc-arm-linux-gnueabihf  gcc-mipsel-linux-gnu
#   - test only: qemu-user-static, libc6-arm64-cross, libc6-armhf-cross, curl.
set -euo pipefail

APP=ipscan
FRIENDLY="IP Scan"
VENDOR="Filipe Brigido 2026"
VER_MAJOR=1; VER_MINOR=1; VER_MICRO=1
VERSION="${VER_MAJOR}.${VER_MINOR}.${VER_MICRO}"
INSTALL_DIR="/usr/local/packages/${APP}"   # where every AXIS OS installs ACAPs
REAL_BIN="${INSTALL_DIR}/bin/${APP}"       # the static Go daemon (launcher target)

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="${ROOT}/dist"
WORK="${ROOT}/out"
GO="${GO:-go}"

log(){ printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
mkdir -p "$DIST" "$WORK"

# target -> APPTYPE / GOARCH / sub-arch / cross gcc
apptype(){ case "$1" in aarch64) echo aarch64;; armv7hf) echo armv7hf;; *) echo mipsisa32r2el;; esac; }
larch(){   case "$1" in aarch64) echo aarch64;; armv7hf) echo armv7hf;; *) echo mips;; esac; }

# ---- Go daemon (static, no cgo) ----------------------------------------------
build_go(){ # $1 = launcher arch (aarch64|armv7hf|mips)
  local la="$1" out="$WORK/$APP-$1" envs=(CGO_ENABLED=0 GOOS=linux)
  [ -f "$out" ] && return
  case "$la" in
    aarch64) envs+=(GOARCH=arm64) ;;
    armv7hf) envs+=(GOARCH=arm GOARM=7) ;;
    mips)    envs+=(GOARCH=mipsle GOMIPS=softfloat) ;;
  esac
  log "go build $la"
  ( cd "$ROOT/app" && env "${envs[@]}" "$GO" build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.flavor=${la}" -o "$out" . )
}

# ---- launcher (ET_DYN stub that execve()s $REAL_BIN) --------------------------
build_launcher(){ # $1 = aarch64|armv7hf|mips
  local la="$1" out="$WORK/launcher-$1" cc src="$WORK/launch-$1.S"
  [ -f "$out" ] && return
  case "$la" in
    aarch64) cc="${CC_AARCH64:-aarch64-linux-gnu-gcc}"
             sed "s#@REAL_BIN@#${REAL_BIN}#g" "$ROOT/launcher/launch-aarch64.S" > "$src" ;;
    armv7hf) cc="${CC_ARMHF:-arm-linux-gnueabihf-gcc}"
             sed "s#@REAL_BIN@#${REAL_BIN}#g" "$ROOT/launcher/launch-armv7hf.S" > "$src" ;;
    mips)    cc="${CC_MIPS:-mipsel-linux-gnu-gcc}"
             python3 "$ROOT/launcher/gen-mips.py" "$REAL_BIN" > "$src" ;;
  esac
  command -v "$cc" >/dev/null || die "$cc not found (see requirements at the top of build.sh)"
  log "launcher $la ($cc)"
  local flags=(-nostdlib -nostartfiles -pie -Wl,-e,_start -Wl,--hash-style=both -Wl,-z,noexecstack)
  [ "$la" = mips ] && flags=(-march=mips32r2 -mabi=32 -EL "${flags[@]}")
  "$cc" "${flags[@]}" -o "$out" "$src"
  # the whole point: ET_DYN, an interpreter, no NEEDED libraries, no relocations
  readelf -h "$out" | grep -q 'DYN'                    || die "launcher-$la is not ET_DYN"
  readelf -l "$out" | grep -q 'program interpreter'    || die "launcher-$la has no PT_INTERP"
  ! readelf -d "$out" | grep -q NEEDED                 || die "launcher-$la has NEEDED libs"
  readelf -r "$out" | grep -q 'no relocations'         || die "launcher-$la has relocations"
}

# ---- package -------------------------------------------------------------------
pack(){ # $1 = aarch64|armv7hf|artpec4|artpec5
  local t="$1" la at stage="$WORK/stage-$1" name
  la="$(larch "$t")"; at="$(apptype "$t")"
  build_go "$la"; build_launcher "$la"
  rm -rf "$stage"; mkdir -p "$stage/bin" "$stage/html"

  cp "$WORK/launcher-$la" "$stage/$APP"
  cp "$WORK/$APP-$la"     "$stage/bin/$APP"
  cp "$ROOT/app/html/index.html" "$stage/html/"
  cp "$ROOT/app/LICENSE" "$ROOT"/packaging/{cgi.txt,param.conf,postinstall.sh,zz_${APP}_proxy.conf} "$stage/"
  sed -e "s/@APPTYPE@/$at/" -e "s/@MAJ@/$VER_MAJOR/" -e "s/@MIN@/$VER_MINOR/" -e "s/@MIC@/$VER_MICRO/" \
      "$ROOT/packaging/package.conf.in" > "$stage/package.conf"
  chmod 755 "$stage/$APP" "$stage/bin/$APP" "$stage/postinstall.sh"

  local files=(package.conf cgi.txt param.conf LICENSE "$APP" bin html postinstall.sh "zz_${APP}_proxy.conf")
  if [ "$la" != mips ]; then  # ARTPEC-4/5 never run AXIS OS 10+, so no manifest there
    python3 - "$ROOT/app/manifest.json" "$stage/manifest.json" "$at" "$VERSION" <<'PY'
import json, sys
src, dst, arch, ver = sys.argv[1:]
m = json.load(open(src))
m["acapPackageConf"]["setup"]["version"] = ver
m["acapPackageConf"]["setup"]["architecture"] = arch   # what acap-build adds
json.dump(m, open(dst, "w"), indent=2)
PY
    files=(manifest.json "${files[@]}")
  fi

  case "$t" in
    aarch64|armv7hf) name="${APP}_${VER_MAJOR}_${VER_MINOR}_${VER_MICRO}_${t}.eap" ;;
    *)               name="${APP}_${VER_MAJOR}_${VER_MINOR}_${VER_MICRO}_${t}_mipsisa32r2el.eap" ;;
  esac
  ( cd "$stage" && tar --numeric-owner --owner=0 --group=0 -czf "$DIST/$name" "${files[@]}" )
  log "built $name ($(stat -c%s "$DIST/$name") bytes)"
}

# ---- tests ----------------------------------------------------------------------
QEMU_aarch64="qemu-aarch64-static -L /usr/aarch64-linux-gnu"
QEMU_armv7hf="qemu-arm-static -L /usr/arm-linux-gnueabihf"
QEMU_mips="qemu-mipsel-static -L /usr/mipsel-linux-gnu"

# The launcher must hand PID/argv/env to $REAL_BIN. qemu-user cannot follow an
# execve into another foreign binary, so a host shell script stands in for the
# daemon at a scratch copy of the path.
test_launcher(){ # $1 = arch
  local la="$1" dir; dir="$(mktemp -d)"
  local path="$dir/bin/$APP" src="$WORK/tlaunch-$la.S" out="$WORK/tlauncher-$la" cc
  mkdir -p "$dir/bin"
  printf '#!/bin/sh\necho "args=$* X=$X"\n' > "$path"; chmod +x "$path"
  case "$la" in
    aarch64) cc="${CC_AARCH64:-aarch64-linux-gnu-gcc}"; sed "s#@REAL_BIN@#$path#g" "$ROOT/launcher/launch-aarch64.S" > "$src" ;;
    armv7hf) cc="${CC_ARMHF:-arm-linux-gnueabihf-gcc}"; sed "s#@REAL_BIN@#$path#g" "$ROOT/launcher/launch-armv7hf.S" > "$src" ;;
    mips)    cc="${CC_MIPS:-mipsel-linux-gnu-gcc}"; python3 "$ROOT/launcher/gen-mips.py" "$path" > "$src" ;;
  esac
  local flags=(-nostdlib -nostartfiles -pie -Wl,-e,_start -Wl,--hash-style=both -Wl,-z,noexecstack)
  [ "$la" = mips ] && flags=(-march=mips32r2 -mabi=32 -EL "${flags[@]}")
  "$cc" "${flags[@]}" -o "$out" "$src"
  local q="QEMU_$la"; local got
  got="$(X=42 ${!q} "$out" a "b c" 2>&1 || true)"
  rm -rf "$dir"
  [ "$got" = "args=a b c X=42" ] && echo "   launcher $la: exec + argv + env OK" || die "launcher $la: got '$got'"
}

smoke(){ # $1 = arch : run the daemon on a Unix socket (classic path) and on TCP
  local la="$1" q="QEMU_$1" sock port=22$((RANDOM%80+10))
  sock="$(mktemp -u)"
  IPSCAN_SOCKET="$sock" IPSCAN_LOG=/dev/null ${!q} "$WORK/$APP-$la" >/dev/null 2>&1 & local p=$!
  sleep 3
  local c=(curl -s --max-time 20 --unix-socket "$sock")
  printf '   daemon %-8s unix info: ' "$la"; "${c[@]}" "http://x/control.cgi?op=info" | grep -oE '"arch":"[a-z0-9]+"|"version":"[0-9.]+"' | tr '\n' ' '; echo
  "${c[@]}" -XPOST "http://x/control.cgi?op=start" -d '{"targets":"127.0.0.1-3","ports":"22,80","timeoutMs":400}' >/dev/null
  sleep 4
  printf '   daemon %-8s scan:      ' "$la"; "${c[@]}" "http://x/control.cgi?op=status" | grep -oE '"state":"[a-z]+"|"alive":[0-9]+' | head -2 | tr '\n' ' '; echo
  printf '   daemon %-8s tcp api/:  ' "$la"; curl -s --max-time 5 "http://127.0.0.1:2202/local/$APP/api/info" | grep -oE '"ok":true' || echo "(no tcp)"
  kill "$p" 2>/dev/null; wait "$p" 2>/dev/null || true; rm -f "$sock"
}

run_tests(){
  log "go vet + unit tests"
  ( cd "$ROOT/app" && "$GO" vet ./... && "$GO" test ./... )
  for t in aarch64 armv7hf artpec5; do pack "$t"; done
  log "launcher tests (qemu)"
  for la in aarch64 armv7hf mips; do test_launcher "$la"; done
  log "daemon tests (qemu)"
  for la in aarch64 armv7hf mips; do smoke "$la"; done
}

rm -f "$WORK"/{launcher-*,"$APP"-*}   # always rebuild binaries from the current source
target="${1:-all}"
case "$target" in
  aarch64|armv7hf|artpec4|artpec5) pack "$target" ;;
  all)  for t in aarch64 armv7hf artpec4 artpec5; do pack "$t"; done ;;
  test) run_tests ;;
  *) echo "usage: $0 [all|aarch64|armv7hf|artpec4|artpec5|test]"; exit 1 ;;
esac
log "done — packages in dist/"
ls -1 "$DIST"
