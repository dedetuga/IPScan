#!/usr/bin/env bash
# Build the IP Scan ACAP (.eap) for every Axis camera family from one source.
#
#   ./build.sh               # everything (default)
#   ./build.sh modern        # aarch64 + armv7hf   (AXIS OS 10+, manifest.json)
#   ./build.sh aarch64       # ARTPEC-8 / newer
#   ./build.sh armv7hf       # ARTPEC-6 / ARTPEC-7
#   ./build.sh legacy        # artpec4 + artpec5   (classic package.conf, MIPS)
#   ./build.sh artpec4|artpec5
#   ./build.sh test          # unit tests + qemu smoke test of every binary
#
# Output: dist/ipscan_<ver>_<target>.eap
#
# Requirements:
#   - Go >= 1.24.1 (the legacy MIPS build needs the golang/go#71591 fix; modern
#     builds work with Go >= 1.21). No third-party Go modules: stdlib only.
#   - legacy only: mipsel-linux-gnu-gcc + binutils (Debian/Ubuntu:
#     gcc-mipsel-linux-gnu) for the tiny PIE launcher.
#   - test only: qemu-user-static.
set -euo pipefail

APP=ipscan
FRIENDLY="IP Scan"
VENDOR="Filipe Brigido 2026"
VER_MAJOR=1; VER_MINOR=0; VER_MICRO=1
VERSION="${VER_MAJOR}.${VER_MINOR}.${VER_MICRO}"

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="${ROOT}/dist"
WORK="${ROOT}/out"
GO="${GO:-go}"
CC_MIPS="${CC_MIPS:-mipsel-linux-gnu-gcc}"

log(){ printf '\033[1;36m==>\033[0m %s\n' "$*"; }
mkdir -p "$DIST" "$WORK"

# ---- Go daemon ---------------------------------------------------------------
# $1 = output, $2 = GOARCH, $3 = GOARM/GOMIPS value, $4 = flavor (modern|legacy)
build_go(){
  local out="$1" goarch="$2" sub="$3" flavor="$4"
  local envs=(CGO_ENABLED=0 GOOS=linux GOARCH="$goarch")
  case "$goarch" in
    arm)    envs+=(GOARM="$sub") ;;
    mipsle) envs+=(GOMIPS="$sub") ;;
  esac
  log "go build ${goarch}${sub:+/$sub} (${flavor})"
  ( cd "$ROOT/app" && env "${envs[@]}" "$GO" build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.flavor=${flavor}" -o "$out" . )
}

# ---- modern .eap (manifest.json; AXIS OS 10+) --------------------------------
pack_modern(){
  local arch="$1" bin="$2" stage="$WORK/stage-$1"
  rm -rf "$stage"; mkdir -p "$stage"
  cp "$ROOT/app/manifest.json" "$ROOT/app/LICENSE" "$stage/"
  cp "$bin" "$stage/$APP"; chmod 0755 "$stage/$APP"
  cp -r "$ROOT/app/html" "$stage/html"
  : > "$stage/param.conf"
  # package.conf: legacy metadata mirror of manifest.json (as in SSH Jump)
  cat > "$stage/package.conf" <<EOF
PACKAGENAME="$FRIENDLY"
MENUNAME="$FRIENDLY"
APPTYPE="$arch"
APPNAME="$APP"
APPID=""
LICENSENAME="Available"
LICENSEPAGE="none"
VENDOR="$VENDOR"
REQEMBDEVVERSION="3.0"
APPMAJORVERSION="$VER_MAJOR"
APPMINORVERSION="$VER_MINOR"
APPMICROVERSION="$VER_MICRO"
APPGRP="sdk"
APPUSR="sdk"
APPOPTS=""
OTHERFILES="html LICENSE"
SETTINGSPAGEFILE="index.html"
SETTINGSPAGETEXT=""
VENDORHOMEPAGELINK=""
PREUPGRADESCRIPT=""
POSTINSTALLSCRIPT=""
STARTMODE="once"
HTTPCGIPATHS=""
EOF
  cp "$stage/package.conf" "$stage/package.conf.orig"
  local eap="$DIST/${APP}_${VER_MAJOR}_${VER_MINOR}_${VER_MICRO}_${arch}.eap"
  tar --numeric-owner --owner=0 --group=0 -C "$stage" -czf "$eap" \
      manifest.json package.conf package.conf.orig param.conf LICENSE "$APP" html
  log "built $(basename "$eap") ($(stat -c%s "$eap") bytes)"
}

build_modern(){
  case "$1" in
    aarch64) build_go "$WORK/$APP-aarch64" arm64 "" modern ;;
    armv7hf) build_go "$WORK/$APP-armv7hf" arm 7 modern ;;
  esac
  pack_modern "$1" "$WORK/$APP-$1"
}

# ---- legacy .eap (classic package.conf; ARTPEC-4/5, MIPS) ---------------------
# See SSH Jump (Legacy) for the full story. In short: elflibcheck.sh only starts
# ET_DYN binaries and Go cannot emit PIE for linux/mipsle, so the package-root
# binary is a freestanding MIPS PIE stub that execve()s the static Go daemon at
# bin/ipscan, preserving argv/env.
INSTALL_DIR="/usr/local/packages/${APP}"
REAL_BIN="${INSTALL_DIR}/bin/${APP}"

build_launcher(){
  log "generating PIE launcher for ${REAL_BIN}"
  python3 - "$REAL_BIN" > "$WORK/launch.S" <<'PY'
import sys
p = sys.argv[1].encode() + b'\0'
while len(p) % 4: p += b'\0'
words = [int.from_bytes(p[i:i+4], 'little') for i in range(0, len(p), 4)]
alloc = ((len(p) + 15)//16)*16
L = ['\t.abicalls', '\t.set\tnoreorder', '\t.text', '\t.globl\t__start',
     '\t.globl\t_start', '\t.ent\t_start', '_start:', '__start:',
     '\tlw\t$t0, 0($sp)',          # argc
     '\taddiu\t$a1, $sp, 4',       # argv
     '\taddiu\t$t1, $t0, 1',
     '\tsll\t$t1, $t1, 2',
     '\taddu\t$a2, $a1, $t1',      # envp = argv + (argc+1)*4
     '\taddiu\t$sp, $sp, -%d' % alloc]
for i, w in enumerate(words):
    L += ['\tli\t$t2, 0x%08x' % w, '\tsw\t$t2, %d($sp)' % (i*4)]
L += ['\tmove\t$a0, $sp',          # path
      '\tli\t$v0, 4011',           # __NR_execve (o32)
      '\tsyscall', '\tnop',
      '\tli\t$a0, 1', '\tli\t$v0, 4001',  # __NR_exit
      '\tsyscall', '\tnop', '\t.end\t_start']
sys.stdout.write('\n'.join(L) + '\n')
PY
  "$CC_MIPS" -march=mips32r2 -mabi=32 -EL -nostdlib -nostartfiles -pie \
    -Wl,-e,_start -o "$WORK/launcher-mips" "$WORK/launch.S"
  if command -v readelf >/dev/null; then
    readelf -h "$WORK/launcher-mips" | grep -q 'DYN' || { echo "launcher is not ET_DYN!"; exit 1; }
  fi
}

LEGACY_READY=0
build_legacy_bins(){
  [ "$LEGACY_READY" = 1 ] && return
  build_launcher
  build_go "$WORK/$APP-mipsle" mipsle softfloat legacy
  LEGACY_READY=1
}

pack_legacy(){
  local soc="$1" stage="$WORK/stage-$1"
  build_legacy_bins
  rm -rf "$stage"; mkdir -p "$stage/bin" "$stage/html"
  cp "$ROOT"/legacy/{package.conf,cgi.txt,param.conf,zz_${APP}_proxy.conf,postinstall.sh} "$stage/"
  cp "$ROOT/app/LICENSE" "$stage/"
  cp "$WORK/launcher-mips" "$stage/$APP"
  cp "$WORK/$APP-mipsle"   "$stage/bin/$APP"
  cp "$ROOT/app/html/index.html" "$stage/html/config.html"   # classic settings page name
  chmod 755 "$stage/$APP" "$stage/bin/$APP" "$stage/postinstall.sh"
  local eap="$DIST/${APP}_${VER_MAJOR}_${VER_MINOR}_${VER_MICRO}_${soc}_mipsisa32r2el.eap"
  ( cd "$stage" && tar --numeric-owner --owner=0 --group=0 -czf "$eap" \
      package.conf cgi.txt param.conf LICENSE "$APP" "zz_${APP}_proxy.conf" postinstall.sh bin html )
  log "built $(basename "$eap") ($(stat -c%s "$eap") bytes)"
}

# ---- smoke tests under qemu ----------------------------------------------------
smoke(){
  local name="$1" qemu="$2" bin="$3" mode="$4" port=22$((RANDOM%80+10))
  command -v "$qemu" >/dev/null || { echo "   (skip $name: $qemu not installed)"; return; }
  local sock; sock="$(mktemp -u)"
  if [ "$mode" = tcp ]; then
    IPSCAN_LISTEN=127.0.0.1:$port IPSCAN_LOG=/dev/null "$qemu" "$bin" >/dev/null 2>&1 & local p=$!
  else
    IPSCAN_SOCKET="$sock" IPSCAN_LOG=/dev/null "$qemu" "$bin" >/dev/null 2>&1 & local p=$!
  fi
  sleep 2
  local c=(curl -s --max-time 20)
  [ "$mode" = tcp ] && base="http://127.0.0.1:$port/local/ipscan/api" || { c+=(--unix-socket "$sock"); base="http://x/control.cgi?op="; }
  local u_info u_start u_status
  if [ "$mode" = tcp ]; then u_info="$base/info"; u_start="$base/start"; u_status="$base/status"
  else u_info="${base}info"; u_start="${base}start"; u_status="${base}status"; fi
  printf '   %-8s info:   ' "$name"; "${c[@]}" "$u_info" | head -c 90; echo
  "${c[@]}" -XPOST "$u_start" -d '{"targets":"127.0.0.1-3","ports":"22,80","timeoutMs":400,"web":false,"netbios":false,"dns":false}' >/dev/null
  sleep 4
  printf '   %-8s status: ' "$name"; "${c[@]}" "$u_status" | grep -oE '"state":"[a-z]+"|"alive":[0-9]+' | tr '\n' ' '; echo
  kill "$p" 2>/dev/null; wait "$p" 2>/dev/null || true; rm -f "$sock"
}

run_tests(){
  log "unit tests"
  ( cd "$ROOT/app" && "$GO" vet ./... && "$GO" test ./... )
  build_modern aarch64; build_modern armv7hf; pack_legacy artpec5
  log "qemu smoke tests"
  smoke aarch64 qemu-aarch64-static "$WORK/$APP-aarch64" tcp
  smoke armv7hf qemu-arm-static     "$WORK/$APP-armv7hf" tcp
  smoke mipsle  qemu-mipsel-static  "$WORK/$APP-mipsle"  unix
}

target="${1:-all}"
case "$target" in
  aarch64|armv7hf) build_modern "$target" ;;
  modern)          build_modern aarch64; build_modern armv7hf ;;
  artpec4|artpec5) pack_legacy "$target" ;;
  legacy)          pack_legacy artpec4; pack_legacy artpec5 ;;
  all)             build_modern aarch64; build_modern armv7hf; pack_legacy artpec4; pack_legacy artpec5 ;;
  test)            run_tests ;;
  *) echo "usage: $0 [all|modern|aarch64|armv7hf|legacy|artpec4|artpec5|test]"; exit 1 ;;
esac
log "done — packages in dist/"
ls -1 "$DIST"
