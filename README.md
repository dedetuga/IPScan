# IP Scan — an Angry‑IP‑Scanner‑style LAN scanner as an ACAP for Axis cameras

A small ACAP application that runs on an Axis device and scans the network the
camera sits on, straight from the camera's web interface. It is the companion
to **[SSH Jump](https://github.com/dedetuga/SSHJump)** /
**[SSH Jump (Legacy)](https://github.com/dedetuga/SSHJumpLegacy)**: first find
the device (switch, AP, NVR, another camera…), then open an SSH session to it
with one click.

```
your browser ──HTTPS──> Axis camera web UI ──ICMP / TCP / ARP / NetBIOS / DNS / HTTP──> LAN
                        (reverse proxy + Axis admin authentication)
```

One source tree builds **all four** packages, each meant to cover AXIS OS
9.x through 12.x:

| Package | Cameras | AXIS OS |
|---|---|---|
| `ipscan_1_1_1_aarch64.eap` | ARTPEC‑8/9, CV25 … | 10.x – 12.x |
| `ipscan_1_1_1_armv7hf.eap` | ARTPEC‑6/7, S2L/S5L … | 9.x – 12.x |
| `ipscan_1_1_1_artpec4_mipsisa32r2el.eap` | ARTPEC‑4 | 9.x (classic, SSH install) |
| `ipscan_1_1_1_artpec5_mipsisa32r2el.eap` | ARTPEC‑5 | 9.x (classic, SSH install) |

Prebuilt packages are in [`dist/`](dist/); the 1.0.1 packages (AXIS OS 10.6+ only on ARM) are kept in `dist/1.0.1/`;
the others are attached to the GitHub releases.

### Test status

| | Verified on hardware | Verified in emulation (qemu) |
|---|---|---|
| 1.0.1 aarch64 | ✅ AXIS P3265‑LVE (ARTPEC‑8), via `api/` | ✅ |
| 1.0.0 | ✅ AXIS M3105‑L | ✅ |
| 1.0.1 armv7hf | ❌ did not start on an armv7hf camera (empty log) — fixed in 1.1.0 by the PIE launcher + `package.conf` path | ✅ |
| 1.1.1 (all four) | ⏳ not yet | ✅ daemon, both transports, launchers; Apache 2.4.58 proxy config |

## How one package runs on AXIS OS 9 … 12

| AXIS OS | Reads | Starts the app via | Web route to the daemon |
|---|---|---|---|
| 9.x – 10.5 | `package.conf` | classic init script (only accepts **ET_DYN** binaries) | `postinstall.sh` (runs as root) installs an Apache `mod_proxy_http` rule: `/local/ipscan/control.cgi` → `unix:/var/run/http/ipscan/http` |
| 10.6 – 11.7 | `manifest.json` | systemd | `httpConfig` **fastCgi**: `control.cgi` → FastCGI on `$FCGI_SOCKET_NAME` |
| 11.8 – 12.x | `manifest.json` | systemd | `reverseProxy`: `/local/ipscan/api/` → `http://localhost:2202` (the daemon listens on **127.0.0.1 and ::1** — on AXIS OS 12 Apache resolves `localhost` to ::1, which is why 1.0.0 got a 503), plus fastCgi as above |

* The package‑root `ipscan` is a ~1 KB **PIE launcher** (freestanding asm, no
  libc, no relocations; `launcher/`) that `execve()`s the static Go daemon at
  `bin/ipscan` keeping PID/argv/env. Classic start scripts refuse static Go
  binaries (ET_EXEC) and Go can only make a PIE for arm/mips with cgo — this
  is the SSH Jump (Legacy) trick, now used for all architectures. If the exec
  fails the launcher writes `ipscan launcher: cannot exec …` to the log.
* The daemon opens every transport that applies (TCP 127.0.0.1/::1:2202,
  FastCGI on `$FCGI_SOCKET_NAME`, or the classic Unix socket) and logs each
  `listening on …` line; the page probes `api/` then `control.cgi` and keeps
  the one that answers.
* **One `mod_proxy` worker per app.** `mod_proxy` keys its workers on the URL
  after the `|` in `ProxyPass "unix:…|http://host/…"`, not on the socket. If two
  ACAPs both use `http://localhost/control.cgi`, Apache merges them into one
  worker and sends both apps' `control.cgi` to the same daemon. IP Scan
  therefore uses `http://ipscan.acap/control.cgi` (the Host is cosmetic; the
  daemon routes on `?op=`). Verified on Apache 2.4.58 next to an app that still
  uses `localhost`. Any other classic ACAP should use its own `<app>.acap` host.
* `package.conf` asks for embedded SDK 2.0 (so AXIS OS 9 accepts it);
  `manifest.json` uses schema 1.3.0 (AXIS OS 10.9+ validates it; the
  architecture field is filled per package).

## What it shows (per host)

| Column | How it is obtained |
|---|---|
| **Status** (dot colour) | ICMP echo, TCP knocks (an accepted **or refused** connection proves the host is up), NetBIOS reply, and finally the kernel **ARP table** — a host that drops ping *and* every port still answers ARP on the camera's own subnet |
| **Ping** | ICMP round‑trip time (or TCP connect time when ICMP isn't available) |
| **Hostname** | reverse DNS (PTR), falling back to the NetBIOS name; workgroup shown too |
| **MAC address** | kernel ARP table (same subnet), or the NetBIOS node‑status reply |
| **Vendor** | embedded IEEE OUI / MA‑M / MA‑S table (~54k prefixes, offline) |
| **Open ports** | TCP connect scan of your port list (presets for cameras/NVRs, network gear, web) |
| **Web** | `GET /` on the first web port: page `<title>` and `Server` header, same‑host redirects followed, self‑signed TLS accepted |

UI features: IP range as `a.b.c.d/nn`, `a.b.c.d-e.f.g.h`, `a.b.c.d-nn`, single
IPs or hostnames (mixed, comma/space/newline separated, up to a /16 per scan);
one‑click chips with the camera's own subnet(s); threads and timeout; live
progress; sort by any column; filter; *show dead hosts*; **CSV export**;
clickable web ports; and **port 22 → "SSH" opens SSH Jump pre‑filled** when
SSH Jump is installed on the same camera. Reloading the page (or opening it in
another browser) shows the running / last scan.

## 1. Install

### aarch64 / armv7hf (web UI, AXIS OS 9 – 12)

1. Camera web UI → **Apps**. On AXIS OS 11/12 enable **"Allow unsigned apps"**
   (or sign the `.eap`, see SSH Jump's README §5 — identical procedure; AXIS
   OS 13+ requires signing).
2. **Add app** → upload `ipscan_1_1_1_aarch64.eap` (ARTPEC‑8+) or
   `ipscan_1_1_1_armv7hf.eap` (ARTPEC‑6/7). A wrong architecture is rejected
   at upload, so if unsure just try.
3. **Enable/Start** the app, then **Open**. On AXIS OS 9.x/10.0–10.5 the
   install script also restarts Apache — wait ~10 s before opening the page.

### ARTPEC‑4 / ARTPEC‑5 (classic ACAP, over SSH)

Exactly like SSH Jump (Legacy) — the web‑UI installer can't install on this
hardware (ACAP framework 2.x):

```bash
scp dist/ipscan_1_1_1_artpec5_mipsisa32r2el.eap packaging/install-dev.sh root@<camera>:/tmp/
ssh root@<camera> 'CAM_PASS=<root password> sh /tmp/install-dev.sh'
```

Then open `http://<camera>/local/ipscan/index.html` (admin login). The package
is self‑configuring (`postinstall.sh` wires the `mod_proxy_http` route and
restarts Apache), so a plain `install-package.sh install` also works.

## 2. Usage

1. The **IP range** is pre‑filled with the camera's subnet; the chips under it
   list every network the camera is on.
2. Pick a **port preset** (or *Custom…*: `22,80,443,8000-8100`).
3. **Start scan.** Live hosts appear as they are found.
4. Click a web port to open it (only works if your browser can route to the
   LAN), or **22 ⟶ SSH** to open the SSH Jump terminal on that host.
5. **Export CSV** exports the alive hosts (all scanned addresses when *Show dead* is on).

Defaults: 64 threads (32 on ARMv7 and MIPS), 1000 ms timeout. A /24 takes a few
seconds; a /16 takes minutes — dead addresses each cost one timeout.

### Liveness and ICMP

ACAPs run as an unprivileged user, and on many AXIS OS versions unprivileged
ICMP ("ping sockets", `net.ipv4.ping_group_range`) is not allowed. The app
detects what is available and shows it in the side panel:

* `ICMP (raw)` / `ICMP (dgram)` + TCP + ARP — full detection;
* `TCP + ARP (ICMP not permitted)` — still finds every host on the camera's
  subnet (ARP), and hosts on other subnets that answer any knocked TCP port
  (80, 443, 22, 445, 554, 139, 8080, 23 + your first ports).

Hosts found **only** through ARP are shown with an amber dot and "arp" in the
Ping column: they exist but drop ping and every probed port.

## 3. Security / auto‑stop

- The backend listens only on loopback (`127.0.0.1`/`::1` port 2202) and local
  Unix sockets; all access goes through the camera's Apache with Axis
  authentication and TLS, **admin only**.
- One scan at a time; results live in memory only.
- **30 minutes without activity** (no scan running, no start/stop/export) → the
  app stops itself (`runMode`/`STARTMODE` `once`, so it stays stopped until
  re‑enabled). Just having the page open does not count as activity.
- Limits: a /16 (65 536 addresses) per scan, 1 024 ports, 256 threads; a
  global socket budget keeps it inside the process' file‑descriptor limit.
- Only scan networks you own or are authorised to administer.

Environment variables (for development / advanced use):

| Var | Default | Meaning |
|---|---|---|
| `IPSCAN_IDLE_TIMEOUT` | `30m` | idle time before auto‑stop |
| `IPSCAN_LISTEN` | `127.0.0.1:2202` + `[::1]:2202` | replace the loopback TCP listeners (debugging) |
| `IPSCAN_SOCKET` | `/var/run/http/ipscan/http` | classic Unix socket (HTTP + FastCGI), used when `FCGI_SOCKET_NAME` is unset |
| `IPSCAN_ICMP` | auto | `raw`, `dgram` or `off` |
| `IPSCAN_LOG` | `/tmp/ipscan.log` | log file (also mirrored to the Axis system log) |
| `IPSCAN_DEBUG` | — | `1` = verbose request tracing |
| `IPSCAN_HTML` | — | dev only: also serve the UI from `$IPSCAN_HTML/<app>/` |

## 4. SSH Jump integration

IP Scan links port 22 (and 2222) to
`/local/sshjump/index.html?host=<ip>&port=<port>` (or `config.html`, SSH Jump
Legacy's page name — whichever exists). For SSH Jump to **pre‑fill** the host, apply the small patch in
[`integration/`](integration/) to each SSH Jump repo and rebuild:

```bash
cd SSHJump       && git apply ../IPScan/integration/sshjump-prefill.patch
cd SSHJumpLegacy && git apply ../IPScan/integration/sshjumplegacy-prefill.patch
```

It only reads `host`, `port` and `user` from the URL and fills the form;
nothing is submitted and no credentials ever travel in the URL. Without the
patch the link still opens SSH Jump, just with an empty form.

> **SSH Jump on AXIS OS 11/12:** the 503 that limits SSH Jump to "AXIS OS < 11"
> is very likely the same `localhost` → `::1` issue: SSH Jump listens only on
> `127.0.0.1:2201`. Listening on `[::1]:2201` too (as IP Scan does) should fix it.

## 5. Build

```bash
./build.sh                 # all four .eap → dist/
./build.sh aarch64|armv7hf|artpec4|artpec5
./build.sh test            # go vet + unit tests + qemu tests of launchers and daemons
```

Requirements: **Go ≥ 1.24.1** (the MIPS build needs the golang/go#71591 fix).
Standard library only — no third‑party Go modules, no network needed. Cross
gcc for the launchers (Debian/Ubuntu): `gcc-aarch64-linux-gnu
gcc-arm-linux-gnueabihf gcc-mipsel-linux-gnu`. For `./build.sh test` also
`qemu-user-static libc6-arm64-cross libc6-armhf-cross` and `curl`.

With the official Axis SDK (produces a manifest‑only package, i.e. AXIS OS
10.6+ — `build.sh` is the one that covers AXIS OS 9):

```bash
DOCKER_BUILDKIT=1 docker build --build-arg GOARCH=arm64 --build-arg SDK_ARCH=aarch64 -o type=local,dest=./out .
```

The MAC‑vendor table (`app/oui.txt.gz`) is regenerated with:

```bash
npm pack oui-data && tar xzf oui-data-*.tgz
python3 tools/gen-oui.py package/index.json app/oui.txt.gz
```

## Layout

```
app/
  main.go        HTTP API, transports (TCP / FastCGI / Unix HTTP+FastCGI), idle watchdog
  scan.go        range/port parsing, scan engine, per-host probing, CSV
  icmp.go        ICMP echo via raw or unprivileged ping socket
  probes.go      ARP table, NetBIOS node status, web detect, local networks, OUI lookup
  oui.txt.gz     embedded MAC vendor table
  html/index.html  the UI
  manifest.json, Makefile, LICENSE
launcher/        PIE launcher stubs: launch-aarch64.S, launch-armv7hf.S, gen-mips.py
packaging/       package.conf.in, cgi.txt, param.conf, postinstall.sh,
                 zz_ipscan_proxy.conf, install-dev.sh (SSH install, ARTPEC-4/5)
integration/     SSH Jump URL-prefill patches
tools/gen-oui.py MAC vendor table generator
build.sh, Dockerfile
dist/            prebuilt .eap packages
```

## API (for scripting)

`https://<camera>/local/ipscan/api/<op>` (AXIS OS 11.8+) or
`https://<camera>/local/ipscan/control.cgi?op=<op>` (all other versions,
and 10.6+ too) — admin auth either way.

| op | method | |
|---|---|---|
| `info` | GET | networks, suggested range, ICMP mode, limits, idle state |
| `start` | POST | JSON `{targets, ports, threads, timeoutMs, dns, netbios, web}` → `{id, total}` |
| `status` | GET | `id`, `since=N` → progress + hosts finished since N (`next` = new cursor) |
| `stop` | POST | stop the current scan |
| `export` | GET | CSV (alive hosts; `all=1` for all) |

## License

See [`app/LICENSE`](app/LICENSE) — application license plus the Go and
oui‑data licenses.

Not affiliated with, endorsed by, or sponsored by Axis Communications AB, or
with the Angry IP Scanner project. "Axis", "AXIS OS", "ACAP" and "ARTPEC" are
trademarks of Axis Communications AB.
