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

One source tree builds **all four** packages:

| Package | Cameras | Framework |
|---|---|---|
| `ipscan_1_0_0_aarch64.eap` | ARTPEC‑8 and newer | AXIS OS 10+ (`manifest.json`) |
| `ipscan_1_0_0_armv7hf.eap` | ARTPEC‑6 / ARTPEC‑7 | AXIS OS 10+ (`manifest.json`) |
| `ipscan_1_0_0_artpec4_mipsisa32r2el.eap` | ARTPEC‑4 | classic ACAP (`package.conf`), AXIS OS 9.x |
| `ipscan_1_0_0_artpec5_mipsisa32r2el.eap` | ARTPEC‑5 | classic ACAP (`package.conf`), AXIS OS 9.x |

Prebuilt packages are in [`dist/`](dist/).

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

### AXIS OS 10+ (aarch64 / armv7hf)

Same as SSH Jump:

1. Camera web UI → **Apps**. On AXIS OS 11/12 enable **"Allow unsigned apps"**
   (or sign the `.eap`, see SSH Jump's README §5 — identical procedure; AXIS
   OS 13+ requires signing).
2. **Add app** → upload `ipscan_1_0_0_aarch64.eap` (ARTPEC‑8+) or
   `ipscan_1_0_0_armv7hf.eap` (ARTPEC‑6/7). If unsure, try aarch64 first.
3. **Enable** the app, then open it → **Open** / settings page.

### ARTPEC‑4 / ARTPEC‑5 (classic ACAP, over SSH)

Exactly like SSH Jump (Legacy) — the web‑UI installer can't install on this
hardware (ACAP framework 2.x):

```bash
scp dist/ipscan_1_0_0_artpec5_mipsisa32r2el.eap legacy/install-dev.sh root@<camera>:/tmp/
ssh root@<camera> 'CAM_PASS=<root password> sh /tmp/install-dev.sh'
```

Then open `http://<camera>/local/ipscan/config.html` (admin login). The package
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

- The backend listens only on `127.0.0.1:2202` (AXIS OS 10+) or a local Unix
  socket (classic); all access goes through the camera's Apache with Axis
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
| `IPSCAN_LISTEN` | `127.0.0.1:2202` (modern) | serve HTTP on TCP (forces TCP on a legacy build too) |
| `IPSCAN_SOCKET` | `/var/run/http/ipscan/http` | legacy Unix socket (HTTP + FastCGI) |
| `IPSCAN_ICMP` | auto | `raw`, `dgram` or `off` |
| `IPSCAN_LOG` | `/tmp/ipscan.log` | log file (also mirrored to the Axis system log) |
| `IPSCAN_DEBUG` | — | `1` = verbose request tracing |
| `IPSCAN_HTML` | — | dev only: also serve the UI from `$IPSCAN_HTML/<app>/` |

## 4. SSH Jump integration

IP Scan links port 22 (and 2222) to
`/local/sshjump/index.html?host=<ip>&port=<port>` (or `config.html` on
ARTPEC‑4/5). For SSH Jump to **pre‑fill** the host, apply the small patch in
[`integration/`](integration/) to each SSH Jump repo and rebuild:

```bash
cd SSHJump       && git apply ../IPScan/integration/sshjump-prefill.patch
cd SSHJumpLegacy && git apply ../IPScan/integration/sshjumplegacy-prefill.patch
```

It only reads `host`, `port` and `user` from the URL and fills the form;
nothing is submitted and no credentials ever travel in the URL. Without the
patch the link still opens SSH Jump, just with an empty form.

## 5. Build

```bash
./build.sh            # all four .eap → dist/
./build.sh modern     # aarch64 + armv7hf
./build.sh legacy     # artpec4 + artpec5
./build.sh test       # go vet + unit tests + qemu smoke test of each binary
```

Requirements: **Go ≥ 1.24.1** (the MIPS build needs the golang/go#71591 fix;
the modern builds are fine with Go ≥ 1.21). Standard library only — no
third‑party Go modules, no network needed. For the legacy packages also
`gcc-mipsel-linux-gnu` (PIE launcher); `qemu-user-static` for `./build.sh test`.

With the official Axis SDK (modern packages only):

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
  main.go        HTTP API, both transports (TCP / Unix HTTP+FastCGI), idle watchdog
  scan.go        range/port parsing, scan engine, per-host probing, CSV
  icmp.go        ICMP echo via raw or unprivileged ping socket
  probes.go      ARP table, NetBIOS node status, web detect, local networks, OUI lookup
  oui.txt.gz     embedded MAC vendor table
  html/index.html  the UI (served as config.html in the classic packages)
  manifest.json, Makefile, LICENSE
legacy/          package.conf, cgi.txt, zz_ipscan_proxy.conf, postinstall.sh, install-dev.sh
integration/     SSH Jump URL-prefill patches
tools/gen-oui.py MAC vendor table generator
build.sh, Dockerfile
dist/            prebuilt .eap packages
```

## API (for scripting)

Modern: `https://<camera>/local/ipscan/api/<op>` · Classic:
`http://<camera>/local/ipscan/control.cgi?op=<op>` (admin auth either way).

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
