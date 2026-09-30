// ipscan — ACAP network scanner (in the spirit of Angry IP Scanner) that runs
// on an Axis device and scans the device's LAN from the camera's web UI:
// liveness (ICMP / TCP / ARP), ping time, hostname (reverse DNS + NetBIOS),
// MAC address + vendor, open TCP ports and web server detection.
//
// Companion to SSH Jump: every host with SSH open gets a one-click link that
// opens the SSH Jump terminal pre-filled with that IP.
//
// One binary per architecture; the transport is chosen at run time, so the
// same package works on every AXIS OS generation (see main()):
//
//	AXIS OS 9.x - 10.5  (classic package.conf): postinstall.sh wires Apache
//	        mod_proxy_http  /local/ipscan/control.cgi -> unix:/var/run/http/ipscan/http
//	        (the daemon speaks HTTP *and* FastCGI on that socket)
//	AXIS OS 10.6+       (manifest.json): httpConfig fastCgi
//	        /local/ipscan/control.cgi -> FastCGI on $FCGI_SOCKET_NAME
//	AXIS OS 11.8+       additionally manifest reverseProxy
//	        /local/ipscan/api/<op>    -> http://localhost:2202
//
// The router accepts both styles (?op=<op> or a trailing /<op> path segment).
// Transport is plain request/response + polling, which works through the Axis
// Apache reverse proxy (it strips WebSocket upgrade headers).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	rdebug "runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Build-time settings (-ldflags "-X main.version=... -X main.flavor=...").
// flavor is informational only (shown by op=info); nothing depends on it.
var (
	version = "1.1.0"
	flavor  = "dev"
)

// ---- configuration (overridable via environment) ---------------------------

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	appName     = env("IPSCAN_APP", "ipscan")
	idleTimeout = parseDuration(env("IPSCAN_IDLE_TIMEOUT", "30m"))
	logPath     = env("IPSCAN_LOG", "/tmp/ipscan.log")
	debug       = os.Getenv("IPSCAN_DEBUG") == "1"
	// IPSCAN_LISTEN replaces the default loopback TCP listeners (debugging).
	tcpAddr    = os.Getenv("IPSCAN_LISTEN")
	socketPath = env("IPSCAN_SOCKET", "/var/run/http/"+appName+"/http")
)

func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 30 * time.Minute
	}
	return d
}

// ---- logging ---------------------------------------------------------------

var sysLog *syslog.Writer

func emit(sev byte, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Print(msg)
	if sysLog == nil {
		return
	}
	switch sev {
	case 'E':
		_ = sysLog.Err(msg)
	case 'W':
		_ = sysLog.Warning(msg)
	case 'D':
		_ = sysLog.Debug(msg)
	default:
		_ = sysLog.Info(msg)
	}
}

func inf(format string, a ...interface{})   { emit('I', format, a...) }
func warnf(format string, a ...interface{}) { emit('W', format, a...) }
func errf(format string, a ...interface{})  { emit('E', format, a...) }

func stackTrace() string { return string(rdebug.Stack()) }
func dbg(format string, a ...interface{}) {
	if debug {
		emit('D', format, a...)
	}
}

// ---- activity tracking (drives the idle shutdown) --------------------------
//
// Activity = the operator doing something (start/stop a scan, export) or a scan
// running. Merely keeping the page open (status polling) is NOT activity, so an
// abandoned browser tab does not keep the scanner alive forever.

type activity struct {
	mu   sync.Mutex
	last time.Time
}

func (a *activity) touch() { a.mu.Lock(); a.last = time.Now(); a.mu.Unlock() }
func (a *activity) idleFor() time.Duration {
	if cur := scans.current(); cur != nil && cur.running() {
		a.touch()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.last)
}

var act = &activity{last: time.Now()}

func stopSelf() {
	warnf("idle for %s with no activity — auto-stopping %s", idleTimeout, appName)
	q := "/axis-cgi/applications/control.cgi?action=stop&package=" + appName
	_ = exec.Command("sh", "-c",
		"curl -s --max-time 5 'http://127.0.0.1"+q+"' >/dev/null 2>&1 || "+
			"curl -sk --max-time 5 'https://127.0.0.1"+q+"' >/dev/null 2>&1").Run()
	os.Exit(0)
}

func watchdog() {
	interval := 30 * time.Second
	if idleTimeout < interval {
		interval = idleTimeout
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		idle := act.idleFor()
		dbg("watchdog: idle=%s (timeout %s)", idle.Round(time.Second), idleTimeout)
		if idle >= idleTimeout {
			stopSelf()
			return
		}
	}
}

// ---- HTTP API ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// GET info -> device networks, defaults, detection capabilities, idle state.
func infoHandler(w http.ResponseWriter) {
	nets := localNets()
	suggest := ""
	for _, n := range nets {
		if n.Suggest != "" {
			suggest = n.Suggest
			break
		}
	}
	idle := act.idleFor()
	writeJSON(w, 200, map[string]interface{}{
		"ok":             true,
		"app":            appName,
		"version":        version,
		"flavor":         flavor,
		"arch":           runtime.GOARCH,
		"networks":       nets,
		"suggest":        suggest,
		"icmp":           pingerMode(),
		"maxHosts":       maxHosts,
		"maxPorts":       maxPorts,
		"defaultThreads": defaultThreads(),
		"maxThreads":     maxThreads,
		"idleSeconds":    int(idle.Seconds()),
		"idleTimeout":    int(idleTimeout.Seconds()),
	})
}

// POST start {targets, ports, threads, timeoutMs, dns, netbios, web}
func startHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, 405, "POST required")
		return
	}
	var req scanRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		errJSON(w, 400, "invalid request")
		return
	}
	act.touch()
	s, err := scans.start(req)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"id": s.ID, "total": len(s.hosts)})
}

// GET status?id=&since=N -> progress + hosts finished since index N.
func statusHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s := scans.current()
	if s == nil {
		writeJSON(w, 200, map[string]interface{}{"id": nil})
		return
	}
	if q.Get("id") != "" && q.Get("id") != s.ID {
		writeJSON(w, 200, map[string]interface{}{"id": nil, "current": s.ID})
		return
	}
	since := atoiDef(q.Get("since"), 0)
	writeJSON(w, 200, s.snapshot(since))
}

// POST stop
func stopHandler(w http.ResponseWriter) {
	act.touch()
	if s := scans.current(); s != nil {
		s.cancel()
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// GET export?format=csv -> the current scan as CSV (alive hosts, or all with all=1)
func exportHandler(w http.ResponseWriter, r *http.Request) {
	act.touch()
	s := scans.current()
	if s == nil {
		errJSON(w, 404, "no scan")
		return
	}
	all := r.URL.Query().Get("all") == "1"
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"ipscan-%s.csv\"", s.Started.Format("20060102-150405")))
	s.writeCSV(w, all)
}

func route(w http.ResponseWriter, r *http.Request) {
	op := r.URL.Query().Get("op")
	if op == "" {
		p := strings.TrimRight(r.URL.Path, "/")
		op = p[strings.LastIndex(p, "/")+1:]
	}
	dbg("%s %s op=%s", r.Method, r.URL.RequestURI(), op)
	switch op {
	case "info", "health":
		infoHandler(w)
	case "start":
		startHandler(w, r)
	case "status":
		statusHandler(w, r)
	case "stop":
		stopHandler(w)
	case "export":
		exportHandler(w, r)
	default:
		http.NotFound(w, r)
	}
}

// ---- transport: Unix socket speaking FastCGI *and* HTTP (legacy) -------------

type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
}

func (l *chanListener) Accept() (net.Conn, error) { return <-l.ch, nil }
func (l *chanListener) Close() error              { return nil }
func (l *chanListener) Addr() net.Addr            { return l.addr }

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func listenUnix(path string) (net.Listener, error) {
	_ = os.MkdirAll(filepath.Dir(path), 0777)
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0666)
	return ln, nil
}

// serveMux serves HTTP and FastCGI on the same listener, told apart by the
// first byte (FastCGI records start with version byte 0x01).
func serveMux(ln net.Listener, h http.Handler) error {
	fcgiL := &chanListener{ch: make(chan net.Conn), addr: ln.Addr()}
	httpL := &chanListener{ch: make(chan net.Conn), addr: ln.Addr()}
	go func() { _ = fcgi.Serve(fcgiL, h) }()
	go func() { _ = http.Serve(httpL, h) }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			br := bufio.NewReader(c)
			_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
			first, err := br.Peek(1)
			_ = c.SetReadDeadline(time.Time{})
			if err != nil {
				_ = c.Close()
				return
			}
			bc := &bufferedConn{Conn: c, r: br}
			if first[0] == 0x01 {
				fcgiL.ch <- bc
			} else {
				httpL.ch <- bc
			}
		}(c)
	}
}

// raiseNoFile lifts the soft fd limit to the hard limit: a scan keeps many
// sockets in flight at once.
func raiseNoFile() {
	var rl syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl) == nil && rl.Cur < rl.Max {
		rl.Cur = rl.Max
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl)
	}
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl) == nil {
		fdLimit = int(rl.Cur)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[ipscan] ")
	if w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_USER, appName); err == nil {
		sysLog = w
	}
	// With syslog connected, stderr would only duplicate every line in the
	// system log (systemd forwards stderr there too), so keep just the file.
	var outs []io.Writer
	if sysLog == nil {
		outs = append(outs, os.Stderr)
	}
	if lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		outs = append(outs, lf)
	}
	log.SetOutput(io.MultiWriter(outs...))
	raiseNoFile()
	initSockSem()
	initPinger()
	inf("ipscan %s (%s, %s/%s) starting; idle timeout %s; icmp=%s; fd limit %d",
		version, flavor, runtime.GOOS, runtime.GOARCH, idleTimeout, pingerMode(), fdLimit)

	go watchdog()
	var h http.Handler = http.HandlerFunc(route)
	if dir := os.Getenv("IPSCAN_HTML"); dir != "" {
		// Development only: serve the UI too, emulating the camera's Apache
		// (/local/<app>/... static files from $IPSCAN_HTML/<app>/, and api/ or
		// control.cgi to the daemon).
		static := http.StripPrefix("/local/", http.FileServer(http.Dir(dir)))
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			if strings.Contains(p, "/api/") || strings.HasSuffix(p, "/control.cgi") {
				route(w, r)
			} else {
				static.ServeHTTP(w, r)
			}
		})
	}

	h = safe(h)
	inf("runtime: uid=%d gid=%d FCGI_SOCKET_NAME=%q", os.Getuid(), os.Getgid(), os.Getenv("FCGI_SOCKET_NAME"))

	// Every transport that can be opened is started; the daemon only gives up
	// when none could. Which one the camera's Apache actually uses depends on
	// the AXIS OS version (see the header comment).
	type server struct {
		name  string
		serve func() error
	}
	var servers []server

	addrs := []string{"127.0.0.1:2202", "[::1]:2202"} // "localhost" may be ::1 first
	if tcpAddr != "" {
		addrs = []string{tcpAddr}
	}
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			if strings.HasPrefix(a, "[::1]") {
				dbg("IPv6 loopback not available (%v)", err)
			} else {
				warnf("cannot listen on tcp:%s: %v", a, err)
			}
			continue
		}
		servers = append(servers, server{"tcp:" + a + " (HTTP)", func() error { return http.Serve(ln, h) }})
	}
	if fs := os.Getenv("FCGI_SOCKET_NAME"); fs != "" {
		// AXIS OS 10.6+: manifest httpConfig "fastCgi" -> /local/<app>/control.cgi
		_ = os.Remove(fs)
		if ln, err := net.Listen("unix", fs); err != nil {
			errf("cannot listen on FastCGI socket %s: %v", fs, err)
		} else {
			_ = os.Chmod(fs, 0777)
			servers = append(servers, server{"unix:" + fs + " (FastCGI)", func() error { return fcgi.Serve(ln, h) }})
		}
	} else if tcpAddr == "" {
		// AXIS OS 9.x/10.x classic package: postinstall.sh points Apache's
		// mod_proxy_http at this socket.
		if ln, err := listenUnix(socketPath); err != nil {
			warnf("cannot listen on unix:%s: %v", socketPath, err)
		} else {
			servers = append(servers, server{"unix:" + socketPath + " (HTTP+FastCGI)", func() error { return serveMux(ln, h) }})
		}
	}
	if len(servers) == 0 {
		errf("no transport could be opened — exiting")
		os.Exit(1)
	}
	errs := make(chan error, len(servers))
	for _, sv := range servers {
		inf("listening on %s", sv.name)
		go func(sv server) {
			err := sv.serve()
			errf("%s stopped: %v", sv.name, err)
			errs <- err
		}(sv)
	}
	for range servers { // keep running while at least one transport is alive
		<-errs
	}
	errf("all transports failed — exiting")
	os.Exit(1)
}

// safe turns a panic inside a request into a logged 500 instead of taking the
// whole daemon down (net/http recovers per request, net/http/fcgi does not).
func safe(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				errf("panic serving %s: %v\n%s", r.URL.RequestURI(), v, stackTrace())
				http.Error(w, "internal error", 500)
			}
		}()
		h.ServeHTTP(w, r)
	})
}
