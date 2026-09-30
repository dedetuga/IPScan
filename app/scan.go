package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxHosts   = 65536 // one /16 per scan
	maxPorts   = 1024
	maxThreads = 256
)

var fdLimit = 1024

func defaultThreads() int {
	if runtime.GOARCH == "mipsle" || runtime.GOARCH == "arm" {
		return 32
	}
	return 64
}

// ---- request -----------------------------------------------------------------

type scanRequest struct {
	Targets   string `json:"targets"`
	Ports     string `json:"ports"`
	Threads   int    `json:"threads"`
	TimeoutMs int    `json:"timeoutMs"`
	DNS       bool   `json:"dns"`
	NetBIOS   bool   `json:"netbios"`
	Web       bool   `json:"web"`
}

var splitRe = regexp.MustCompile(`[\s,;]+`)

func ip2u(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }
func u2ip(u uint32) net.IP {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, u)
	return b
}

// parseTargets accepts, separated by commas/spaces/newlines:
//
//	192.168.1.10                  single address
//	192.168.1.0/24                CIDR (network/broadcast skipped for /30 and larger)
//	192.168.1.10-192.168.1.50     range
//	192.168.1.10-50               last-octet range
//	nvr.local                     hostname (resolved, IPv4)
func parseTargets(s string) ([]uint32, error) {
	var out []uint32
	seen := make(map[uint32]bool)
	add := func(u uint32) error {
		if seen[u] {
			return nil
		}
		if len(out) >= maxHosts {
			return fmt.Errorf("too many addresses (max %d per scan — a /16)", maxHosts)
		}
		seen[u] = true
		out = append(out, u)
		return nil
	}
	addRange := func(a, b uint32) error {
		if b < a {
			a, b = b, a
		}
		if uint64(b)-uint64(a)+1 > maxHosts {
			return fmt.Errorf("range too large (max %d addresses — a /16)", maxHosts)
		}
		for u := uint64(a); u <= uint64(b); u++ {
			if err := add(uint32(u)); err != nil {
				return err
			}
		}
		return nil
	}
	for _, tok := range splitRe.Split(strings.TrimSpace(s), -1) {
		if tok == "" {
			continue
		}
		switch {
		case strings.Contains(tok, "/"):
			ip, n, err := net.ParseCIDR(tok)
			if err != nil || ip.To4() == nil {
				return nil, fmt.Errorf("invalid CIDR %q (IPv4 only)", tok)
			}
			ones, _ := n.Mask.Size()
			if ones < 16 {
				return nil, fmt.Errorf("%s is too large (smallest prefix is /16)", tok)
			}
			first := ip2u(n.IP)
			last := first | ^binary.BigEndian.Uint32(n.Mask)
			if ones <= 30 {
				first, last = first+1, last-1
			}
			if err := addRange(first, last); err != nil {
				return nil, err
			}
		case strings.Contains(tok, "-"):
			i := strings.Index(tok, "-")
			a := net.ParseIP(tok[:i]).To4()
			if a == nil {
				return nil, fmt.Errorf("invalid range %q", tok)
			}
			rhs := tok[i+1:]
			var b net.IP
			if n, err := strconv.Atoi(rhs); err == nil && n >= 0 && n <= 255 {
				b = net.IPv4(a[0], a[1], a[2], byte(n)).To4()
			} else if b = net.ParseIP(rhs).To4(); b == nil {
				return nil, fmt.Errorf("invalid range %q", tok)
			}
			if err := addRange(ip2u(a), ip2u(b)); err != nil {
				return nil, err
			}
		default:
			if ip := net.ParseIP(tok); ip != nil {
				if ip.To4() == nil {
					return nil, fmt.Errorf("%q: IPv6 is not supported", tok)
				}
				if err := add(ip2u(ip)); err != nil {
					return nil, err
				}
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", tok)
			cancel()
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("cannot resolve %q", tok)
			}
			for _, ip := range ips {
				if err := add(ip2u(ip)); err != nil {
					return nil, err
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no targets given")
	}
	return out, nil
}

// parsePorts accepts "22,80,443,8000-8100".
func parsePorts(s string) ([]int, error) {
	seen := make(map[int]bool)
	var out []int
	for _, tok := range splitRe.Split(strings.TrimSpace(s), -1) {
		if tok == "" {
			continue
		}
		a, b := tok, tok
		if i := strings.Index(tok, "-"); i > 0 {
			a, b = tok[:i], tok[i+1:]
		}
		lo, e1 := strconv.Atoi(a)
		hi, e2 := strconv.Atoi(b)
		if e1 != nil || e2 != nil || lo < 1 || hi > 65535 || lo > hi {
			return nil, fmt.Errorf("invalid port %q", tok)
		}
		for p := lo; p <= hi; p++ {
			if !seen[p] {
				if len(out) >= maxPorts {
					return nil, fmt.Errorf("too many ports (max %d)", maxPorts)
				}
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

func atoiDef(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---- results -------------------------------------------------------------------

type Host struct {
	IP      string  `json:"ip"`
	Alive   bool    `json:"alive"`
	Via     string  `json:"via,omitempty"` // icmp | tcp | udp | arp
	RTT     float64 `json:"rtt,omitempty"` // ms
	Name    string  `json:"name,omitempty"`
	NetBIOS string  `json:"netbios,omitempty"`
	Group   string  `json:"group,omitempty"`
	MAC     string  `json:"mac,omitempty"`
	Vendor  string  `json:"vendor,omitempty"`
	Ports   []int   `json:"ports,omitempty"`
	Web     string  `json:"web,omitempty"`
	WebURL  string  `json:"webUrl,omitempty"`
	u       uint32
}

type Scan struct {
	ID       string
	Started  time.Time
	req      scanRequest
	ports    []int
	targets  []uint32
	timeout  time.Duration
	threads  int
	hosts    []uint32 // == targets (kept for len)
	ctx      context.Context
	cancelFn context.CancelFunc

	mu       sync.Mutex
	done     []*Host
	alive    int
	state    string // running | done | stopped
	finished time.Time
}

func (s *Scan) running() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.state == "running" }

func (s *Scan) cancel() {
	s.mu.Lock()
	if s.state == "running" {
		s.state = "stopped"
		s.finished = time.Now()
	}
	s.mu.Unlock()
	s.cancelFn()
}

func (s *Scan) snapshot(since int) map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if since < 0 {
		since = 0
	}
	if since > len(s.done) {
		since = len(s.done)
	}
	end := time.Now()
	if s.state != "running" {
		end = s.finished
	}
	batch := s.done[since:]
	if len(batch) > 2000 { // keep each response small; the client keeps polling
		batch = batch[:2000]
	}
	return map[string]interface{}{
		"id":        s.ID,
		"state":     s.state,
		"total":     len(s.targets),
		"scanned":   len(s.done),
		"alive":     s.alive,
		"elapsedMs": end.Sub(s.Started).Milliseconds(),
		"since":     since,
		"next":      since + len(batch),
		"hosts":     batch,
		"ports":     s.ports,
		"targets":   s.req.Targets,
	}
}

func (s *Scan) writeCSV(w io.Writer, all bool) {
	s.mu.Lock()
	hs := append([]*Host(nil), s.done...)
	s.mu.Unlock()
	sort.Slice(hs, func(i, j int) bool { return hs[i].u < hs[j].u })
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"IP", "Status", "Ping (ms)", "Hostname", "NetBIOS", "Workgroup",
		"MAC", "Vendor", "Open ports", "Web", "Detected via"})
	for _, h := range hs {
		if !h.Alive && !all {
			continue
		}
		status, rtt := "dead", ""
		if h.Alive {
			status = "alive"
			if h.RTT > 0 {
				rtt = strconv.FormatFloat(h.RTT, 'f', 1, 64)
			}
		}
		ports := make([]string, len(h.Ports))
		for i, p := range h.Ports {
			ports[i] = strconv.Itoa(p)
		}
		_ = cw.Write([]string{h.IP, status, rtt, h.Name, h.NetBIOS, h.Group,
			h.MAC, h.Vendor, strings.Join(ports, " "), h.Web, h.Via})
	}
	cw.Flush()
}

// ---- scan manager (one scan at a time; a new one replaces the previous) -------

type scanManager struct {
	mu  sync.Mutex
	cur *Scan
}

var scans = &scanManager{}

func (m *scanManager) current() *Scan { m.mu.Lock(); defer m.mu.Unlock(); return m.cur }

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *scanManager) start(req scanRequest) (*Scan, error) {
	targets, err := parseTargets(req.Targets)
	if err != nil {
		return nil, err
	}
	ports, err := parsePorts(req.Ports)
	if err != nil {
		return nil, err
	}
	if req.Threads == 0 {
		req.Threads = defaultThreads()
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = 1000
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Scan{
		ID:       newID(),
		Started:  time.Now(),
		req:      req,
		ports:    ports,
		targets:  targets,
		hosts:    targets,
		timeout:  time.Duration(clamp(req.TimeoutMs, 100, 10000)) * time.Millisecond,
		threads:  clamp(req.Threads, 1, maxThreads),
		ctx:      ctx,
		cancelFn: cancel,
		state:    "running",
	}
	m.mu.Lock()
	if m.cur != nil {
		m.cur.cancel()
	}
	m.cur = s
	m.mu.Unlock()
	inf("scan %s: %d targets (%s), %d ports, %d threads, timeout %s, dns=%v netbios=%v web=%v",
		s.ID, len(targets), req.Targets, len(ports), s.threads, s.timeout, req.DNS, req.NetBIOS, req.Web)
	go s.run()
	return s, nil
}

func (s *Scan) run() {
	jobs := make(chan uint32)
	var wg sync.WaitGroup
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				h := s.probeHost(u)
				if s.ctx.Err() != nil && !h.Alive {
					continue // cancelled mid-probe: result is meaningless
				}
				s.mu.Lock()
				s.done = append(s.done, h)
				if h.Alive {
					s.alive++
				}
				s.mu.Unlock()
			}
		}()
	}
feed:
	for _, u := range s.targets {
		select {
		case jobs <- u:
		case <-s.ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	s.mu.Lock()
	if s.state == "running" {
		s.state = "done"
		s.finished = time.Now()
	}
	st, alive, n, took := s.state, s.alive, len(s.done), s.finished.Sub(s.Started)
	s.mu.Unlock()
	s.cancelFn()
	act.touch()
	inf("scan %s %s: %d/%d scanned, %d alive, %s", s.ID, st, n, len(s.targets), alive, took.Round(time.Millisecond))
}

// ---- per-host probing ------------------------------------------------------------

// Socket budget shared by every probe of every worker, so large thread/port
// counts cannot exhaust the process' file descriptors.
var sockSem = make(chan struct{}, 512)

func initSockSem() {
	n := clamp(fdLimit-64, 32, 1024)
	sockSem = make(chan struct{}, n)
}

// livenessPorts: TCP ports knocked to decide whether a host is up when ICMP is
// unavailable or filtered. A RST (connection refused) proves the host exists
// just as well as an accepted connection.
var livenessPorts = []int{80, 443, 22, 445, 554, 139, 8080, 23}

type tcpResult struct {
	port  int
	open  bool
	alive bool
	rtt   time.Duration
}

func tcpProbe(ctx context.Context, ip net.IP, port int, timeout time.Duration) tcpResult {
	select {
	case sockSem <- struct{}{}:
	case <-ctx.Done():
		return tcpResult{port: port}
	}
	defer func() { <-sockSem }()
	d := net.Dialer{Timeout: timeout}
	t0 := time.Now()
	c, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	rtt := time.Since(t0)
	if err == nil {
		_ = c.Close()
		return tcpResult{port: port, open: true, alive: true, rtt: rtt}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return tcpResult{port: port, alive: true, rtt: rtt}
	}
	return tcpResult{port: port}
}

func msf(d time.Duration) float64 {
	v := float64(d.Microseconds()) / 1000
	if v < 0.1 {
		v = 0.1
	}
	return float64(int(v*10+0.5)) / 10
}

func (s *Scan) probeHost(u uint32) *Host {
	ip := u2ip(u)
	h := &Host{IP: ip.String(), u: u}
	ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()

	// NetBIOS is fired first: it is cheap (1 UDP datagram), also triggers ARP
	// resolution, and its answer proves the host alive.
	var nbCh chan nbInfo
	if s.req.NetBIOS {
		nbCh = make(chan nbInfo, 1)
		go func() { nbCh <- netbiosQuery(s.ctx, ip, s.timeout) }()
	}

	// ---- liveness: ICMP and TCP knocks race; first positive answer wins.
	type live struct {
		via string
		rtt time.Duration
	}
	liveCh := make(chan live, 1+len(livenessPorts)+len(s.ports))
	openFound := make(map[int]bool)
	var openMu sync.Mutex
	var pending sync.WaitGroup
	if pingerMode() != "off" {
		pending.Add(1)
		go func() {
			defer pending.Done()
			if rtt, ok := ping(ctx, ip, s.timeout); ok {
				liveCh <- live{"icmp", rtt}
			}
		}()
	}
	knock := append([]int(nil), livenessPorts...)
	for _, p := range s.ports { // user ports that are cheap to include
		if len(knock) >= 12 {
			break
		}
		dup := false
		for _, k := range knock {
			dup = dup || k == p
		}
		if !dup {
			knock = append(knock, p)
		}
	}
	for _, p := range knock {
		pending.Add(1)
		go func(p int) {
			defer pending.Done()
			r := tcpProbe(ctx, ip, p, s.timeout)
			if r.open {
				openMu.Lock()
				openFound[p] = true
				openMu.Unlock()
			}
			if r.alive {
				liveCh <- live{"tcp", r.rtt}
			}
		}(p)
	}
	allDone := make(chan struct{})
	go func() { pending.Wait(); close(allDone) }()

	var got *live
	select {
	case l := <-liveCh:
		got = &l
	case <-allDone:
		select {
		case l := <-liveCh:
			got = &l
		default:
		}
	case <-ctx.Done():
	}
	if got != nil {
		h.Alive, h.Via, h.RTT = true, got.via, msf(got.rtt)
		// Prefer an ICMP RTT if it arrives shortly after a faster TCP answer.
		if got.via == "tcp" && pingerMode() != "off" {
			t := time.NewTimer(50 * time.Millisecond)
		wait:
			for {
				select {
				case l := <-liveCh:
					if l.via == "icmp" {
						h.Via, h.RTT = "icmp", msf(l.rtt)
						break wait
					}
				case <-t.C:
					break wait
				}
			}
			t.Stop()
		}
	}
	// Let the knocks finish (bounded by the timeout) so we keep their open ports.
	select {
	case <-allDone:
	case <-ctx.Done():
	}
	if s.ctx.Err() != nil {
		return h
	}

	var nb nbInfo
	if nbCh != nil {
		nb = <-nbCh
		if nb.Name != "" && !h.Alive {
			h.Alive, h.Via = true, "udp"
		}
	}
	// ARP: on the local L2 segment every knock above made the kernel resolve the
	// target's MAC; a complete ARP entry means the host answered even if it
	// firewalls ICMP and every TCP port.
	mac := arpLookup(h.IP)
	if !h.Alive && mac != "" {
		h.Alive, h.Via = true, "arp"
	}
	if !h.Alive {
		return h
	}
	if mac == "" && nb.MAC != "" {
		mac = nb.MAC
	}
	h.MAC = mac
	h.Vendor = ouiVendor(mac)
	h.NetBIOS, h.Group = nb.Name, nb.Group

	// ---- details for live hosts: remaining ports + reverse DNS in parallel.
	var wg sync.WaitGroup
	if s.req.DNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cn := context.WithTimeout(s.ctx, 2*time.Second)
			defer cn()
			if names, err := net.DefaultResolver.LookupAddr(c, h.IP); err == nil && len(names) > 0 {
				h.Name = strings.TrimSuffix(names[0], ".")
			}
		}()
	}
	var todo []int
	openMu.Lock()
	for _, p := range s.ports {
		if !openFound[p] && !contains(knock, p) {
			todo = append(todo, p)
		}
	}
	openMu.Unlock()
	perHost := make(chan struct{}, 32)
	for _, p := range todo {
		wg.Add(1)
		perHost <- struct{}{}
		go func(p int) {
			defer func() { <-perHost; wg.Done() }()
			pc, pcn := context.WithTimeout(s.ctx, s.timeout)
			defer pcn()
			if r := tcpProbe(pc, ip, p, s.timeout); r.open {
				openMu.Lock()
				openFound[p] = true
				openMu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	for _, p := range s.ports { // report only ports the user asked for
		if openFound[p] {
			h.Ports = append(h.Ports, p)
		}
	}
	if s.req.Web {
		h.Web, h.WebURL = webDetect(s.ctx, h.IP, openFound, s.timeout)
	}
	if h.MAC == "" { // ARP may have completed during the port scan
		h.MAC = arpLookup(h.IP)
		h.Vendor = ouiVendor(h.MAC)
	}
	if h.Name == "" && h.NetBIOS != "" {
		h.Name = h.NetBIOS
	}
	return h
}

func contains(a []int, v int) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}
