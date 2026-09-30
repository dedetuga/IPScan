package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/binary"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- ARP table ------------------------------------------------------------------

// arpLookup returns the MAC of a complete (ATF_COM) entry in the kernel ARP
// table, or "". Reading /proc/net/arp needs no privileges.
func arpLookup(ip string) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 4 || fs[0] != ip {
			continue
		}
		flags, _ := strconv.ParseUint(strings.TrimPrefix(fs[2], "0x"), 16, 32)
		if flags&0x2 == 0 || fs[3] == "00:00:00:00:00:00" {
			return ""
		}
		return strings.ToUpper(fs[3])
	}
	return ""
}

// ---- NetBIOS node status (UDP 137, like `nmblookup -A`) --------------------------

type nbInfo struct {
	Name, Group, MAC string
}

func netbiosQuery(ctx context.Context, ip net.IP, timeout time.Duration) nbInfo {
	var res nbInfo
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: 137})
	if err != nil {
		return res
	}
	defer c.Close()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	go func() { <-ctx.Done(); _ = c.SetDeadline(time.Now()) }()

	q := make([]byte, 0, 50)
	q = append(q, byte(time.Now().UnixNano()), 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	q = append(q, 0x20)
	name := [16]byte{'*'}
	for _, b := range name {
		q = append(q, 'A'+b>>4, 'A'+b&0x0f)
	}
	q = append(q, 0, 0x00, 0x21, 0x00, 0x01) // NBSTAT, IN
	if _, err := c.Write(q); err != nil {
		return res
	}
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil || n < 57 {
		return res
	}
	b := buf[:n]
	off := 12
	if b[off]&0xc0 == 0xc0 { // compressed name pointer
		off += 2
	} else {
		for off < len(b) && b[off] != 0 {
			off += int(b[off]) + 1
		}
		off++
	}
	off += 10 // type, class, ttl, rdlength
	if off >= len(b) {
		return res
	}
	count := int(b[off])
	off++
	for i := 0; i < count && off+18 <= len(b); i++ {
		nm := strings.TrimRight(string(b[off:off+15]), " \x00")
		suffix := b[off+15]
		group := binary.BigEndian.Uint16(b[off+16:off+18])&0x8000 != 0
		off += 18
		if suffix != 0x00 || !printableASCII(nm) {
			continue
		}
		if !group && res.Name == "" {
			res.Name = nm
		} else if group && res.Group == "" {
			res.Group = nm
		}
	}
	if off+6 <= len(b) {
		m := net.HardwareAddr(b[off : off+6])
		if !bytes.Equal(m, make([]byte, 6)) {
			res.MAC = strings.ToUpper(m.String())
		}
	}
	return res
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return s != ""
}

// ---- web server detection --------------------------------------------------------

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	spaceRe = regexp.MustCompile(`\s+`)
	webTLS  = map[int]bool{443: true, 8443: true, 4443: true, 9443: true}
	webPref = []int{80, 443, 8080, 8443, 8000, 8081, 8888, 81, 88, 4443, 9443, 5000, 5001, 7443}
)

// webDetect GETs "/" on the first web-looking open port and summarises it as
// "<title> — <Server>" (or the HTTP status). Redirects are followed on the
// same host only.
func webDetect(ctx context.Context, ip string, open map[int]bool, timeout time.Duration) (string, string) {
	var ports []int
	for _, p := range webPref {
		if open[p] {
			ports = append(ports, p)
		}
	}
	if len(ports) > 2 {
		ports = ports[:2]
	}
	for _, p := range ports {
		schemes := []string{"http", "https"}
		if webTLS[p] {
			schemes = []string{"https", "http"}
		}
		for _, sch := range schemes {
			u := fmt.Sprintf("%s://%s", sch, net.JoinHostPort(ip, strconv.Itoa(p)))
			if (sch == "http" && p == 80) || (sch == "https" && p == 443) {
				u = sch + "://" + ip
			}
			if s, ok := httpSummary(ctx, u, ip, timeout); ok {
				return s, u + "/"
			}
		}
	}
	return "", ""
}

func httpSummary(ctx context.Context, url, host string, timeout time.Duration) (string, bool) {
	to := timeout * 3
	if to < 2*time.Second {
		to = 2 * time.Second
	}
	cl := &http.Client{
		Timeout: to,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, // LAN gear: self-signed
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: to,
			DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Hostname() != host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", url+"/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (ipscan ACAP)")
	select {
	case sockSem <- struct{}{}:
	case <-ctx.Done():
		return "", false
	}
	defer func() { <-sockSem }()
	resp, err := cl.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	title := ""
	if m := titleRe.FindSubmatch(body); m != nil {
		title = strings.TrimSpace(spaceRe.ReplaceAllString(html.UnescapeString(string(m[1])), " "))
	}
	if len(title) > 80 {
		title = title[:80] + "…"
	}
	server := resp.Header.Get("Server")
	if len(server) > 60 {
		server = server[:60]
	}
	parts := []string{}
	if title != "" {
		parts = append(parts, title)
	}
	if server != "" {
		parts = append(parts, server)
	}
	if len(parts) == 0 {
		parts = append(parts, "HTTP "+strconv.Itoa(resp.StatusCode))
	} else if resp.StatusCode == 401 {
		parts = append(parts, "401")
	}
	return strings.Join(parts, " — "), true
}

// ---- local networks ----------------------------------------------------------------

type netInfo struct {
	Iface   string `json:"iface"`
	IP      string `json:"ip"`
	CIDR    string `json:"cidr"`
	Prefix  int    `json:"prefix"`
	Suggest string `json:"suggest,omitempty"`
}

// localNets lists the device's IPv4 networks with a suggested scan range: the
// whole subnet up to /20, otherwise the /24 around the device's own address.
func localNets() []netInfo {
	var out, linkLocal []netInfo
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ones, _ := ipn.Mask.Size()
			netw := &net.IPNet{IP: ipn.IP.Mask(ipn.Mask), Mask: ipn.Mask}
			ni := netInfo{Iface: ifc.Name, IP: ipn.IP.String(), CIDR: netw.String(), Prefix: ones}
			if ones >= 20 {
				ni.Suggest = netw.String()
			} else {
				ip4 := ipn.IP.To4()
				ni.Suggest = fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
			}
			if ipn.IP.IsLinkLocalUnicast() {
				linkLocal = append(linkLocal, ni)
			} else {
				out = append(out, ni)
			}
		}
	}
	for i := range linkLocal { // 169.254/16 is huge and rarely what you want
		linkLocal[i].Suggest = ""
	}
	return append(out, linkLocal...)
}

// ---- MAC vendor (IEEE OUI / MA-M / MA-S) ----------------------------------------------

//go:embed oui.txt.gz
var ouiGz []byte

var (
	ouiOnce  sync.Once
	ouiBlob  []byte
	ouiLines []uint32 // offsets of each "PREFIX\tVendor\n" line, sorted by prefix
)

func loadOUI() {
	zr, err := gzip.NewReader(bytes.NewReader(ouiGz))
	if err != nil {
		return
	}
	ouiBlob, _ = io.ReadAll(zr)
	ouiLines = make([]uint32, 0, 60000)
	start := 0
	for i, c := range ouiBlob {
		if c == '\n' {
			ouiLines = append(ouiLines, uint32(start))
			start = i + 1
		}
	}
	sort.Slice(ouiLines, func(i, j int) bool { return ouiKey(ouiLines[i]) < ouiKey(ouiLines[j]) })
}

func ouiKey(off uint32) string {
	b := ouiBlob[off:]
	return string(b[:bytes.IndexByte(b, '\t')])
}

func ouiVal(off uint32) string {
	b := ouiBlob[off:]
	b = b[bytes.IndexByte(b, '\t')+1:]
	return string(b[:bytes.IndexByte(b, '\n')])
}

func ouiVendor(mac string) string {
	hexs := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(hexs) != 12 {
		return ""
	}
	if v, _ := strconv.ParseUint(hexs[:2], 16, 8); v&0x02 != 0 {
		return "(private / random MAC)"
	}
	ouiOnce.Do(loadOUI)
	for _, n := range []int{9, 7, 6} { // MA-S, MA-M, MA-L
		k := hexs[:n]
		i := sort.Search(len(ouiLines), func(i int) bool { return ouiKey(ouiLines[i]) >= k })
		if i < len(ouiLines) && ouiKey(ouiLines[i]) == k {
			return ouiVal(ouiLines[i])
		}
	}
	return ""
}
