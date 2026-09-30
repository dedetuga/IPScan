package main

import (
	"context"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestParseTargets(t *testing.T) {
	cases := map[string]int{
		"192.168.1.0/24":                 254,
		"192.168.1.10-20":                11,
		"192.168.1.250-192.168.2.5":      12,
		"10.0.0.1, 10.0.0.1 10.0.0.2":    2,
		"10.0.0.0/31":                    2,
		"10.0.0.7/32":                    1,
		"10.0.0.0/30\n10.0.0.1-10.0.0.3": 3,
		"172.16.0.0/16":                  65534,
	}
	for in, want := range cases {
		got, err := parseTargets(in)
		if err != nil || len(got) != want {
			t.Errorf("%q: got %d (%v), want %d", in, len(got), err, want)
		}
	}
	for _, bad := range []string{"", "10.0.0.0/8", "1.2.3.4-1.3.4.5", "fe80::1", "10.0.0.300", "1.2.3.4-x"} {
		if _, err := parseTargets(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestParsePorts(t *testing.T) {
	got, err := parsePorts("443, 22,80 8000-8002,22")
	if err != nil || !reflect.DeepEqual(got, []int{22, 80, 443, 8000, 8001, 8002}) {
		t.Fatalf("got %v %v", got, err)
	}
	if p, err := parsePorts(""); err != nil || len(p) != 0 {
		t.Fatalf("empty: %v %v", p, err)
	}
	for _, bad := range []string{"0", "65536", "80-22", "1-2000", "http"} {
		if _, err := parsePorts(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestOUI(t *testing.T) {
	for mac, want := range map[string]string{
		"00:40:8c:aa:bb:cc": "Axis",
		"AC-CC-8E-00-00-01": "Axis",
		"24:5a:4c:00:00:01": "Ubiquiti",
		"02:00:00:00:00:01": "(private / random MAC)",
		"":                  "",
	} {
		if got := ouiVendor(mac); got != want {
			t.Errorf("%s: got %q want %q", mac, got, want)
		}
	}
}

// Needs root or a permissive net.ipv4.ping_group_range; skipped otherwise.
func TestPingLoopback(t *testing.T) {
	for _, m := range []string{"raw", "dgram"} {
		os.Setenv("IPSCAN_ICMP", m)
		pg = nil
		initPinger()
		if pingerMode() != m {
			t.Logf("icmp mode %s unavailable here", m)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, ok := ping(ctx, net.ParseIP("127.0.0.1"), time.Second)
		cancel()
		if !ok {
			t.Errorf("%s: no echo reply from 127.0.0.1", m)
		}
	}
	os.Unsetenv("IPSCAN_ICMP")
}
