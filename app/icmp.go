package main

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ICMP echo with whatever the platform allows, in order:
//   raw   — SOCK_RAW (root / CAP_NET_RAW)
//   dgram — unprivileged "ping socket" (needs the process' group inside
//           net.ipv4.ping_group_range)
//   off   — neither: liveness falls back to TCP knocks + ARP, which on a LAN
//           finds hosts that drop ping anyway.
// A single socket and reader serve every concurrent ping.

type pinger struct {
	conn    net.PacketConn
	mode    string
	id      uint16
	seq     uint32
	mu      sync.Mutex
	waiters map[uint64]chan pingReply
}

type pingReply struct {
	at  time.Time
	seq uint16
}

var pg *pinger

func pingerMode() string {
	if pg == nil {
		return "off"
	}
	return pg.mode
}

func initPinger() {
	want := os.Getenv("IPSCAN_ICMP") // "", raw, dgram or off
	if want == "off" {
		return
	}
	var conn net.PacketConn
	mode := ""
	if want != "dgram" {
		if c, err := net.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
			conn, mode = c, "raw"
		}
	}
	if conn == nil && want != "raw" {
		if c, err := listenDgramICMP(); err == nil {
			conn, mode = c, "dgram"
		} else {
			dbg("icmp ping socket unavailable: %v", err)
		}
	}
	if conn == nil {
		return
	}
	pg = &pinger{conn: conn, mode: mode, id: uint16(os.Getpid()), waiters: make(map[uint64]chan pingReply)}
	go pg.readLoop()
}

func listenDgramICMP() (net.PacketConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "icmp-dgram")
	defer f.Close()
	return net.FilePacketConn(f)
}

func key(ip net.IP, seq uint16) uint64 {
	return uint64(binary.BigEndian.Uint32(ip.To4()))<<16 | uint64(seq)
}

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func (p *pinger) readLoop() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := p.conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		b := buf[:n]
		// raw sockets are delivered without the IPv4 header by Go on Linux, as
		// are dgram ping sockets; be defensive in case a header slipped through.
		if len(b) >= 20 && b[0]>>4 == 4 {
			hl := int(b[0]&0x0f) * 4
			if len(b) >= hl+8 && b[hl] == 0 {
				b = b[hl:]
			}
		}
		if len(b) < 8 || b[0] != 0 /* echo reply */ {
			continue
		}
		if p.mode == "raw" && binary.BigEndian.Uint16(b[4:6]) != p.id {
			continue // another process' ping
		}
		var src net.IP
		switch a := addr.(type) {
		case *net.IPAddr:
			src = a.IP
		case *net.UDPAddr:
			src = a.IP
		}
		if src == nil || src.To4() == nil {
			continue
		}
		seq := binary.BigEndian.Uint16(b[6:8])
		k := key(src, seq)
		now := time.Now()
		p.mu.Lock()
		if ch, ok := p.waiters[k]; ok {
			select {
			case ch <- pingReply{now, seq}:
			default:
			}
		}
		p.mu.Unlock()
	}
}

func (p *pinger) send(ip net.IP, seq uint16) error {
	msg := make([]byte, 16)
	msg[0] = 8 // echo request
	binary.BigEndian.PutUint16(msg[4:], p.id)
	binary.BigEndian.PutUint16(msg[6:], seq)
	binary.BigEndian.PutUint64(msg[8:], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(msg[2:], checksum(msg))
	var dst net.Addr = &net.IPAddr{IP: ip}
	if p.mode == "dgram" {
		dst = &net.UDPAddr{IP: ip}
	}
	_, err := p.conn.WriteTo(msg, dst)
	return err
}

// ping sends up to two echo requests (the second at half the timeout) and
// returns the RTT of the first reply.
func ping(ctx context.Context, ip net.IP, timeout time.Duration) (time.Duration, bool) {
	p := pg
	if p == nil {
		return 0, false
	}
	ch := make(chan pingReply, 2)
	var seqs [2]uint16
	var sent [2]time.Time
	register := func(i int) {
		seqs[i] = uint16(atomic.AddUint32(&p.seq, 1))
		p.mu.Lock()
		p.waiters[key(ip, seqs[i])] = ch
		p.mu.Unlock()
		sent[i] = time.Now()
		_ = p.send(ip, seqs[i])
	}
	defer func() {
		p.mu.Lock()
		for _, s := range seqs {
			delete(p.waiters, key(ip, s))
		}
		p.mu.Unlock()
	}()
	register(0)
	retry := time.NewTimer(timeout / 2)
	defer retry.Stop()
	for {
		select {
		case r := <-ch:
			if r.seq == seqs[1] && !sent[1].IsZero() {
				return r.at.Sub(sent[1]), true
			}
			return r.at.Sub(sent[0]), true
		case <-retry.C:
			register(1)
		case <-ctx.Done():
			return 0, false
		}
	}
}
