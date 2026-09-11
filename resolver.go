package browsernet

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Resolver looks up hostnames through the SDN tunnel and an in-memory cache.
type Resolver struct {
	sdn   *SDN
	ttl   time.Duration
	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	addrs []net.IPAddr
	exp   time.Time
}

func newResolver(s *SDN) *Resolver {
	return &Resolver{sdn: s, ttl: s.cfg.DNSCacheTTL, cache: map[string]cacheEntry{}}
}

// NetResolver returns a *net.Resolver whose Dial tunnels DNS-over-TCP.
func (r *Resolver) NetResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return r.sdn.dialReady(ctx, "tcp", r.sdn.cfg.DNSServer)
		},
	}
}

// LookupHost implements the spec-level DNS entry point.
func (r *Resolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := r.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP.String())
	}
	return out, nil
}

// LookupIPAddr resolves host through cache, IP literals, or DNS-over-TCP.
func (r *Resolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = hostWithoutZone(host)
	if host == "" {
		return nil, ErrEmptyHost
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IPAddr{{IP: ip}}, nil
	}
	if addrs, ok := r.get(host); ok {
		return addrs, nil
	}
	addrs, err := r.lookupDNSTCP(ctx, host)
	if err != nil {
		return nil, err
	}
	r.put(host, addrs)
	return addrs, nil
}

func (r *Resolver) lookupDNSTCP(ctx context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, qtype := range []uint16{1, 28} {
		addrs, err := r.lookupType(ctx, host, qtype)
		if err != nil {
			if qtype == 1 && len(out) == 0 {
				return nil, err
			}
			continue
		}
		out = append(out, addrs...)
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

func (r *Resolver) lookupType(ctx context.Context, host string, qtype uint16) ([]net.IPAddr, error) {
	msg := buildDNSQuery(host, qtype)
	conn, err := r.sdn.dialReady(ctx, "tcp", r.sdn.cfg.DNSServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := conn.Write(append(hdr[:], msg...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n <= 0 || n > 4096 {
		return nil, fmt.Errorf("browsernet: bad dns length %d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return parseDNSAnswers(resp, qtype)
}

func (r *Resolver) get(host string) ([]net.IPAddr, bool) {
	if r.ttl <= 0 {
		return nil, false
	}
	r.mu.RLock()
	ent, ok := r.cache[host]
	r.mu.RUnlock()
	if !ok || time.Now().After(ent.exp) {
		return nil, false
	}
	out := make([]net.IPAddr, len(ent.addrs))
	copy(out, ent.addrs)
	return out, true
}

func (r *Resolver) put(host string, addrs []net.IPAddr) {
	if r.ttl <= 0 {
		return
	}
	cp := make([]net.IPAddr, len(addrs))
	copy(cp, addrs)
	r.mu.Lock()
	r.cache[host] = cacheEntry{addrs: cp, exp: time.Now().Add(r.ttl)}
	r.mu.Unlock()
}

// Purge drops cached lookups.
func (r *Resolver) Purge() {
	r.mu.Lock()
	r.cache = map[string]cacheEntry{}
	r.mu.Unlock()
}

func buildDNSQuery(name string, qtype uint16) []byte {
	id := uint16(time.Now().UnixNano())
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	buf = append(buf, encodeDNSName(name)...)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1)
	return append(buf, tail[:]...)
}

func encodeDNSName(name string) []byte {
	var out []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			out = append(out, byte(len(label)))
			out = append(out, label...)
			start = i + 1
		}
	}
	return append(out, 0)
}

func parseDNSAnswers(msg []byte, want uint16) ([]net.IPAddr, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("browsernet: short dns message")
	}
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	var err error
	off, err = skipDNSName(msg, off)
	if err != nil {
		return nil, err
	}
	off += 4
	var addrs []net.IPAddr
	for i := 0; i < ancount && off+10 <= len(msg); i++ {
		off, err = skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			break
		}
		if typ == want {
			switch typ {
			case 1:
				if rdlen == 4 {
					ip := make(net.IP, 4)
					copy(ip, msg[off:off+4])
					addrs = append(addrs, net.IPAddr{IP: ip})
				}
			case 28:
				if rdlen == 16 {
					ip := make(net.IP, 16)
					copy(ip, msg[off:off+16])
					addrs = append(addrs, net.IPAddr{IP: ip})
				}
			}
		}
		off += rdlen
	}
	return addrs, nil
}

func skipDNSName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, fmt.Errorf("browsernet: truncated dns name")
		}
		l := int(msg[off])
		if l == 0 {
			return off + 1, nil
		}
		if l&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return 0, fmt.Errorf("browsernet: truncated dns pointer")
			}
			return off + 2, nil
		}
		off += 1 + l
	}
}
