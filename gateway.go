package browsernet

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Gateway is the user-infrastructure side of browsernet. It accepts
// WebSocket upgrades and either pipes them to an upstream SOCKS5 proxy
// or speaks SOCKS5 itself and dials destinations.
type Gateway struct {
	// Upstream is an optional socks5 host:port. Empty means direct dial.
	Upstream string
	// DialTimeout bounds outbound CONNECT dials in direct mode.
	DialTimeout time.Duration
}

// Handler returns an http.Handler that upgrades WebSocket connections.
func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(g.ServeHTTP)
}

// ServeHTTP upgrades a WebSocket and runs the tunnel.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	conn, err := upgradeWebSocket(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer conn.Close()
	if g.Upstream != "" {
		up, err := net.DialTimeout("tcp", g.Upstream, timeoutOr(g.DialTimeout, 15*time.Second))
		if err != nil {
			return
		}
		pipeConns(conn, up)
		return
	}
	ServeSOCKS5(conn, timeoutOr(g.DialTimeout, 20*time.Second))
}

// ServeSOCKS5 implements a minimal RFC 1928 CONNECT server on conn.
func ServeSOCKS5(conn net.Conn, dialTimeout time.Duration) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != socksVer5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{socksVer5, socksAuthNone}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	host, err := readSOCKSHost(conn, req[3])
	if err != nil {
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(conn, pb[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb[:]))
	if req[1] != socksCmdConnect {
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), dialTimeout)
	if err != nil {
		_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	rep := []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	if ta, ok := up.LocalAddr().(*net.TCPAddr); ok && ta.IP.To4() != nil {
		rep = []byte{5, 0, 0, 1}
		rep = append(rep, ta.IP.To4()...)
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], uint16(ta.Port))
		rep = append(rep, p[:]...)
	}
	if _, err := conn.Write(rep); err != nil {
		_ = up.Close()
		return
	}
	pipeConns(conn, up)
}

func pipeConns(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
}

func timeoutOr(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, fmt.Errorf("websocket upgrade required")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("hijack unsupported")
	}
	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	accept := gatewayWSAccept(key)
	_, err = bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	leftover := make([]byte, bufrw.Reader.Buffered())
	if len(leftover) > 0 {
		_, _ = io.ReadFull(bufrw.Reader, leftover)
	}
	return newWSConn(conn, leftover, false), nil
}

func gatewayWSAccept(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sum := sha1.Sum([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(sum[:])
}
