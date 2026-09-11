package browsernet

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// SDN is a client-side Software-Defined Network. It implements the
// DialContext surface that http.Transport, gRPC, pgx and other clients
// already accept, plus a virtual Listener and a replaceable DefaultResolver.
type SDN struct {
	cfg      Config
	dialer   streamDialer
	resolver *Resolver

	mu     sync.RWMutex
	closed bool
}

// New constructs an SDN from a proxy URL and options.
func New(proxyURL string, opts ...Option) (*SDN, error) {
	cfg, err := applyOptions(proxyURL, opts)
	if err != nil {
		return nil, err
	}
	s := &SDN{cfg: cfg}
	d, err := s.buildDialer()
	if err != nil {
		return nil, err
	}
	s.dialer = d
	s.resolver = newResolver(s)
	return s, nil
}

// NewSDN is the architecture-spec alias of New.
func NewSDN(proxyURL string, opts ...Option) (*SDN, error) {
	return New(proxyURL, opts...)
}

// Dialer returns a *net.Dialer whose Resolver is the SDN resolver.
func (s *SDN) Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   s.cfg.DialTimeout,
		KeepAlive: s.cfg.KeepAlive,
		Resolver:  s.resolver.NetResolver(),
	}
}

// DialContext opens a tunneled connection. network is tcp/tcp4/tcp6/udp*.
func (s *SDN) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	stream, err := parseNetwork(network)
	if err != nil {
		return nil, err
	}
	if !stream {
		return s.dialUDP(ctx, address)
	}
	return s.dialReady(ctx, network, address)
}

// Dial is DialContext with a background context.
func (s *SDN) Dial(network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.DialTimeout)
	defer cancel()
	return s.DialContext(ctx, network, address)
}

// DialTLS dials then performs crypto/tls inside process memory.
func (s *SDN) DialTLS(ctx context.Context, network, address string, cfg *tls.Config) (net.Conn, error) {
	raw, err := s.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	cfg = TLSConfig(address, cfg)
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

// Listen opens a virtual net.Listener via SOCKS5 BIND.
func (s *SDN) Listen(network, address string) (net.Listener, error) {
	return s.ListenContext(context.Background(), network, address)
}

// ListenContext is Listen with a cancelable bind handshake.
func (s *SDN) ListenContext(ctx context.Context, network, address string) (net.Listener, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	if _, err := parseNetwork(network); err != nil {
		return nil, err
	}
	return newVirtualListener(ctx, s, network, address)
}

// Resolver returns a *net.Resolver that tunnels DNS-over-TCP.
func (s *SDN) Resolver() *net.Resolver {
	return s.resolver.NetResolver()
}

// LookupHost resolves a hostname through the tunnel and in-memory cache.
func (s *SDN) LookupHost(ctx context.Context, host string) ([]string, error) {
	return s.resolver.LookupHost(ctx, host)
}

// Install replaces net.DefaultResolver. It cannot replace net.Dial.
func (s *SDN) Install() {
	net.DefaultResolver = s.Resolver()
}

// HTTPTransport returns an *http.Transport that dials through the SDN.
func (s *SDN) HTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           s.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// HTTPClient returns an *http.Client bound to HTTPTransport.
func (s *SDN) HTTPClient() *http.Client {
	return &http.Client{Transport: s.HTTPTransport()}
}

// Transport is an alias of HTTPTransport.
func (s *SDN) Transport() *http.Transport { return s.HTTPTransport() }

// GRPCDialer is compatible with grpc.WithContextDialer.
func (s *SDN) GRPCDialer(ctx context.Context, address string) (net.Conn, error) {
	return s.DialContext(ctx, "tcp", address)
}

// Close marks the SDN closed. Outstanding connections are not cancelled.
func (s *SDN) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *SDN) guard() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	return nil
}

func (s *SDN) openProxyStream(ctx context.Context) (net.Conn, error) {
	if s.dialer == nil {
		return nil, ErrNotConfigured
	}
	if s.cfg.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.DialTimeout)
		defer cancel()
	}
	return s.dialer.DialStream(ctx)
}

func (s *SDN) dialReady(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	conn, err := s.openProxyStream(ctx)
	if err != nil {
		return nil, err
	}
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	if err := socks5Handshake(conn, s.cfg.Username, s.cfg.Password); err != nil {
		_ = conn.Close()
		return nil, err
	}
	remoteDNS := s.cfg.RemoteDNS || !isIPLiteral(host)
	bound, err := socks5Command(conn, socksCmdConnect, host, port, remoteDNS)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if bound == nil {
		bound = pipeAddr{netw: network, addr: address}
	}
	return conn, nil
}

func (s *SDN) dialUDP(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	ctrl, err := s.openProxyStream(ctx)
	if err != nil {
		return nil, err
	}
	if d, ok := ctx.Deadline(); ok {
		_ = ctrl.SetDeadline(d)
	}
	if err := socks5Handshake(ctrl, s.cfg.Username, s.cfg.Password); err != nil {
		_ = ctrl.Close()
		return nil, err
	}
	relay, err := socks5Command(ctrl, socksCmdUDP, "0.0.0.0", 0, false)
	if err != nil {
		_ = ctrl.Close()
		return nil, err
	}
	_ = ctrl.SetDeadline(time.Time{})
	return newUDPTunnel(ctrl, relay, host, port), nil
}

func (s *SDN) String() string {
	return fmt.Sprintf("browsernet.SDN(proxy=%q gateway=%q)", s.cfg.ProxyURL, s.cfg.Gateway)
}
