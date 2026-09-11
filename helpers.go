package browsernet

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// PGXDialFunc matches github.com/jackc/pgx/v5/pgconn.Config.DialFunc.
func (s *SDN) PGXDialFunc() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.DialContext
}

// PQDialer implements github.com/lib/pq.Dialer and pq.DialerContext.
type PQDialer struct{ SDN *SDN }

func (d PQDialer) Dial(network, address string) (net.Conn, error) {
	return d.SDN.Dial(network, address)
}

func (d PQDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.SDN.DialContext(ctx, network, address)
}

func (d PQDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.SDN.DialContext(ctx, network, address)
}

// MySQLDialFunc matches github.com/go-sql-driver/mysql RegisterDialContext.
func (s *SDN) MySQLDialFunc() func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		return s.DialContext(ctx, "tcp", addr)
	}
}

// RedisDialer matches github.com/redis/go-redis/v9 Options.Dialer.
func (s *SDN) RedisDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.DialContext
}

// TLSConfig fills ServerName from address when the base config leaves it empty.
func TLSConfig(address string, base *tls.Config) *tls.Config {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if base == nil {
		return &tls.Config{ServerName: host}
	}
	cfg := base.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	return cfg
}

var (
	globalMu   sync.RWMutex
	defaultSDN *SDN
)

// InstallGlobal stores s as the package-level SDN and calls s.Install().
func InstallGlobal(s *SDN) {
	globalMu.Lock()
	defaultSDN = s
	globalMu.Unlock()
	if s != nil {
		s.Install()
	}
}

// DefaultSDN returns the last SDN passed to InstallGlobal.
func DefaultSDN() *SDN {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return defaultSDN
}
