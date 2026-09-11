package browsernet

import (
	"net/url"
	"time"
)

// Option configures an SDN instance.
type Option func(*Config)

// Config holds Software-Defined Network settings.
type Config struct {
	ProxyURL    string
	Gateway     string
	Username    string
	Password    string
	DialTimeout time.Duration
	KeepAlive   time.Duration
	DNSCacheTTL time.Duration
	DNSServer   string
	RemoteDNS   bool
	remoteSet   bool
	TunnelPath  string
}

func defaultConfig() Config {
	return Config{
		DialTimeout: 30 * time.Second,
		KeepAlive:   30 * time.Second,
		DNSCacheTTL: 5 * time.Minute,
		DNSServer:   "1.1.1.1:53",
		TunnelPath:  "/tunnel",
	}
}

// WithGateway sets the WebSocket endpoint wasm uses to reach SOCKS5.
func WithGateway(wsURL string) Option {
	return func(c *Config) { c.Gateway = wsURL }
}

// WithCredentials overrides proxy username and password.
func WithCredentials(user, pass string) Option {
	return func(c *Config) {
		c.Username = user
		c.Password = pass
	}
}

// WithTimeout sets the dial and handshake timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Config) { c.DialTimeout = d }
}

// WithRemoteDNS forces SOCKS5 domain ATYP (proxy-side DNS).
func WithRemoteDNS(on bool) Option {
	return func(c *Config) {
		c.RemoteDNS = on
		c.remoteSet = true
	}
}

// WithDNSCacheTTL sets resolver cache lifetime. Pass 0 to disable.
func WithDNSCacheTTL(d time.Duration) Option {
	return func(c *Config) { c.DNSCacheTTL = d }
}

// WithDNSServer sets the recursive resolver used for tunneled DNS-over-TCP.
func WithDNSServer(addr string) Option {
	return func(c *Config) { c.DNSServer = addr }
}

// WithTunnelPath overrides the gateway path (default /tunnel).
func WithTunnelPath(path string) Option {
	return func(c *Config) { c.TunnelPath = path }
}

func applyOptions(proxyURL string, opts []Option) (Config, error) {
	cfg := defaultConfig()
	cfg.ProxyURL = proxyURL
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.ProxyURL == "" && cfg.Gateway == "" {
		return cfg, ErrNotConfigured
	}
	if cfg.Username == "" && cfg.ProxyURL != "" {
		if u, err := url.Parse(cfg.ProxyURL); err == nil && u.User != nil {
			cfg.Username = u.User.Username()
			cfg.Password, _ = u.User.Password()
		}
	}
	if cfg.TunnelPath == "" {
		cfg.TunnelPath = "/tunnel"
	}
	if !cfg.remoteSet {
		scheme := schemeOf(cfg.ProxyURL)
		cfg.RemoteDNS = scheme == "socks5h" || jsWasm
	}
	return cfg, nil
}
