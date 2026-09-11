package browsernet

import (
	"context"
	"net"
	"net/url"
	"strings"
)

type streamDialer interface {
	DialStream(ctx context.Context) (net.Conn, error)
}

func (s *SDN) buildDialer() (streamDialer, error) {
	target := s.cfg.Gateway
	if target == "" {
		target = s.cfg.ProxyURL
	}
	if target == "" {
		return nil, ErrNotConfigured
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss", "http", "https":
		return newWSDialer(rewriteGatewayURL(u, s.cfg.TunnelPath)), nil
	case "socks5", "socks5h", "socks", "tcp":
		if jsWasm {
			return nil, ErrNoGateway
		}
		host := u.Host
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "1080")
		}
		return &tcpStreamDialer{addr: host}, nil
	default:
		if jsWasm {
			return nil, ErrNoGateway
		}
		return &tcpStreamDialer{addr: target}, nil
	}
}

func rewriteGatewayURL(u *url.URL, tunnelPath string) string {
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}
	if u.Path == "" || u.Path == "/" {
		if tunnelPath == "" {
			tunnelPath = "/tunnel"
		}
		u.Path = tunnelPath
	}
	return u.String()
}

func schemeOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
}
