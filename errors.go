package browsernet

import (
	"errors"
	"fmt"
)

var (
	// ErrClosed is returned by I/O on a connection that has been closed.
	ErrClosed = errors.New("browsernet: connection closed")
	// ErrTimeout is returned when a deadline is exceeded.
	ErrTimeout = errors.New("browsernet: i/o timeout")
	// ErrNotSupported is returned for operations the active transport cannot perform.
	ErrNotSupported = errors.New("browsernet: operation not supported")
	// ErrNoGateway is returned on js/wasm when no WebSocket/WebRTC gateway is configured.
	ErrNoGateway = errors.New("browsernet: wasm builds require a WebSocket or WebRTC gateway")
	// ErrSOCKSVersion is returned when the proxy does not speak SOCKS5.
	ErrSOCKSVersion = errors.New("browsernet: unexpected SOCKS version")
	// ErrNoAcceptableAuth is returned when the proxy rejects offered auth methods.
	ErrNoAcceptableAuth = errors.New("browsernet: proxy rejected authentication methods")
	// ErrAuthFailed is returned when username/password authentication fails.
	ErrAuthFailed = errors.New("browsernet: proxy authentication failed")
	// ErrListenClosed is returned by Accept after the listener is closed.
	ErrListenClosed = errors.New("browsernet: listener closed")
	// ErrBadAddress is returned when host:port cannot be parsed.
	ErrBadAddress = errors.New("browsernet: malformed host:port address")
	// ErrWebRTCUnavailable is returned when the runtime has no RTCPeerConnection.
	ErrWebRTCUnavailable = errors.New("browsernet: WebRTC is not available in this runtime")
	// ErrEmptyHost is returned when a lookup is requested for an empty name.
	ErrEmptyHost = errors.New("browsernet: empty hostname")
	// ErrNotConfigured is returned when New is called without a proxy or gateway.
	ErrNotConfigured = errors.New("browsernet: no proxy or gateway configured")
)

// SOCKSReplyError is a SOCKS5 reply code from RFC 1928 section 6.
type SOCKSReplyError byte

func (e SOCKSReplyError) Error() string {
	msg, ok := socksReplyText[byte(e)]
	if !ok {
		msg = "unassigned"
	}
	return fmt.Sprintf("browsernet: socks5 reply %d (%s)", byte(e), msg)
}

var socksReplyText = map[byte]string{
	0x00: "succeeded",
	0x01: "general failure",
	0x02: "connection not allowed",
	0x03: "network unreachable",
	0x04: "host unreachable",
	0x05: "connection refused",
	0x06: "ttl expired",
	0x07: "command not supported",
	0x08: "address type not supported",
}
