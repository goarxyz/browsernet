//go:build !js

package browsernet

import (
	"context"
	"net"
)

// DialWebRTC is only available on GOOS=js GOARCH=wasm.
func (s *SDN) DialWebRTC(ctx context.Context, peerID string) (net.Conn, error) {
	return nil, ErrWebRTCUnavailable
}

// ListenWebRTC is only available on GOOS=js GOARCH=wasm.
func (s *SDN) ListenWebRTC(ctx context.Context, localID string) (net.Listener, error) {
	return nil, ErrWebRTCUnavailable
}
