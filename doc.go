// Package browsernet is a client-side software-defined network for Go.
//
// When Go is compiled with GOOS=js GOARCH=wasm, the standard library has no
// operating-system sockets. net.Dial, net.LookupHost, database/sql drivers,
// gRPC and crypto/tls therefore fail at the syscall layer.
//
// browsernet intercepts the integration points that Go actually exposes
// (DialContext, net.Resolver, net.Listener, http.Transport) and tunnels
// TCP, UDP and TLS through a SOCKS5 proxy that the developer hosts on
// their own infrastructure. In a browser tab the physical hop is a
// WebSocket or a WebRTC DataChannel; on native GOOS the same API speaks
// raw TCP so tests run without a browser.
//
// The browser never sees the destination. It is a blind transport pipe.
// TLS handshakes run inside Wasm memory via crypto/tls.
//
// Integration is explicit. net.Dial cannot be monkey-patched globally.
// Pass SDN.DialContext into http.Transport, pgx, pq, mysql and grpc.
// Call SDN.Install to replace net.DefaultResolver.
package browsernet
