package browsernet

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func splitHostPort(address string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrBadAddress, err)
	}
	port, err = strconv.Atoi(p)
	if err != nil || port < 0 || port > 65535 {
		return "", 0, fmt.Errorf("%w: invalid port in %q", ErrBadAddress, address)
	}
	return h, port, nil
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func parseNetwork(network string) (stream bool, err error) {
	switch strings.ToLower(network) {
	case "tcp", "tcp4", "tcp6":
		return true, nil
	case "udp", "udp4", "udp6":
		return false, nil
	default:
		return false, fmt.Errorf("%w: %s", ErrNotSupported, network)
	}
}

func isIPLiteral(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

func hostWithoutZone(host string) string {
	if i := strings.LastIndexByte(host, '%'); i != -1 {
		return host[:i]
	}
	return host
}

type pipeAddr struct {
	netw string
	addr string
}

func (a pipeAddr) Network() string { return a.netw }
func (a pipeAddr) String() string  { return a.addr }
