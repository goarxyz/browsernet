package browsernet

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	socksVer5 = 0x05

	socksAuthNone     = 0x00
	socksAuthUser     = 0x02
	socksAuthNoAccept = 0xff
	socksUserPassVer  = 0x01

	socksCmdConnect = 0x01
	socksCmdBind    = 0x02
	socksCmdUDP     = 0x03
	socksCmdResolve = 0xf0

	socksATYPIPv4   = 0x01
	socksATYPDomain = 0x03
	socksATYPIPv6   = 0x04
)

func socks5Handshake(rw io.ReadWriter, user, pass string) error {
	methods := []byte{socksAuthNone}
	if user != "" {
		methods = []byte{socksAuthNone, socksAuthUser}
	}
	req := append([]byte{socksVer5, byte(len(methods))}, methods...)
	if _, err := rw.Write(req); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(rw, resp[:]); err != nil {
		return err
	}
	if resp[0] != socksVer5 {
		return ErrSOCKSVersion
	}
	switch resp[1] {
	case socksAuthNone:
		return nil
	case socksAuthUser:
		return socks5UserPass(rw, user, pass)
	case socksAuthNoAccept:
		return ErrNoAcceptableAuth
	default:
		return fmt.Errorf("%w: method %d", ErrNoAcceptableAuth, resp[1])
	}
}

func socks5UserPass(rw io.ReadWriter, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return ErrAuthFailed
	}
	buf := []byte{socksUserPassVer, byte(len(user))}
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	if _, err := rw.Write(buf); err != nil {
		return err
	}
	var resp [2]byte
	if _, err := io.ReadFull(rw, resp[:]); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return ErrAuthFailed
	}
	return nil
}

func socks5Command(rw io.ReadWriter, cmd byte, host string, port int, remoteDNS bool) (net.Addr, error) {
	req, err := encodeSOCKSRequest(cmd, host, port, remoteDNS)
	if err != nil {
		return nil, err
	}
	if _, err := rw.Write(req); err != nil {
		return nil, err
	}
	return readSOCKSReply(rw)
}

func encodeSOCKSRequest(cmd byte, host string, port int, remoteDNS bool) ([]byte, error) {
	host = hostWithoutZone(host)
	buf := []byte{socksVer5, cmd, 0x00}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil && !remoteDNS:
		buf = append(buf, socksATYPIPv4)
		buf = append(buf, ip.To4()...)
	case ip != nil && ip.To4() == nil && !remoteDNS:
		buf = append(buf, socksATYPIPv6)
		buf = append(buf, ip.To16()...)
	default:
		if host == "" || len(host) > 255 {
			return nil, fmt.Errorf("%w: %q", ErrBadAddress, host)
		}
		buf = append(buf, socksATYPDomain, byte(len(host)))
		buf = append(buf, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	return append(buf, p[:]...), nil
}

func readSOCKSReply(r io.Reader) (net.Addr, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != socksVer5 {
		return nil, ErrSOCKSVersion
	}
	if hdr[1] != 0x00 {
		return nil, SOCKSReplyError(hdr[1])
	}
	host, err := readSOCKSHost(r, hdr[3])
	if err != nil {
		return nil, err
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(p[:]))
	if ip := net.ParseIP(host); ip != nil {
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}
	return pipeAddr{netw: "tcp", addr: joinHostPort(host, port)}, nil
}

func readSOCKSHost(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksATYPIPv4:
		var a [4]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return "", err
		}
		return net.IP(a[:]).String(), nil
	case socksATYPIPv6:
		var a [16]byte
		if _, err := io.ReadFull(r, a[:]); err != nil {
			return "", err
		}
		return net.IP(a[:]).String(), nil
	case socksATYPDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", SOCKSReplyError(0x08)
	}
}

func packUDP(host string, port int, payload []byte) ([]byte, error) {
	req, err := encodeSOCKSRequest(0, host, port, !isIPLiteral(host))
	if err != nil {
		return nil, err
	}
	// UDP header is RSV RSV FRAG + ATYP ADDR PORT + data. Drop VER CMD RSV.
	header := append([]byte{0x00, 0x00, 0x00}, req[3:]...)
	return append(header, payload...), nil
}

func unpackUDP(frame []byte) (host string, port int, payload []byte, err error) {
	if len(frame) < 4 {
		return "", 0, nil, fmt.Errorf("%w: short udp frame", ErrBadAddress)
	}
	if frame[2] != 0 {
		return "", 0, nil, fmt.Errorf("%w: fragmented udp", ErrNotSupported)
	}
	r := &sliceReader{b: frame[4:]}
	host, err = readSOCKSHost(r, frame[3])
	if err != nil {
		return "", 0, nil, err
	}
	if len(r.b) < 2 {
		return "", 0, nil, fmt.Errorf("%w: short udp port", ErrBadAddress)
	}
	port = int(binary.BigEndian.Uint16(r.b[:2]))
	payload = r.b[2:]
	return host, port, payload, nil
}

type sliceReader struct{ b []byte }

func (s *sliceReader) Read(p []byte) (int, error) {
	if len(s.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.b)
	s.b = s.b[n:]
	return n, nil
}
