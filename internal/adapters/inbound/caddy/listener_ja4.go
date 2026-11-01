package caddy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"crypto/tls"
	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(JA4ListenerWrapper{})
}

const (
	tlsRecordHandshake = 0x16
	tlsRecordHeaderLen = 5
	// maxTLSRecordLen is the largest plaintext TLS record (RFC 8446 5.1).
	maxTLSRecordLen = 1 << 14
)

// JA4ListenerWrapper fingerprints each client's TLS ClientHello. It must sit
// before Caddy's TLS listener so it sees the raw handshake bytes; they are
// replayed unchanged to the real TLS server.
type JA4ListenerWrapper struct{}

// CaddyModule returns the Caddy module information.
func (JA4ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.raiwall_ja4",
		New: func() caddy.Module { return new(JA4ListenerWrapper) },
	}
}

// WrapListener implements caddy.ListenerWrapper.
func (JA4ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &ja4Listener{Listener: l}
}

type ja4Listener struct{ net.Listener }

func (l *ja4Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &ja4Conn{Conn: c, fp: &connFingerprints{}}, nil
}

// ja4Conn buffers the first TLS record on the first Read, derives the JA4
// fingerprint from it, then serves the buffered bytes back to the caller.
type ja4Conn struct {
	net.Conn
	fp      *connFingerprints
	peeked  bool
	pending []byte
	err     error
}

func (c *ja4Conn) fingerprints() *connFingerprints { return c.fp }

func (c *ja4Conn) Read(p []byte) (int, error) {
	if !c.peeked {
		c.peeked = true
		c.peek()
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

// peek reads exactly one TLS record. A client that is not starting a TLS
// handshake (or sends an oversized record) is passed through unfingerprinted.
func (c *ja4Conn) peek() {
	header := make([]byte, tlsRecordHeaderLen)
	n, err := io.ReadFull(c.Conn, header)
	c.pending = header[:n]
	if err != nil {
		c.err = err
		return
	}
	if header[0] != tlsRecordHandshake {
		return
	}
	bodyLen := int(binary.BigEndian.Uint16(header[3:5]))
	if bodyLen == 0 || bodyLen > maxTLSRecordLen {
		return
	}
	body := make([]byte, bodyLen)
	n, err = io.ReadFull(c.Conn, body)
	c.pending = append(c.pending, body[:n]...)
	if err != nil {
		c.err = err
		return
	}
	if ja4 := ja4FromRecord(c.pending, c.Conn); ja4 != "" {
		c.fp.setJA4(ja4)
	}
}

var errStopHandshake = errors.New("raiwall: fingerprint captured")

// ja4FromRecord lets crypto/tls parse a recorded ClientHello so the JA4 input
// is exactly what Go's own server would see. Nothing reaches the network:
// reads come from the record and writes are discarded.
func ja4FromRecord(record []byte, real net.Conn) string {
	var ja4 string
	cfg := &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			ja4 = bot.ComputeJA4(h)
			return nil, errStopHandshake
		},
	}
	_ = tls.Server(&replayConn{Conn: real, r: bytes.NewReader(record)}, cfg).Handshake()
	return ja4
}

// replayConn serves a fixed byte slice and swallows writes, delegating only
// the address methods to the real connection.
type replayConn struct {
	net.Conn
	r *bytes.Reader
}

func (c *replayConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *replayConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *replayConn) Close() error                     { return nil }
func (c *replayConn) SetDeadline(time.Time) error      { return nil }
func (c *replayConn) SetReadDeadline(time.Time) error  { return nil }
func (c *replayConn) SetWriteDeadline(time.Time) error { return nil }
