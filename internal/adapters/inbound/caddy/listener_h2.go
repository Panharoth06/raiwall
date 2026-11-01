package caddy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"strings"

	"github.com/Panharoth06/raiwall/internal/core/bot"
	"github.com/caddyserver/caddy/v2"
	"golang.org/x/net/http2/hpack"
)

func init() {
	caddy.RegisterModule(H2ListenerWrapper{})
}

const (
	h2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	// h2CaptureLimit bounds how many bytes of a connection are buffered while
	// looking for the opening SETTINGS, WINDOW_UPDATE and HEADERS frames.
	h2CaptureLimit = 16 << 10

	h2FrameHeaders      = 0x1
	h2FrameSettings     = 0x4
	h2FrameWindowUpdate = 0x8
	h2FrameHeaderLen    = 9

	h2FlagPadded   = 0x8
	h2FlagPriority = 0x20
)

// H2ListenerWrapper fingerprints the opening frames of HTTP/2 connections.
// It must sit after Caddy's TLS listener so it sees decrypted bytes.
type H2ListenerWrapper struct{}

// CaddyModule returns the Caddy module information.
func (H2ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.raiwall_h2",
		New: func() caddy.Module { return new(H2ListenerWrapper) },
	}
}

// WrapListener implements caddy.ListenerWrapper.
func (H2ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &h2Listener{Listener: l}
}

type h2Listener struct{ net.Listener }

func (l *h2Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	hc := &h2Conn{Conn: c, fp: &connFingerprints{}}
	// net/http treats any conn exposing ConnectionState as TLS, so only wrap
	// connections that can answer it; anything else passes through untouched.
	if _, ok := c.(interface{ ConnectionState() tls.ConnectionState }); !ok {
		return c, nil
	}
	return hc, nil
}

// h2Conn tees the first bytes read from an HTTP/2 connection into a frame
// parser. It forwards the TLS surface (ConnectionState, HandshakeContext) that
// net/http uses to detect and negotiate HTTP/2.
type h2Conn struct {
	net.Conn
	fp *connFingerprints

	state   int // 0 unchecked, 1 capturing, 2 done
	buf     []byte
	scratch hpack.Decoder
}

func (c *h2Conn) fingerprints() *connFingerprints { return c.fp }

// NetConn lets connectionFingerprints unwrap to the TLS conn and beyond.
func (c *h2Conn) NetConn() net.Conn { return c.Conn }

func (c *h2Conn) ConnectionState() tls.ConnectionState {
	return c.Conn.(interface{ ConnectionState() tls.ConnectionState }).ConnectionState()
}

func (c *h2Conn) HandshakeContext(ctx context.Context) error {
	if h, ok := c.Conn.(interface{ HandshakeContext(context.Context) error }); ok {
		return h.HandshakeContext(ctx)
	}
	return nil
}

func (c *h2Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.observe(p[:n])
	}
	return n, err
}

func (c *h2Conn) observe(data []byte) {
	if c.state == 0 {
		if c.ConnectionState().NegotiatedProtocol != "h2" {
			c.state = 2
			return
		}
		c.state = 1
	}
	if c.state != 1 {
		return
	}
	c.buf = append(c.buf, data...)
	if len(c.buf) > h2CaptureLimit {
		c.finish()
		return
	}
	if c.parse() {
		c.finish()
	}
}

func (c *h2Conn) finish() {
	c.state = 2
	c.buf = nil
}

// parse walks the buffered preface and frames. It returns true once the first
// HEADERS frame (or an unparseable stream) ends the capture.
func (c *h2Conn) parse() bool {
	buf := c.buf
	if len(buf) < len(h2Preface) {
		return false
	}
	if string(buf[:len(h2Preface)]) != h2Preface {
		return true
	}
	buf = buf[len(h2Preface):]

	fp := &bot.HTTP2Fingerprint{}
	for {
		if len(buf) < h2FrameHeaderLen {
			return false
		}
		length := int(buf[0])<<16 | int(buf[1])<<8 | int(buf[2])
		ftype, flags := buf[3], buf[4]
		if len(buf) < h2FrameHeaderLen+length {
			return false
		}
		payload := buf[h2FrameHeaderLen : h2FrameHeaderLen+length]
		buf = buf[h2FrameHeaderLen+length:]

		switch ftype {
		case h2FrameSettings:
			for i := 0; i+6 <= len(payload); i += 6 {
				fp.Settings = append(fp.Settings, bot.HTTP2Setting{
					ID:    binary.BigEndian.Uint16(payload[i:]),
					Value: binary.BigEndian.Uint32(payload[i+2:]),
				})
			}
		case h2FrameWindowUpdate:
			if len(payload) == 4 && fp.WindowUpdate == 0 {
				fp.WindowUpdate = binary.BigEndian.Uint32(payload) & 0x7fffffff
			}
		case h2FrameHeaders:
			fp.PseudoHeaderOrder = pseudoHeaderOrder(payload, flags)
			fp.RawString = bot.ComputeH2Fingerprint(fp)
			fp.Hash = bot.ComputeH2Hash(fp)
			c.fp.setH2(fp)
			return true
		}
	}
}

// pseudoHeaderOrder HPACK-decodes the first header block fragment and returns
// the pseudo-header order using the m,a,s,p letters of the Akamai format.
func pseudoHeaderOrder(payload []byte, flags byte) []string {
	if flags&h2FlagPadded != 0 {
		if len(payload) < 1 {
			return nil
		}
		pad := int(payload[0])
		payload = payload[1:]
		if pad > len(payload) {
			return nil
		}
		payload = payload[:len(payload)-pad]
	}
	if flags&h2FlagPriority != 0 {
		if len(payload) < 5 {
			return nil
		}
		payload = payload[5:]
	}

	var order []string
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if !strings.HasPrefix(f.Name, ":") {
			return
		}
		switch f.Name {
		case ":method":
			order = append(order, "m")
		case ":authority":
			order = append(order, "a")
		case ":scheme":
			order = append(order, "s")
		case ":path":
			order = append(order, "p")
		}
	})
	// A fragment cut at CONTINUATION still yields the leading pseudo-headers.
	_, _ = dec.Write(payload)
	return order
}
