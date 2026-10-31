package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// deadline returns the earlier of the client timeout and the context deadline.
func (c *SimpleRESPClient) deadline(ctx context.Context) time.Time {
	d := time.Now().Add(c.timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		return cd
	}
	return d
}

func (c *SimpleRESPClient) rawDial(ctx context.Context) (net.Conn, error) {
	if d := c.dialer.Load(); d != nil {
		return (*d)("tcp", c.addr)
	}
	nd := net.Dialer{Timeout: c.timeout}
	return nd.DialContext(ctx, "tcp", c.addr)
}

// dialConn opens a connection, completes the TLS handshake when enabled, and
// authenticates. Both the command and the subscribe connection go through here
// so AUTH is repeated on every reconnect.
func (c *SimpleRESPClient) dialConn(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	conn, err := c.rawDial(ctx)
	if err != nil {
		return nil, nil, err
	}
	if c.tlsCfg != nil {
		tc := tls.Client(conn, c.tlsCfg.Clone())
		_ = tc.SetDeadline(c.deadline(ctx))
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("redis tls handshake with %s: %w", c.addr, err)
		}
		conn = tc
	}
	reader := bufio.NewReader(conn)
	if c.password != "" {
		if err := c.authenticate(ctx, conn, reader); err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
	}
	return conn, reader, nil
}

func (c *SimpleRESPClient) authenticate(ctx context.Context, conn net.Conn, reader *bufio.Reader) error {
	parts := []string{"AUTH"}
	if c.username != "" {
		parts = append(parts, c.username)
	}
	parts = append(parts, c.password)

	_ = conn.SetDeadline(c.deadline(ctx))
	if _, err := conn.Write(buildRESPCommand(parts...)); err != nil {
		return fmt.Errorf("redis auth: %w", err)
	}
	if _, err := parseRESP(reader); err != nil {
		return fmt.Errorf("redis auth: %w", err)
	}
	return nil
}
