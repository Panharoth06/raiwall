package redis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Subscribe delivers message payloads for channel on the returned channel. It
// uses a dedicated connection, reconnects with capped exponential backoff and
// resubscribes after any failure. The channel closes when ctx ends or the
// client closes. Messages published while disconnected are lost; callers
// recover through their snapshot poll fallback.
func (c *SimpleRESPClient) Subscribe(ctx context.Context, channel string) (<-chan string, error) {
	if c.closed.Load() {
		return nil, errors.New("redis: client closed")
	}
	// The first attempt runs synchronously so a bad address or credentials
	// surface to the caller instead of retrying silently in the background.
	conn, reader, err := c.openSubscription(ctx, channel)
	if err != nil {
		return nil, err
	}
	out := make(chan string, subscribeBuffer)
	c.subWG.Add(1)
	go c.subscribeLoop(ctx, channel, conn, reader, out)
	return out, nil
}

func (c *SimpleRESPClient) openSubscription(ctx context.Context, channel string) (net.Conn, *bufio.Reader, error) {
	conn, reader, err := c.dialConn(ctx)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(c.deadline(ctx))
	if _, err := conn.Write(buildRESPCommand("SUBSCRIBE", channel)); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("redis subscribe: %w", err)
	}
	if _, err := parseRESP(reader); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("redis subscribe: %w", err)
	}
	// The handshake deadline must not outlive the handshake: the keep-alive
	// writer would start failing after the command timeout and force
	// reconnects on an otherwise healthy idle subscription.
	_ = conn.SetWriteDeadline(time.Time{})
	if c.opts.OnReconnect != nil {
		c.opts.OnReconnect()
	}
	return conn, reader, nil
}

func (c *SimpleRESPClient) subscribeLoop(ctx context.Context, channel string, conn net.Conn, reader *bufio.Reader, out chan<- string) {
	defer c.subWG.Done()
	defer close(out)

	backoff := c.opts.ReconnectMin
	for {
		if conn != nil {
			if c.readMessages(ctx, conn, reader, out) {
				backoff = c.opts.ReconnectMin
			}
			_ = conn.Close()
			conn = nil
		}
		select {
		case <-ctx.Done():
			return
		case <-c.subCtx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, c.opts.ReconnectMax)

		var err error
		if conn, reader, err = c.openSubscription(ctx, channel); err != nil {
			conn = nil
		}
	}
}

// keepAlive sends PING on a subscribe connection until stop closes. The reply
// arrives as a "pong" frame that readMessages ignores; its only job is to keep
// the read deadline from expiring on a healthy but idle channel.
func (c *SimpleRESPClient) keepAlive(conn net.Conn, stop <-chan struct{}) {
	ticker := time.NewTicker(c.opts.KeepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(c.opts.KeepAlive))
			if _, err := conn.Write(buildRESPCommand("PING")); err != nil {
				return
			}
		}
	}
}

// readMessages pumps messages until the connection fails or a context ends.
// It reports whether the connection delivered anything, which resets backoff.
func (c *SimpleRESPClient) readMessages(ctx context.Context, conn net.Conn, reader *bufio.Reader, out chan<- string) bool {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	stopClient := context.AfterFunc(c.subCtx, func() { _ = conn.Close() })
	defer stopClient()

	// A PING every KeepAlive elicits traffic; silence for several intervals
	// means the socket is half-open. One pinger serves the whole connection.
	stopPing := make(chan struct{})
	defer close(stopPing)
	go c.keepAlive(conn, stopPing)

	delivered := false
	for {
		_ = conn.SetReadDeadline(time.Now().Add(c.opts.KeepAlive * keepAliveMisses))
		resp, err := parseRESP(reader)
		if err != nil {
			return delivered
		}
		items, ok := resp.([]any)
		if !ok || len(items) < 3 {
			continue
		}
		if kind, _ := items[0].(string); kind != "message" {
			continue
		}
		payload, ok := items[2].(string)
		if !ok {
			continue
		}
		delivered = true
		select {
		case out <- payload:
		case <-ctx.Done():
			return delivered
		case <-c.subCtx.Done():
			return delivered
		}
	}
}
