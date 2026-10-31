package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// RedisClient defines the client methods required by RedisStorage.
type RedisClient interface {
	Eval(ctx context.Context, script string, keys []string, args ...any) (any, error)
	Del(ctx context.Context, keys ...string) error
	Ping(ctx context.Context) error
	Close() error
}

// dialFunc opens a raw TCP connection. Tests inject in-memory pipes through it.
type dialFunc func(network, addr string) (net.Conn, error)

// SimpleRESPClient is a dependency-free Redis client. Commands share one
// mutex-guarded connection; Subscribe uses a dedicated connection per call.
// Full Sentinel/Cluster support is tracked in TASKS.md 4.1.
type SimpleRESPClient struct {
	addr     string
	timeout  time.Duration
	username string
	password string
	tlsCfg   *tls.Config
	opts     Options

	dialer atomic.Pointer[dialFunc]

	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader

	closed atomic.Bool
	// subCtx cancels every active subscription when the client closes.
	subCtx    context.Context
	subCancel context.CancelFunc
	subWG     sync.WaitGroup
}

// NewSimpleRESPClient creates an unauthenticated, plaintext client. It is kept
// for callers that predate Options.
func NewSimpleRESPClient(addr string, timeout time.Duration) *SimpleRESPClient {
	c, _ := NewRESPClient(Options{Addr: addr, Timeout: timeout})
	return c
}

// NewRESPClient builds a client with AUTH and TLS support. It does not connect;
// the first command dials lazily.
func NewRESPClient(opts Options) (*SimpleRESPClient, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	opts = opts.withDefaults()
	tlsCfg, err := opts.tlsConfig()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &SimpleRESPClient{
		addr:      opts.Addr,
		timeout:   opts.Timeout,
		username:  opts.Username,
		password:  opts.Password,
		tlsCfg:    tlsCfg,
		opts:      opts,
		subCtx:    ctx,
		subCancel: cancel,
	}, nil
}

// SetDialer overrides the network dialer.
func (c *SimpleRESPClient) SetDialer(dialer func(network, addr string) (net.Conn, error)) {
	d := dialFunc(dialer)
	c.dialer.Store(&d)
}

// Close closes the command connection and stops every subscription.
func (c *SimpleRESPClient) Close() error {
	c.closed.Store(true)
	c.subCancel()
	c.subWG.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropConnLocked()
}

func (c *SimpleRESPClient) dropConnLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn, c.reader = nil, nil
	return err
}

// do runs one command on the shared connection. A server error reply keeps the
// connection; any I/O failure discards it so the next call redials.
func (c *SimpleRESPClient) do(ctx context.Context, parts ...string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		conn, reader, err := c.dialConn(ctx)
		if err != nil {
			return nil, err
		}
		c.conn, c.reader = conn, reader
	}
	_ = c.conn.SetDeadline(c.deadline(ctx))
	if _, err := c.conn.Write(buildRESPCommand(parts...)); err != nil {
		_ = c.dropConnLocked()
		return nil, err
	}
	resp, err := parseRESP(c.reader)
	if err != nil {
		var serverErr respError
		if !errors.As(err, &serverErr) {
			_ = c.dropConnLocked()
		}
		return nil, err
	}
	return resp, nil
}

// Ping checks that Redis is reachable.
func (c *SimpleRESPClient) Ping(ctx context.Context) error {
	_, err := c.do(ctx, "PING")
	return err
}

// Del deletes keys.
func (c *SimpleRESPClient) Del(ctx context.Context, keys ...string) error {
	_, err := c.do(ctx, append([]string{"DEL"}, keys...)...)
	return err
}

// Eval evaluates a Lua script.
func (c *SimpleRESPClient) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	parts := []string{"EVAL", script, strconv.Itoa(len(keys))}
	parts = append(parts, keys...)
	for _, a := range args {
		parts = append(parts, fmt.Sprintf("%v", a))
	}
	return c.do(ctx, parts...)
}

// Get returns the value at key, or ErrNil when the key does not exist.
func (c *SimpleRESPClient) Get(ctx context.Context, key string) (string, error) {
	resp, err := c.do(ctx, "GET", key)
	if err != nil {
		return "", err
	}
	s, ok := resp.(string)
	if !ok {
		return "", ErrNil
	}
	return s, nil
}

// Set stores value at key. A non-positive ttl stores it without expiry.
func (c *SimpleRESPClient) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	parts := []string{"SET", key, value}
	if ttl > 0 {
		parts = append(parts, "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	}
	_, err := c.do(ctx, parts...)
	return err
}

// Publish sends message to channel.
func (c *SimpleRESPClient) Publish(ctx context.Context, channel, message string) error {
	_, err := c.do(ctx, "PUBLISH", channel, message)
	return err
}
