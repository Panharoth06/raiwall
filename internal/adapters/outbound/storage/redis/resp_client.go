package redis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RedisClient defines the client methods required by RedisStorage.
type RedisClient interface {
	Eval(ctx context.Context, script string, keys []string, args ...any) (any, error)
	Del(ctx context.Context, keys ...string) error
	Ping(ctx context.Context) error
	Close() error
}

// SimpleRESPClient is a zero-dependency, pure-Go Redis client implementing RedisClient.
type SimpleRESPClient struct {
	addr    string
	timeout time.Duration
	dialer  func(network, addr string) (net.Conn, error)
	mu      sync.Mutex
	conn    net.Conn
	reader  *bufio.Reader
}

// NewSimpleRESPClient creates a SimpleRESPClient connected to addr.
func NewSimpleRESPClient(addr string, timeout time.Duration) *SimpleRESPClient {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &SimpleRESPClient{
		addr:    addr,
		timeout: timeout,
	}
}

// SetDialer allows overriding the network dialer.
func (c *SimpleRESPClient) SetDialer(dialer func(network, addr string) (net.Conn, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dialer = dialer
}

func (c *SimpleRESPClient) ensureConn() error {
	if c.conn != nil {
		return nil
	}
	var conn net.Conn
	var err error
	if c.dialer != nil {
		conn, err = c.dialer("tcp", c.addr)
	} else {
		conn, err = net.DialTimeout("tcp", c.addr, c.timeout)
	}
	if err != nil {
		return err
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

// Close closes the Redis connection.
func (c *SimpleRESPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.reader = nil
		return err
	}
	return nil
}

// Ping checks if Redis is reachable.
func (c *SimpleRESPClient) Ping(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConn(); err != nil {
		return err
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))

	if _, err := c.conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}
	resp, err := parseRESP(c.reader)
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}
	if s, ok := resp.(string); ok && strings.EqualFold(s, "PONG") {
		return nil
	}
	return nil
}

// Del deletes keys in Redis.
func (c *SimpleRESPClient) Del(ctx context.Context, keys ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConn(); err != nil {
		return err
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))

	cmd := buildRESPCommand(append([]string{"DEL"}, keys...)...)
	if _, err := c.conn.Write(cmd); err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}
	_, err := parseRESP(c.reader)
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// Eval evaluates a Lua script in Redis.
func (c *SimpleRESPClient) Eval(ctx context.Context, script string, keys []string, args ...any) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConn(); err != nil {
		return nil, err
	}
	_ = c.conn.SetDeadline(time.Now().Add(c.timeout))

	cmdParts := []string{"EVAL", script, strconv.Itoa(len(keys))}
	cmdParts = append(cmdParts, keys...)
	for _, a := range args {
		cmdParts = append(cmdParts, fmt.Sprintf("%v", a))
	}

	cmd := buildRESPCommand(cmdParts...)
	if _, err := c.conn.Write(cmd); err != nil {
		c.conn.Close()
		c.conn = nil
		return nil, err
	}
	resp, err := parseRESP(c.reader)
	if err != nil {
		c.conn.Close()
		c.conn = nil
		return nil, err
	}
	return resp, nil
}

func buildRESPCommand(parts ...string) []byte {
	var buf strings.Builder
	buf.WriteString(fmt.Sprintf("*%d\r\n", len(parts)))
	for _, p := range parts {
		buf.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(p), p))
	}
	return []byte(buf.String())
}

func parseRESP(r *bufio.Reader) (any, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) == 0 {
		return nil, errors.New("empty resp line")
	}

	prefix := line[0]
	content := line[1:]

	switch prefix {
	case '+':
		return content, nil
	case '-':
		return nil, errors.New(content)
	case ':':
		return strconv.ParseInt(content, 10, 64)
	case '$':
		length, err := strconv.Atoi(content)
		if err != nil {
			return nil, err
		}
		if length == -1 {
			return nil, nil
		}
		buf := make([]byte, length+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:length]), nil
	case '*':
		count, err := strconv.Atoi(content)
		if err != nil {
			return nil, err
		}
		if count == -1 {
			return nil, nil
		}
		items := make([]any, count)
		for i := 0; i < count; i++ {
			item, err := parseRESP(r)
			if err != nil {
				return nil, err
			}
			items[i] = item
		}
		return items, nil
	default:
		return nil, fmt.Errorf("unknown resp prefix: %c", prefix)
	}
}
