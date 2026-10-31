package redis

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrNil is returned by Get when the key does not exist. MockRedisClient returns
// the same sentinel so callers can treat both clients uniformly.
var ErrNil = errors.New("redis: nil")

// respError is an error reply sent by the server (a RESP "-" line). Unlike an
// I/O failure it leaves the connection in a consistent state, so the client
// keeps the connection open after receiving one.
type respError string

func (e respError) Error() string { return string(e) }

func buildRESPCommand(parts ...string) []byte {
	var buf strings.Builder
	fmt.Fprintf(&buf, "*%d\r\n", len(parts))
	for _, p := range parts {
		fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(p), p)
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
		return nil, respError(content)
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
			var serverErr respError
			if errors.As(err, &serverErr) {
				// Keep reading so the remaining elements do not desynchronise the stream.
				items[i] = serverErr
				continue
			}
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
