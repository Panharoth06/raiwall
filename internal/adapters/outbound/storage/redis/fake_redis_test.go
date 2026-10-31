package redis

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeRedis is an in-process RESP server implementing only the commands the
// client uses. It shares state across connections so two clients can exercise
// pub/sub, and can drop every connection to simulate a server restart.
type fakeRedis struct {
	ln       net.Listener
	password string

	mu    sync.Mutex
	data  map[string]string
	subs  map[string]map[*fakeConn]struct{}
	conns map[*fakeConn]struct{}

	authFailures atomic.Int32
	authSuccess  atomic.Int32
	pings        atomic.Int32
	accepted     atomic.Int32
	published    atomic.Int32
}

type fakeConn struct {
	net.Conn
	wmu sync.Mutex
}

func (c *fakeConn) write(s string) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, _ = c.Conn.Write([]byte(s))
}

func startFakeRedis(t *testing.T, password string, tlsCfg *tls.Config) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	f := &fakeRedis{
		ln:       ln,
		password: password,
		data:     make(map[string]string),
		subs:     make(map[string]map[*fakeConn]struct{}),
		conns:    make(map[*fakeConn]struct{}),
	}
	go f.acceptLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		f.dropConnections()
	})
	return f
}

func (f *fakeRedis) addr() string { return f.ln.Addr().String() }

func (f *fakeRedis) acceptLoop() {
	for {
		raw, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.accepted.Add(1)
		fc := &fakeConn{Conn: raw}
		f.mu.Lock()
		f.conns[fc] = struct{}{}
		f.mu.Unlock()
		go f.serve(fc)
	}
}

// dropConnections closes every client connection, as a server restart would.
func (f *fakeRedis) dropConnections() {
	f.mu.Lock()
	conns := make([]*fakeConn, 0, len(f.conns))
	for c := range f.conns {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (f *fakeRedis) subscriberCount(channel string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs[channel])
}

func (f *fakeRedis) serve(fc *fakeConn) {
	defer func() {
		f.mu.Lock()
		delete(f.conns, fc)
		for _, set := range f.subs {
			delete(set, fc)
		}
		f.mu.Unlock()
		_ = fc.Close()
	}()

	reader := bufio.NewReader(fc)
	authed := f.password == ""
	for {
		resp, err := parseRESP(reader)
		if err != nil {
			return
		}
		items, _ := resp.([]any)
		args := make([]string, len(items))
		for i, it := range items {
			args[i], _ = it.(string)
		}
		if len(args) == 0 {
			continue
		}
		fc.write(f.execute(fc, &authed, args))
	}
}

func bulk(s string) string { return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n" }

func (f *fakeRedis) execute(fc *fakeConn, authed *bool, args []string) string {
	cmd := strings.ToUpper(args[0])
	if cmd == "AUTH" {
		if f.password == "" || args[len(args)-1] != f.password {
			f.authFailures.Add(1)
			return "-WRONGPASS invalid username-password pair\r\n"
		}
		f.authSuccess.Add(1)
		*authed = true
		return "+OK\r\n"
	}
	if !*authed {
		return "-NOAUTH Authentication required.\r\n"
	}

	switch cmd {
	case "PING":
		f.pings.Add(1)
		return "+PONG\r\n"
	case "SET":
		f.mu.Lock()
		f.data[args[1]] = args[2]
		f.mu.Unlock()
		return "+OK\r\n"
	case "GET":
		f.mu.Lock()
		v, ok := f.data[args[1]]
		f.mu.Unlock()
		if !ok {
			return "$-1\r\n"
		}
		return bulk(v)
	case "PUBLISH":
		f.published.Add(1)
		return f.publish(args[1], args[2])
	case "SUBSCRIBE":
		f.mu.Lock()
		if f.subs[args[1]] == nil {
			f.subs[args[1]] = make(map[*fakeConn]struct{})
		}
		f.subs[args[1]][fc] = struct{}{}
		f.mu.Unlock()
		return "*3\r\n" + bulk("subscribe") + bulk(args[1]) + ":1\r\n"
	default:
		return "-ERR unknown command\r\n"
	}
}

func (f *fakeRedis) publish(channel, message string) string {
	f.mu.Lock()
	targets := make([]*fakeConn, 0, len(f.subs[channel]))
	for c := range f.subs[channel] {
		targets = append(targets, c)
	}
	f.mu.Unlock()
	frame := "*3\r\n" + bulk("message") + bulk(channel) + bulk(message)
	for _, c := range targets {
		c.write(frame)
	}
	return fmt.Sprintf(":%d\r\n", len(targets))
}

// selfSignedTLS returns a server config for 127.0.0.1 and the PEM path of its
// certificate, which doubles as the CA the client must trust.
func selfSignedTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake-redis"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, caPath
}
