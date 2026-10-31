// Command upstream is the echo backend used by the CRS parity harness. The
// regression corpus asserts status codes only (no response-body expectations),
// so a 200 that echoes the request is enough for allowed traffic.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultAddr  = "127.0.0.1:19090"
	maxEchoBody  = 64 << 10
	readTimeout  = 10 * time.Second
	writeTimeout = 10 * time.Second
	idleTimeout  = 30 * time.Second
)

func main() {
	addr := defaultAddr
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
	server.Handler = http.HandlerFunc(echo)
	log.Printf("CRS upstream listening on %s", addr)
	log.Fatal(server.ListenAndServe())
}

func echo(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxEchoBody))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s %s\n", r.Method, r.RequestURI)
	for name, values := range r.Header {
		fmt.Fprintf(w, "%s: %s\n", name, strings.Join(values, ", "))
	}
	_, _ = w.Write(body)
}
