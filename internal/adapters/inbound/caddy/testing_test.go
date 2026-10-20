package caddy

import "net/http"

type mockNextHandler struct {
	invoked      bool
	statusCode   int
	body         string
	receivedHead http.Header
}

func (m *mockNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.invoked = true
	m.receivedHead = r.Header.Clone()
	if m.statusCode != 0 {
		w.WriteHeader(m.statusCode)
	}
	if m.body != "" {
		_, _ = w.Write([]byte(m.body))
	}
	return nil
}
