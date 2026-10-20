package bot

import (
	"bytes"
	"strings"
	"testing"
)

func TestHoneypotInjector_StaticHTML(t *testing.T) {
	injector := NewHoneypotInjector(DefaultTrapPath)

	staticHTML := `<!DOCTYPE html>
<html>
<head><title>My Static Site</title></head>
<body>
  <h1>Welcome to my static site</h1>
  <p>Static article content</p>
</body>
</html>`

	injected, ok := injector.Inject([]byte(staticHTML))
	if !ok {
		t.Fatalf("Expected honeypot to be injected into static HTML")
	}

	injectedStr := string(injected)
	if !strings.Contains(injectedStr, injector.TrapPath()) {
		t.Errorf("Injected HTML missing trap path: %s", injectedStr)
	}
	if !strings.Contains(injectedStr, `style="display:none"`) {
		t.Errorf("Injected HTML missing hidden style")
	}

	// Verify position: before </body>
	bodyIdx := strings.Index(injectedStr, "</body>")
	trapIdx := strings.Index(injectedStr, injector.TrapPath())
	if trapIdx >= bodyIdx {
		t.Errorf("Trap link (%d) should be before </body> (%d)", trapIdx, bodyIdx)
	}

	// Double injection check: re-injecting should be a no-op
	reInjected, reOk := injector.Inject(injected)
	if reOk {
		t.Errorf("Re-injecting already trapped HTML should return ok=false")
	}
	if !bytes.Equal(reInjected, injected) {
		t.Errorf("Re-injected HTML modified unexpectedly")
	}
}

func TestHoneypotInjector_SPAHydrationSafety(t *testing.T) {
	injector := NewHoneypotInjector(DefaultTrapPath)

	spaCases := []struct {
		name string
		html string
	}{
		{
			name: "Next.js SSR page with __next id",
			html: `<!DOCTYPE html><html><head></head><body><div id="__next"><div>App</div></div><script id="__NEXT_DATA__">{}</script></body></html>`,
		},
		{
			name: "React CRA page with root id",
			html: `<!DOCTYPE html><html><head></head><body><div id="root"><div>React App</div></div></body></html>`,
		},
		{
			name: "React SSR with data-reactroot",
			html: `<!DOCTYPE html><html><head></head><body><div data-reactroot=""><h1>SSR React</h1></div></body></html>`,
		},
		{
			name: "Vue / Vite page with app id",
			html: `<!DOCTYPE html><html><head></head><body><div id="app"></div><script src="/src/main.ts"></script></body></html>`,
		},
		{
			name: "Nuxt 3 with __nuxt id",
			html: `<!DOCTYPE html><html><head></head><body><div id="__nuxt">Nuxt App</div><script>window.__NUXT__={}</script></body></html>`,
		},
		{
			name: "Angular with ng-version attribute",
			html: `<!DOCTYPE html><html><head></head><body><app-root ng-version="17.0.0">Angular</app-root></body></html>`,
		},
		{
			name: "SvelteKit hydration marker",
			html: `<!DOCTYPE html><html><head></head><body><div class="svelte-1a2b3c">Svelte Content</div></body></html>`,
		},
	}

	for _, tc := range spaCases {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.html)
			got, injected := injector.Inject(input)

			if injected {
				t.Fatalf("[%s] Injected honeypot into SPA! Hydration safety violated!", tc.name)
			}
			if !bytes.Equal(got, input) {
				t.Fatalf("[%s] SPA HTML was modified! Original bytes must be preserved.", tc.name)
			}
		})
	}
}

func TestIsTrapRequest(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/.raiwall/trap", true},
		{"/.raiwall/trap/", true},
		{"/.raiwall/trap/crawler", true},
		{"/.raiwall/trap/random-token-xyz", true},
		{"/api/v1/trap", false},
		{"/index.html", false},
		{"/.raiwall/challenge/verify", false},
	}

	for _, tt := range tests {
		if got := IsTrapRequest(tt.path); got != tt.want {
			t.Errorf("IsTrapRequest(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
