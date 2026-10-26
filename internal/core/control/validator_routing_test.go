package control

import (
	"testing"
)

func TestValidateAppRouting(t *testing.T) {
	base := func(mutate func(*AppConfig)) *AppConfig {
		app := &AppConfig{
			ID:            "site-1",
			Name:          "Site",
			Hostnames:     []string{"app.example.com"},
			RoutingType:   RoutingProxy,
			SSLMode:       SSLModeNone,
			LoadBalancing: LoadBalanceRoundRobin,
			Ports:         []ListeningPort{{Port: 80, Scheme: "http"}},
		}
		if mutate != nil {
			mutate(app)
		}
		return app
	}

	t.Run("valid proxy app", func(t *testing.T) {
		if errs := validateAppRouting(base(nil)); len(errs) != 0 {
			t.Fatalf("unexpected errors: %+v", errs)
		}
	})

	t.Run("https port requires tls", func(t *testing.T) {
		app := base(func(a *AppConfig) {
			a.Ports = []ListeningPort{{Port: 80, Scheme: "http"}, {Port: 443, Scheme: "https"}}
		})
		errs := validateAppRouting(app)
		if len(errs) != 1 || errs[0].Field != "ssl_mode" {
			t.Fatalf("expected ssl_mode error, got %+v", errs)
		}
	})

	t.Run("https port with auto tls is valid", func(t *testing.T) {
		app := base(func(a *AppConfig) {
			a.SSLMode = SSLModeAuto
			a.Ports = []ListeningPort{{Port: 443, Scheme: "https"}}
		})
		if errs := validateAppRouting(app); len(errs) != 0 {
			t.Fatalf("unexpected errors: %+v", errs)
		}
	})

	t.Run("manual tls requires certificate", func(t *testing.T) {
		app := base(func(a *AppConfig) { a.SSLMode = SSLModeManual })
		errs := validateAppRouting(app)
		if len(errs) != 1 || errs[0].Field != "certificate_id" {
			t.Fatalf("expected certificate_id error, got %+v", errs)
		}
	})

	t.Run("static routing requires absolute root", func(t *testing.T) {
		app := base(func(a *AppConfig) {
			a.RoutingType = RoutingStatic
			a.DocumentRoot = "relative/path"
		})
		errs := validateAppRouting(app)
		if len(errs) != 1 || errs[0].Field != "document_root" {
			t.Fatalf("expected document_root error, got %+v", errs)
		}
	})

	t.Run("static routing accepts absolute root", func(t *testing.T) {
		app := base(func(a *AppConfig) {
			a.RoutingType = RoutingStatic
			a.DocumentRoot = "/srv/www"
		})
		if errs := validateAppRouting(app); len(errs) != 0 {
			t.Fatalf("unexpected errors: %+v", errs)
		}
	})

	t.Run("redirect rejects relative-looking host", func(t *testing.T) {
		app := base(func(a *AppConfig) {
			a.RoutingType = RoutingRedirect
			a.RedirectURL = "example.com/landing"
			a.RedirectStatus = 301
		})
		errs := validateAppRouting(app)
		if len(errs) != 1 || errs[0].Field != "redirect_url" {
			t.Fatalf("expected redirect_url error, got %+v", errs)
		}
	})

	t.Run("redirect rejects unsupported status", func(t *testing.T) {
		app := base(func(a *AppConfig) {
			a.RoutingType = RoutingRedirect
			a.RedirectURL = "https://example.com/landing"
			a.RedirectStatus = 200
		})
		errs := validateAppRouting(app)
		if len(errs) != 1 || errs[0].Field != "redirect_status" {
			t.Fatalf("expected redirect_status error, got %+v", errs)
		}
	})

	t.Run("balances policy validated", func(t *testing.T) {
		app := base(func(a *AppConfig) { a.LoadBalancing = "random" })
		errs := validateAppRouting(app)
		if len(errs) != 1 || errs[0].Field != "load_balancing" {
			t.Fatalf("expected load_balancing error, got %+v", errs)
		}
	})
}
