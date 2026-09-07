package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newSecurityTestServer(t *testing.T, proxyHandler http.Handler) *Server {
	t.Helper()
	server, err := NewServer(nil, nil, nil, nil, nil, nil, WithProxyHandler(proxyHandler))
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	return server
}

func TestServer_RejectsNonLoopbackBindWithoutOverride(t *testing.T) {
	if _, err := NewServer(nil, nil, nil, nil, nil, nil, WithBindAddr("0.0.0.0")); err == nil {
		t.Fatal("expected non-loopback bind to require explicit override")
	}
	if _, err := NewServer(nil, nil, nil, nil, nil, nil,
		WithBindAddr("0.0.0.0"), WithUnsafeBind(true)); err != nil {
		t.Fatalf("unsafe bind override should be explicit and accepted: %v", err)
	}
}

func TestServer_RejectsRebindingHostOnLocalAPI(t *testing.T) {
	server := newSecurityTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/status", nil)
	req.Host = "attacker.example"
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusForbidden)
	}
}

func TestServer_AllowsSameOriginStateChange(t *testing.T) {
	server := newSecurityTestServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/quota/refresh", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if res.Code == http.StatusForbidden {
		t.Fatalf("same-origin request was rejected: %s", res.Body.String())
	}
}

func TestServer_RejectsCrossSiteStateChanges(t *testing.T) {
	server := newSecurityTestServer(t, nil)
	tests := []struct {
		name   string
		origin string
		site   string
	}{
		{name: "origin", origin: "https://attacker.example"},
		{name: "fetch metadata", site: "cross-site"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/quota/refresh", nil)
			req.Host = "127.0.0.1"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.site != "" {
				req.Header.Set("Sec-Fetch-Site", tc.site)
			}
			res := httptest.NewRecorder()
			server.ServeHTTP(res, req)
			if res.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", res.Code, http.StatusForbidden)
			}
		})
	}
}

func TestServer_RejectsStateChangeWithoutOrigin(t *testing.T) {
	server := newSecurityTestServer(t, nil)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/quota/refresh", nil)
	req.Host = "127.0.0.1"
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusForbidden)
	}
}

func TestServer_ProtectsOAuthStart(t *testing.T) {
	server := newSecurityTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/oauth/start", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "https://attacker.example")
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusForbidden)
	}
}

func TestServer_PreservesReverseProxyTraffic(t *testing.T) {
	handled := false
	server := newSecurityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent", nil)
	req.Host = "daily-cloudcode-pa.googleapis.com"
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if !handled || res.Code != http.StatusNoContent {
		t.Fatalf("proxy handled=%v status=%d", handled, res.Code)
	}
}

func TestServer_PreservesExplicitForwardProxyTraffic(t *testing.T) {
	handled := false
	server := newSecurityTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://speech.googleapis.com/v1/speech", nil)
	req.Host = "127.0.0.1"
	res := httptest.NewRecorder()
	server.ServeHTTP(res, req)
	if !handled || res.Code != http.StatusNoContent {
		t.Fatalf("proxy handled=%v status=%d", handled, res.Code)
	}
}
