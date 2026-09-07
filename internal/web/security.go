package web

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var errRequestSecurity = errors.New("request failed local security policy")

func isLoopbackAddress(value string) bool {
	host := strings.TrimSpace(strings.ToLower(value))
	if host == "localhost" {
		return true
	}
	return net.ParseIP(strings.Trim(host, "[]")).IsLoopback()
}

func hostWithoutPort(value string) string {
	host := strings.TrimSpace(value)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(strings.Trim(parsed, "[]"))
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func isWildcardAddress(value string) bool {
	host := hostWithoutPort(value)
	return host == "" || host == "0.0.0.0" || host == "::"
}

func sameHost(left, right string) bool {
	return hostWithoutPort(left) == hostWithoutPort(right)
}

func (s *Server) validLocalHost(host string) bool {
	if host == "" {
		return false
	}
	hostName := hostWithoutPort(host)
	if isLoopbackAddress(hostName) {
		return true
	}
	if isWildcardAddress(s.cfg.BindAddr) {
		return false
	}
	return sameHost(hostName, s.cfg.BindAddr)
}

func parseOrigin(value string) (*url.URL, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, false
	}
	return parsed, true
}

func (s *Server) validOrigin(value, requestHost string, proxyRequest bool) bool {
	parsed, ok := parseOrigin(value)
	if !ok {
		return false
	}
	if proxyRequest {
		// Proxy clients normally omit Origin. If a browser supplies one, only a
		// local dashboard origin is accepted; the upstream Host is not a local
		// origin and must not be used for CSRF validation.
		return isLoopbackAddress(parsed.Hostname())
	}
	if !s.validLocalHost(requestHost) || !sameHost(parsed.Host, requestHost) {
		return false
	}
	return true
}

func (s *Server) validateRequestSecurity(r *http.Request, proxyRequest bool) error {
	if site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); site == "cross-site" {
		return fmt.Errorf("%w: cross-site Sec-Fetch-Site is not permitted", errRequestSecurity)
	}

	if !proxyRequest && !s.validLocalHost(r.Host) {
		return fmt.Errorf("%w: Host is not a permitted local address", errRequestSecurity)
	}

	origins := r.Header.Values("Origin")
	if len(origins) > 1 {
		return fmt.Errorf("%w: multiple Origin headers are not permitted", errRequestSecurity)
	}
	if !proxyRequest && isStateChangingRequest(r) && len(origins) == 0 {
		return fmt.Errorf("%w: state-changing local requests require Origin", errRequestSecurity)
	}
	if len(origins) == 1 && !s.validOrigin(origins[0], r.Host, proxyRequest) {
		return fmt.Errorf("%w: Origin is not permitted", errRequestSecurity)
	}
	return nil
}

func isStateChangingRequest(r *http.Request) bool {
	if r.URL.Path == "/oauth/start" || r.URL.Path == "/api/oauth/start" {
		return true
	}
	return strings.HasPrefix(r.URL.Path, "/api/") && r.Method != http.MethodGet &&
		r.Method != http.MethodHead && r.Method != http.MethodOptions
}
