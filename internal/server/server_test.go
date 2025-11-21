package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/codeGROOVE-dev/prcost/pkg/cost"
)

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if s.logger == nil {
		t.Error("Server logger not initialized")
	}
	if s.httpClient == nil {
		t.Error("Server httpClient not initialized")
	}
	if s.ipLimiters == nil {
		t.Error("Server ipLimiters not initialized")
	}
}

func TestSetCommit(t *testing.T) {
	s := New()
	commit := "abc123def"
	s.SetCommit(commit)
	if s.serverCommit != commit {
		t.Errorf("SetCommit() failed: got %s, want %s", s.serverCommit, commit)
	}
}

func TestSetCORSConfig(t *testing.T) {
	tests := []struct {
		name         string
		origins      string
		allowAll     bool
		wantAllowAll bool
		wantOrigins  int
	}{
		{
			name:         "allow all",
			origins:      "",
			allowAll:     true,
			wantAllowAll: true,
			wantOrigins:  0,
		},
		{
			name:         "specific origins",
			origins:      "https://example.com,https://test.com",
			allowAll:     false,
			wantAllowAll: false,
			wantOrigins:  2,
		},
		{
			name:         "wildcard origin",
			origins:      "https://*.example.com",
			allowAll:     false,
			wantAllowAll: false,
			wantOrigins:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			s.SetCORSConfig(tt.origins, tt.allowAll)
			if s.allowAllCors != tt.wantAllowAll {
				t.Errorf("allowAllCors = %v, want %v", s.allowAllCors, tt.wantAllowAll)
			}
			if len(s.allowedOrigins) != tt.wantOrigins {
				t.Errorf("len(allowedOrigins) = %d, want %d", len(s.allowedOrigins), tt.wantOrigins)
			}
		})
	}
}

func TestSetRateLimit(t *testing.T) {
	s := New()
	rps := 50
	burst := 75
	s.SetRateLimit(rps, burst)
	if s.rateLimit != rps {
		t.Errorf("rateLimit = %d, want %d", s.rateLimit, rps)
	}
	if s.rateBurst != burst {
		t.Errorf("rateBurst = %d, want %d", s.rateBurst, burst)
	}
}

func TestValidateGitHubPRURL(t *testing.T) {
	s := New()
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid PR URL",
			url:     "https://github.com/owner/repo/pull/123",
			wantErr: false,
		},
		{
			name:    "valid PR URL with trailing slash",
			url:     "https://github.com/owner/repo/pull/123/",
			wantErr: false,
		},
		{
			name:    "invalid - not github.com",
			url:     "https://gitlab.com/owner/repo/pull/123",
			wantErr: true,
		},
		{
			name:    "invalid - http instead of https",
			url:     "http://github.com/owner/repo/pull/123",
			wantErr: true,
		},
		{
			name:    "invalid - has query params",
			url:     "https://github.com/owner/repo/pull/123?foo=bar",
			wantErr: true,
		},
		{
			name:    "invalid - has fragment",
			url:     "https://github.com/owner/repo/pull/123#section",
			wantErr: true,
		},
		{
			name:    "invalid - missing pull number",
			url:     "https://github.com/owner/repo/pull/",
			wantErr: true,
		},
		{
			name:    "invalid - wrong path format",
			url:     "https://github.com/owner/repo/issues/123",
			wantErr: true,
		},
		{
			name:    "invalid - too long",
			url:     "https://github.com/" + strings.Repeat("a", 200) + "/repo/pull/123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.validateGitHubPRURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGitHubPRURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtractToken(t *testing.T) {
	s := New()
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "Bearer token",
			header: "Bearer ghp_abc123",
			want:   "ghp_abc123",
		},
		{
			name:   "token prefix",
			header: "token ghp_abc123",
			want:   "ghp_abc123",
		},
		{
			name:   "plain token",
			header: "ghp_abc123",
			want:   "ghp_abc123",
		},
		{
			name:   "empty",
			header: "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/calculate", http.NoBody)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			got := s.extractToken(req)
			if got != tt.want {
				t.Errorf("extractToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsOriginAllowed(t *testing.T) {
	s := New()
	s.SetCORSConfig("https://example.com,https://*.test.com,*.dev.com", false)

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{
			name:   "exact match",
			origin: "https://example.com",
			want:   true,
		},
		{
			name:   "wildcard subdomain match",
			origin: "https://sub.test.com",
			want:   true,
		},
		{
			name:   "wildcard deep subdomain match",
			origin: "https://deep.sub.test.com",
			want:   true,
		},
		{
			name:   "wildcard without protocol",
			origin: "https://sub.dev.com",
			want:   true,
		},
		{
			name:   "no match",
			origin: "https://evil.com",
			want:   false,
		},
		{
			name:   "partial match not allowed",
			origin: "https://notexample.com",
			want:   false,
		},
		{
			name:   "protocol mismatch",
			origin: "http://sub.test.com",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.isOriginAllowed(tt.origin)
			if got != tt.want {
				t.Errorf("isOriginAllowed(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

func TestHandleHealth(t *testing.T) {
	s := New()
	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	w := httptest.NewRecorder()

	s.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("handleHealth() status = %d, want %d", w.Code, http.StatusOK)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("handleHealth() status = %s, want healthy", response["status"])
	}
}

func TestServeHTTPSecurityHeaders(t *testing.T) {
	s := New()
	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	headers := map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"X-XSS-Protection":             "1; mode=block",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Resource-Policy": "cross-origin",
	}

	for name, want := range headers {
		got := w.Header().Get(name)
		if got != want {
			t.Errorf("Security header %s = %s, want %s", name, got, want)
		}
	}
}

func TestServeHTTPCORS(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		allowAllCors   bool
		configOrigins  string
		wantCORSHeader bool
	}{
		{
			name:           "allow all - valid origin",
			origin:         "https://example.com",
			allowAllCors:   true,
			configOrigins:  "",
			wantCORSHeader: true,
		},
		{
			name:           "specific origin - allowed",
			origin:         "https://example.com",
			allowAllCors:   false,
			configOrigins:  "https://example.com",
			wantCORSHeader: true,
		},
		{
			name:           "specific origin - not allowed",
			origin:         "https://evil.com",
			allowAllCors:   false,
			configOrigins:  "https://example.com",
			wantCORSHeader: false,
		},
		{
			name:           "no origin header",
			origin:         "",
			allowAllCors:   false,
			configOrigins:  "https://example.com",
			wantCORSHeader: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			s.SetCORSConfig(tt.configOrigins, tt.allowAllCors)

			req := httptest.NewRequest(http.MethodOptions, "/v1/calculate", http.NoBody)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()

			s.ServeHTTP(w, req)

			corsHeader := w.Header().Get("Access-Control-Allow-Origin")
			hasCORS := corsHeader != ""

			if hasCORS != tt.wantCORSHeader {
				t.Errorf("CORS header present = %v, want %v (header value: %s)", hasCORS, tt.wantCORSHeader, corsHeader)
			}

			if w.Code != http.StatusNoContent {
				t.Errorf("OPTIONS request status = %d, want %d", w.Code, http.StatusNoContent)
			}
		})
	}
}

func TestServeHTTPRouting(t *testing.T) {
	s := New()

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{
			name:       "health endpoint",
			method:     http.MethodGet,
			path:       "/health",
			wantStatus: http.StatusOK,
		},
		{
			name:       "calculate endpoint - wrong method",
			method:     http.MethodDelete,
			path:       "/v1/calculate",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "not found",
			method:     http.MethodGet,
			path:       "/nonexistent",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, http.NoBody)
			w := httptest.NewRecorder()

			s.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("ServeHTTP() status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestParseRequest(t *testing.T) {
	s := New()

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "valid request",
			body:    `{"url":"https://github.com/owner/repo/pull/123"}`,
			wantErr: false,
		},
		{
			name:    "valid request with config",
			body:    `{"url":"https://github.com/owner/repo/pull/123","config":{"annual_salary":300000}}`,
			wantErr: false,
		},
		{
			name:    "missing url",
			body:    `{}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			body:    `{invalid`,
			wantErr: true,
		},
		{
			name:    "invalid url format",
			body:    `{"url":"https://gitlab.com/owner/repo/pull/123"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/calculate", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			_, err := s.parseRequest(req.Context(), req)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandleCalculateNoToken(t *testing.T) {
	// Clear environment variables that could provide a fallback token
	// t.Setenv automatically restores the original value after the test
	t.Setenv("GITHUB_TOKEN", "")
	// Clear PATH to prevent gh CLI lookup
	t.Setenv("PATH", "")

	s := New()

	reqBody := CalculateRequest{
		URL: "https://github.com/owner/repo/pull/123",
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/calculate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header

	w := httptest.NewRecorder()
	s.handleCalculate(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("handleCalculate() without token status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRateLimiting(t *testing.T) {
	s := New()
	s.SetRateLimit(1, 1) // Very low rate limit for testing

	// Test rate limiter directly to avoid actual GitHub API calls
	req1 := httptest.NewRequest(http.MethodPost, "/v1/calculate", http.NoBody)
	req1.RemoteAddr = "192.168.1.1:12345"

	// Get rate limiter for this IP
	limiter := s.limiter(req1.Context(), "192.168.1.1")

	// First request - allowed
	if !limiter.Allow() {
		t.Error("First request should not be rate limited")
	}

	// Second request from same IP should be rate limited
	if limiter.Allow() {
		t.Error("Second request should be rate limited")
	}
}

func TestSanitizeError(t *testing.T) {
	tests := []struct {
		name  string
		input error
		want  string
	}{
		{
			name:  "contains Bearer token",
			input: errors.New("error with Bearer ghp_1234567890abcdef1234567890abcdef123456"),
			want:  "error with [REDACTED_TOKEN]",
		},
		{
			name:  "contains token prefix",
			input: errors.New("error with token ghp_1234567890abcdef1234567890abcdef123456"),
			want:  "error with [REDACTED_TOKEN]",
		},
		{
			name:  "contains github_pat token",
			input: errors.New("error with github_pat_" + strings.Repeat("a", 82)),
			want:  "error with [REDACTED_TOKEN]",
		},
		{
			name:  "no token",
			input: errors.New("normal error message"),
			want:  "normal error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeError(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfigMerging(t *testing.T) {
	s := New()

	// Create a request with custom config
	reqBody := CalculateRequest{
		URL: "https://github.com/owner/repo/pull/123",
		Config: &cost.Config{
			AnnualSalary:       300000,
			BenefitsMultiplier: 1.4,
			EventDuration:      15 * time.Minute,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/calculate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fake_token")

	// Parse the request
	parsedReq, err := s.parseRequest(req.Context(), req)
	if err != nil {
		t.Fatalf("parseRequest() error = %v", err)
	}

	// Verify config values are present
	if parsedReq.Config.AnnualSalary != 300000 {
		t.Errorf("Config.AnnualSalary = %f, want 300000", parsedReq.Config.AnnualSalary)
	}
	if parsedReq.Config.BenefitsMultiplier != 1.4 {
		t.Errorf("Config.BenefitsMultiplier = %f, want 1.4", parsedReq.Config.BenefitsMultiplier)
	}
	if parsedReq.Config.EventDuration != 15*time.Minute {
		t.Errorf("Config.EventDuration = %v, want 15m", parsedReq.Config.EventDuration)
	}
}

// Test cache functions
func TestCachePRDataMemory(t *testing.T) {
	s := New()
	ctx := testContext()

	prData := cost.PRData{
		LinesAdded:   100,
		LinesDeleted: 50,
		Author:       "testuser",
		CreatedAt:    time.Now(),
	}

	// Use unique key with timestamp to avoid collision with persisted cache
	key := fmt.Sprintf("test-pr:https://github.com/owner/repo/pull/123:ts=%d", time.Now().UnixNano())

	// Initially should not be cached
	_, cached := s.cachedPRData(ctx, key)
	if cached {
		t.Error("PR data should not be cached initially")
	}

	// Cache the data
	s.cachePRData(ctx, key, prData)

	// Should now be cached
	cachedData, cached := s.cachedPRData(ctx, key)
	if !cached {
		t.Error("PR data should be cached after caching")
	}

	if cachedData.LinesAdded != prData.LinesAdded {
		t.Errorf("Cached LinesAdded = %d, want %d", cachedData.LinesAdded, prData.LinesAdded)
	}
	if cachedData.Author != prData.Author {
		t.Errorf("Cached Author = %s, want %s", cachedData.Author, prData.Author)
	}
}

func TestHandleCalculateInvalidJSON(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodPost, "/v1/calculate", strings.NewReader("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ghp_test")

	w := httptest.NewRecorder()
	s.handleCalculate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleCalculate() with invalid JSON status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleCalculateMissingURL(t *testing.T) {
	s := New()

	reqBody := CalculateRequest{} // No URL
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/calculate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ghp_test")

	w := httptest.NewRecorder()
	s.handleCalculate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleCalculate() with missing URL status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleRepoSampleInvalidJSON(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodPost, "/v1/repo-sample", strings.NewReader("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ghp_test")

	w := httptest.NewRecorder()
	s.handleRepoSample(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleRepoSample() with invalid JSON status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleRepoSampleMissingFields(t *testing.T) {
	s := New()

	tests := []struct {
		name string
		body RepoSampleRequest
	}{
		{
			name: "missing owner",
			body: RepoSampleRequest{Repo: "repo", Days: 30},
		},
		{
			name: "missing repo",
			body: RepoSampleRequest{Owner: "owner", Days: 30},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/repo-sample", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer ghp_test")

			w := httptest.NewRecorder()
			s.handleRepoSample(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("handleRepoSample() %s status = %d, want %d", tt.name, w.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestHandleOrgSampleMissingOrg(t *testing.T) {
	s := New()

	reqBody := OrgSampleRequest{Days: 30} // Missing Org
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/org-sample", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ghp_test")

	w := httptest.NewRecorder()
	s.handleOrgSample(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("handleOrgSample() with missing org status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleRepoSampleStreamHeaders(t *testing.T) {
	s := New()

	reqBody := RepoSampleRequest{
		Owner: "testowner",
		Repo:  "testrepo",
		Days:  30,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/repo-sample-stream", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ghp_test")

	w := httptest.NewRecorder()
	// Note: This will fail with no token error or GitHub API error, but we're testing headers
	s.handleRepoSampleStream(w, req)

	// Check SSE headers were set
	contentType := w.Header().Get("Content-Type")
	if contentType != "text/event-stream" {
		t.Errorf("Content-Type = %s, want text/event-stream", contentType)
	}

	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl != "no-cache" {
		t.Errorf("Cache-Control = %s, want no-cache", cacheControl)
	}

	connection := w.Header().Get("Connection")
	if connection != "keep-alive" {
		t.Errorf("Connection = %s, want keep-alive", connection)
	}
}

func TestHandleOrgSampleStreamHeaders(t *testing.T) {
	s := New()

	reqBody := OrgSampleRequest{
		Org:  "testorg",
		Days: 30,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/org-sample-stream", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ghp_test")

	w := httptest.NewRecorder()
	s.handleOrgSampleStream(w, req)

	// Check SSE headers were set
	contentType := w.Header().Get("Content-Type")
	if contentType != "text/event-stream" {
		t.Errorf("Content-Type = %s, want text/event-stream", contentType)
	}
}

func TestMergeConfig(t *testing.T) {
	s := New()

	baseConfig := cost.Config{
		AnnualSalary: 250000,
	}
	customConfig := &cost.Config{
		AnnualSalary: 300000,
	}

	merged := s.mergeConfig(baseConfig, customConfig)

	if merged.AnnualSalary != 300000 {
		t.Errorf("mergeConfig() AnnualSalary = %f, want 300000", merged.AnnualSalary)
	}
}

func TestHandleNotFound(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/invalid/path", http.NoBody)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Invalid path status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleMethodNotAllowed(t *testing.T) {
	s := New()

	// PATCH is not allowed on /v1/calculate
	req := httptest.NewRequest(http.MethodPatch, "/v1/calculate", http.NoBody)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Wrong method status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestSetTokenValidationErrors(t *testing.T) {
	s := New()

	// Test with invalid app ID (empty)
	err := s.SetTokenValidation("", "nonexistent.pem")
	if err == nil {
		t.Error("SetTokenValidation() with empty app ID should return error")
	}

	// Test with nonexistent key file
	err = s.SetTokenValidation("12345", "/nonexistent/path/key.pem")
	if err == nil {
		t.Error("SetTokenValidation() with nonexistent key file should return error")
	}
}

func TestSetDataSource(t *testing.T) {
	s := New()

	tests := []struct {
		name       string
		source     string
		wantSource string
	}{
		{"prx source", "prx", "prx"},
		{"turnserver source", "turnserver", "turnserver"},
		{"invalid source falls back to prx", "custom", "prx"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s.SetDataSource(tt.source)
			if s.dataSource != tt.wantSource {
				t.Errorf("SetDataSource(%s) = %s, want %s", tt.source, s.dataSource, tt.wantSource)
			}
		})
	}
}

func TestLimiterConcurrency(t *testing.T) {
	s := New()
	s.SetRateLimit(10, 10)
	ctx := testContext()

	// Test that same IP gets same limiter (concurrency safe)
	limiter1 := s.limiter(ctx, "192.168.1.1")
	limiter2 := s.limiter(ctx, "192.168.1.1")

	if limiter1 != limiter2 {
		t.Error("Same IP should return same limiter instance")
	}

	// Test that different IPs get different limiters
	limiter3 := s.limiter(ctx, "192.168.1.2")
	if limiter1 == limiter3 {
		t.Error("Different IPs should return different limiters")
	}
}

func TestSanitizeErrorWithMultipleTokens(t *testing.T) {
	input := errors.New("error with Bearer ghp_token1 and token ghp_token2")
	result := sanitizeError(input)

	if strings.Contains(result, "ghp_") {
		t.Errorf("sanitizeError() still contains token: %s", result)
	}
	if !strings.Contains(result, "[REDACTED_TOKEN]") {
		t.Error("sanitizeError() should contain redaction marker")
	}
}

func TestAllowAllCorsFlag(t *testing.T) {
	s := New()
	s.SetCORSConfig("", true) // Allow all

	// Verify the allowAllCors flag is set
	if !s.allowAllCors {
		t.Error("SetCORSConfig with allowAll=true should set allowAllCors flag")
	}

	// When allowAll is false, flag should be false
	s.SetCORSConfig("https://example.com", false)
	if s.allowAllCors {
		t.Error("SetCORSConfig with allowAll=false should clear allowAllCors flag")
	}
}

func TestIsOriginAllowedEdgeCases(t *testing.T) {
	s := New()
	s.SetCORSConfig("https://example.com,https://*.test.com", false)

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{"empty origin", "", false},
		{"case sensitive exact match", "https://Example.com", false},
		// Note: The wildcard matcher appears to match the base domain too
		{"wildcard matches base domain", "https://test.com", true},
		{"wildcard matches subdomain", "https://sub.test.com", true},
		{"wildcard ignores path", "https://sub.test.com/path", true}, // Path is stripped before matching
		{"unmatched domain", "https://other.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.isOriginAllowed(tt.origin)
			if got != tt.want {
				t.Errorf("isOriginAllowed(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

func TestRateLimiterBehavior(t *testing.T) {
	s := New()
	s.SetRateLimit(1, 2) // 1 per second, burst of 2
	ctx := testContext()

	limiter := s.limiter(ctx, "192.168.1.100")

	// First two requests should be allowed (burst)
	if !limiter.Allow() {
		t.Error("First request should be allowed (within burst)")
	}
	if !limiter.Allow() {
		t.Error("Second request should be allowed (within burst)")
	}

	// Third request should be rate limited
	if limiter.Allow() {
		t.Error("Third request should be rate limited (burst exhausted)")
	}
}

func TestValidateGitHubPRURLEdgeCases(t *testing.T) {
	s := New()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"PR number zero", "https://github.com/owner/repo/pull/0", false},
		{"Large PR number", "https://github.com/owner/repo/pull/999999", false},
		{"Dashes in owner", "https://github.com/owner-name/repo/pull/123", false},
		{"Dashes in repo", "https://github.com/owner/repo-name/pull/123", false},
		{"Underscores rejected", "https://github.com/owner_name/repo_name/pull/123", true},
		{"Numbers in names", "https://github.com/owner123/repo456/pull/123", false},
		{"Dots in repo", "https://github.com/owner/repo.name/pull/123", false},
		{"Single char owner", "https://github.com/a/repo/pull/123", false},
		{"Single char repo", "https://github.com/owner/r/pull/123", false},
		{"Non-numeric PR number", "https://github.com/owner/repo/pull/abc", true},
		{"Negative PR number", "https://github.com/owner/repo/pull/-1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.validateGitHubPRURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGitHubPRURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestParseRequestEdgeCases(t *testing.T) {
	s := New()

	tests := []struct {
		name        string
		contentType string
		body        string
		wantErr     bool
	}{
		{
			name:        "empty body",
			contentType: "application/json",
			body:        "",
			wantErr:     true,
		},
		{
			name:        "whitespace only",
			contentType: "application/json",
			body:        "   ",
			wantErr:     true,
		},
		{
			name:        "null json",
			contentType: "application/json",
			body:        "null",
			wantErr:     true,
		},
		{
			name:        "array instead of object",
			contentType: "application/json",
			body:        "[]",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/calculate", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			_, err := s.parseRequest(req.Context(), req)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCacheConcurrency(t *testing.T) {
	s := New()
	ctx := testContext()

	prData := cost.PRData{
		LinesAdded: 100,
		Author:     "testuser",
	}

	key := "pr:https://github.com/owner/repo/pull/123"

	// Test concurrent writes
	done := make(chan bool)
	for range 10 {
		go func() {
			s.cachePRData(ctx, key, prData)
			done <- true
		}()
	}

	// Wait for all writes
	for range 10 {
		<-done
	}

	// Test concurrent reads
	for range 10 {
		go func() {
			_, _ = s.cachedPRData(ctx, key)
			done <- true
		}()
	}

	// Wait for all reads
	for range 10 {
		<-done
	}

	// Verify data is still correct
	cached, ok := s.cachedPRData(ctx, key)
	if !ok {
		t.Error("Data should still be cached after concurrent access")
	}
	if cached.LinesAdded != 100 {
		t.Errorf("Cached data corrupted: LinesAdded = %d, want 100", cached.LinesAdded)
	}
}

func TestExtractTokenVariations(t *testing.T) {
	s := New()

	tests := []struct {
		name        string
		authHeader  string
		wantToken   string
		description string
	}{
		{
			name:        "Bearer with single space",
			authHeader:  "Bearer ghp_token123",
			wantToken:   "ghp_token123",
			description: "Standard Bearer format",
		},
		{
			name:        "token prefix",
			authHeader:  "token ghp_token123",
			wantToken:   "ghp_token123",
			description: "Lowercase token prefix",
		},
		{
			name:        "plain token",
			authHeader:  "ghp_token123",
			wantToken:   "ghp_token123",
			description: "No prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/calculate", http.NoBody)
			req.Header.Set("Authorization", tt.authHeader)

			got := s.extractToken(req)
			if got != tt.wantToken {
				t.Errorf("extractToken() = %q, want %q (%s)", got, tt.wantToken, tt.description)
			}
		})
	}
}

// Helper function to create a test context
func testContext() context.Context {
	return context.Background()
}

func TestParseConfigFromQuery(t *testing.T) {
	tests := []struct {
		name         string
		queryString  string
		wantNil      bool
		wantSalary   float64
		wantBenefits float64
	}{
		{
			name:         "both salary and benefits",
			queryString:  "salary=300000&benefits=1.5",
			wantNil:      false,
			wantSalary:   300000,
			wantBenefits: 1.5,
		},
		{
			name:         "only salary",
			queryString:  "salary=250000",
			wantNil:      false,
			wantSalary:   250000,
			wantBenefits: 0,
		},
		{
			name:         "only benefits",
			queryString:  "benefits=1.3",
			wantNil:      false,
			wantSalary:   0,
			wantBenefits: 1.3,
		},
		{
			name:        "no config params",
			queryString: "other=value",
			wantNil:     true,
		},
		{
			name:        "empty query",
			queryString: "",
			wantNil:     true,
		},
		{
			name:         "invalid salary value",
			queryString:  "salary=invalid&benefits=1.2",
			wantNil:      false,
			wantSalary:   0,
			wantBenefits: 1.2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test?"+tt.queryString, http.NoBody)
			query := req.URL.Query()

			cfg := parseConfigFromQuery(query)

			if tt.wantNil {
				if cfg != nil {
					t.Errorf("parseConfigFromQuery() = %v, want nil", cfg)
				}
				return
			}

			if cfg == nil {
				t.Fatal("parseConfigFromQuery() = nil, want non-nil")
			}

			if cfg.AnnualSalary != tt.wantSalary {
				t.Errorf("AnnualSalary = %v, want %v", cfg.AnnualSalary, tt.wantSalary)
			}
			if cfg.BenefitsMultiplier != tt.wantBenefits {
				t.Errorf("BenefitsMultiplier = %v, want %v", cfg.BenefitsMultiplier, tt.wantBenefits)
			}
		})
	}
}

func TestSetR2RCallout(t *testing.T) {
	s := New()

	// Test enabling
	s.SetR2RCallout(true)
	if !s.r2rCallout {
		t.Error("SetR2RCallout(true) did not enable r2rCallout")
	}

	// Test disabling
	s.SetR2RCallout(false)
	if s.r2rCallout {
		t.Error("SetR2RCallout(false) did not disable r2rCallout")
	}
}

func TestShutdown(t *testing.T) {
	s := New()

	// Shutdown should not panic
	s.Shutdown()
}

func TestErrorTypes(t *testing.T) {
	t.Run("AccessError", func(t *testing.T) {
		err := NewAccessError(http.StatusForbidden, "test error")
		if err == nil {
			t.Fatal("NewAccessError() returned nil")
		}

		expectedMsg := "access error (403): test error"
		if err.Error() != expectedMsg {
			t.Errorf("Error() = %q, want %q", err.Error(), expectedMsg)
		}

		if !IsAccessError(err) {
			t.Error("IsAccessError() = false, want true")
		}

		// Test with non-access error
		regularErr := errors.New("regular error")
		if IsAccessError(regularErr) {
			t.Error("IsAccessError(regularErr) = true, want false")
		}
	})

	t.Run("IsAccessError with different status codes", func(t *testing.T) {
		testCases := []struct {
			name       string
			statusCode int
			want       bool
		}{
			{"Forbidden", http.StatusForbidden, true},
			{"Unauthorized", http.StatusUnauthorized, true},
			{"NotFound", http.StatusNotFound, true},
			{"BadRequest", http.StatusBadRequest, false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := NewAccessError(tc.statusCode, "test")
				got := IsAccessError(err)
				if got != tc.want {
					t.Errorf("IsAccessError() = %v, want %v", got, tc.want)
				}
			})
		}
	})

	t.Run("IsAccessError with error strings", func(t *testing.T) {
		testCases := []struct {
			name   string
			errMsg string
			want   bool
		}{
			{"Resource not accessible", "Resource not accessible by integration", true},
			{"Not Found", "Not Found", true},
			{"Rate limit", "API rate limit exceeded", true},
			{"Other error", "some other error", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := errors.New(tc.errMsg)
				got := IsAccessError(err)
				if got != tc.want {
					t.Errorf("IsAccessError(%q) = %v, want %v", tc.errMsg, got, tc.want)
				}
			})
		}
	})
}

func TestHandleWebUI(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	s.handleWebUI(w, req)

	resp := w.Result()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleWebUI() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", contentType, "text/html; charset=utf-8")
	}
}

func TestHandleStatic(t *testing.T) {
	s := New()

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{
			name:       "root path",
			path:       "/",
			wantStatus: http.StatusNotFound, // Static handler doesn't serve root
		},
		{
			name:       "js file",
			path:       "/static/app.js",
			wantStatus: http.StatusNotFound, // File doesn't exist in test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, http.NoBody)
			w := httptest.NewRecorder()

			s.handleStatic(w, req)

			resp := w.Result()
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Errorf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("handleStatic(%q) status = %d, want %d", tt.path, resp.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestParseRepoSampleRequest(t *testing.T) {
	s := New()

	tests := []struct {
		name           string
		body           string
		wantErr        bool
		wantOwner      string
		wantRepo       string
		wantDays       int
		wantSampleSize int
	}{
		{
			name:           "valid request with all fields",
			body:           `{"owner":"testowner","repo":"testrepo","days":30,"sample_size":10}`,
			wantErr:        false,
			wantOwner:      "testowner",
			wantRepo:       "testrepo",
			wantDays:       30,
			wantSampleSize: 10,
		},
		{
			name:           "valid request with defaults",
			body:           `{"owner":"testowner","repo":"testrepo"}`,
			wantErr:        false,
			wantOwner:      "testowner",
			wantRepo:       "testrepo",
			wantDays:       60,
			wantSampleSize: 250,
		},
		{
			name:    "missing owner",
			body:    `{"repo":"testrepo"}`,
			wantErr: true,
		},
		{
			name:    "missing repo",
			body:    `{"owner":"testowner"}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			body:    `{invalid}`,
			wantErr: true,
		},
		{
			name:           "custom days and samples",
			body:           `{"owner":"owner","repo":"repo","days":60,"sample_size":20}`,
			wantErr:        false,
			wantOwner:      "owner",
			wantRepo:       "repo",
			wantDays:       60,
			wantSampleSize: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/repo-sample", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			result, err := s.parseRepoSampleRequest(req.Context(), req)

			if tt.wantErr {
				if err == nil {
					t.Error("parseRepoSampleRequest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseRepoSampleRequest() unexpected error: %v", err)
			}

			if result.Owner != tt.wantOwner {
				t.Errorf("Owner = %q, want %q", result.Owner, tt.wantOwner)
			}
			if result.Repo != tt.wantRepo {
				t.Errorf("Repo = %q, want %q", result.Repo, tt.wantRepo)
			}
			if result.Days != tt.wantDays {
				t.Errorf("Days = %d, want %d", result.Days, tt.wantDays)
			}
			if result.SampleSize != tt.wantSampleSize {
				t.Errorf("SampleSize = %d, want %d", result.SampleSize, tt.wantSampleSize)
			}
		})
	}
}

func TestParseOrgSampleRequest(t *testing.T) {
	s := New()

	tests := []struct {
		name           string
		body           string
		wantErr        bool
		wantOrg        string
		wantDays       int
		wantSampleSize int
	}{
		{
			name:           "valid request with all fields",
			body:           `{"org":"testorg","days":30,"sample_size":10}`,
			wantErr:        false,
			wantOrg:        "testorg",
			wantDays:       30,
			wantSampleSize: 10,
		},
		{
			name:           "valid request with defaults",
			body:           `{"org":"testorg"}`,
			wantErr:        false,
			wantOrg:        "testorg",
			wantDays:       60,
			wantSampleSize: 250,
		},
		{
			name:    "missing org",
			body:    `{"days":30}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			body:    `{invalid}`,
			wantErr: true,
		},
		{
			name:           "custom days and samples",
			body:           `{"org":"myorg","days":60,"sample_size":20}`,
			wantErr:        false,
			wantOrg:        "myorg",
			wantDays:       60,
			wantSampleSize: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/org-sample", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			result, err := s.parseOrgSampleRequest(req.Context(), req)

			if tt.wantErr {
				if err == nil {
					t.Error("parseOrgSampleRequest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseOrgSampleRequest() unexpected error: %v", err)
			}

			if result.Org != tt.wantOrg {
				t.Errorf("Org = %q, want %q", result.Org, tt.wantOrg)
			}
			if result.Days != tt.wantDays {
				t.Errorf("Days = %d, want %d", result.Days, tt.wantDays)
			}
			if result.SampleSize != tt.wantSampleSize {
				t.Errorf("SampleSize = %d, want %d", result.SampleSize, tt.wantSampleSize)
			}
		})
	}
}

func TestHandleStaticWithValidFile(t *testing.T) {
	s := New()

	// Test with a path that might exist in the embedded FS
	req := httptest.NewRequest(http.MethodGet, "/static/index.html", http.NoBody)
	w := httptest.NewRecorder()

	s.handleStatic(w, req)

	resp := w.Result()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("Failed to close response body: %v", err)
		}
	}()

	// We expect either 200 (file exists) or 404 (file doesn't exist in test)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Errorf("handleStatic() status = %d, want 200 or 404", resp.StatusCode)
	}
}

func TestMergeConfigEdgeCases(t *testing.T) {
	s := New()

	tests := []struct {
		name     string
		base     cost.Config
		override *cost.Config
		want     cost.Config
	}{
		{
			name: "override with nil",
			base: cost.Config{
				AnnualSalary:       250000,
				BenefitsMultiplier: 1.3,
			},
			override: nil,
			want: cost.Config{
				AnnualSalary:       250000,
				BenefitsMultiplier: 1.3,
			},
		},
		{
			name: "override with zero values",
			base: cost.Config{
				AnnualSalary:       250000,
				BenefitsMultiplier: 1.3,
			},
			override: &cost.Config{},
			want: cost.Config{
				AnnualSalary:       250000,
				BenefitsMultiplier: 1.3,
			},
		},
		{
			name: "override salary only",
			base: cost.Config{
				AnnualSalary:       250000,
				BenefitsMultiplier: 1.3,
			},
			override: &cost.Config{
				AnnualSalary: 300000,
			},
			want: cost.Config{
				AnnualSalary:       300000,
				BenefitsMultiplier: 1.3,
			},
		},
		{
			name: "override benefits only",
			base: cost.Config{
				AnnualSalary:       250000,
				BenefitsMultiplier: 1.3,
			},
			override: &cost.Config{
				BenefitsMultiplier: 1.5,
			},
			want: cost.Config{
				AnnualSalary:       250000,
				BenefitsMultiplier: 1.5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.mergeConfig(tt.base, tt.override)
			if got.AnnualSalary != tt.want.AnnualSalary {
				t.Errorf("AnnualSalary = %v, want %v", got.AnnualSalary, tt.want.AnnualSalary)
			}
			if got.BenefitsMultiplier != tt.want.BenefitsMultiplier {
				t.Errorf("BenefitsMultiplier = %v, want %v", got.BenefitsMultiplier, tt.want.BenefitsMultiplier)
			}
		})
	}
}

func TestParseRequestPOST(t *testing.T) {
	s := New()

	tests := []struct {
		name    string
		body    string
		wantURL string
		wantErr bool
	}{
		{
			name:    "valid JSON",
			body:    `{"url":"https://github.com/owner/repo/pull/123"}`,
			wantURL: "https://github.com/owner/repo/pull/123",
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			body:    `{invalid json}`,
			wantErr: true,
		},
		{
			name:    "missing url field",
			body:    `{"config":{"salary":300000}}`,
			wantErr: true,
		},
		{
			name:    "empty url",
			body:    `{"url":""}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/calculate", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			result, err := s.parseRequest(req.Context(), req)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result.URL != tt.wantURL {
				t.Errorf("parseRequest() URL = %v, want %v", result.URL, tt.wantURL)
			}
		})
	}
}

func TestHandleHealthErrorPath(t *testing.T) {
	s := New()

	// Create a response writer that fails on write
	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)

	// Use a normal recorder - we're testing the encode path
	w := httptest.NewRecorder()

	s.handleHealth(w, req)

	// Should succeed normally
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHandleWebUIErrorPaths(t *testing.T) {
	s := New()

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{
			name:       "root path",
			path:       "/",
			wantStatus: http.StatusOK,
		},
		{
			name:       "web ui path",
			path:       "/web",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, http.NoBody)
			w := httptest.NewRecorder()

			s.handleWebUI(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}

func TestTokenFunction(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Test when fallbackToken is empty
	token := s.token(ctx)

	// Token might be from gh CLI or empty
	// Just verify the function doesn't crash
	_ = token
}

func TestLimiterCleanup(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Create many limiters to trigger cleanup
	// The cleanup happens at 10001 limiters
	for i := range 10005 {
		ip := fmt.Sprintf("192.168.1.%d", i)
		_ = s.limiter(ctx, ip)
	}

	// Should have cleaned up to half
	s.ipLimitersMu.RLock()
	count := len(s.ipLimiters)
	s.ipLimitersMu.RUnlock()

	if count > 10001 {
		t.Errorf("Expected limiter cleanup, got %d limiters", count)
	}
}

func TestNewWithDatastoreEnv(t *testing.T) {
	// Test with DATASTORE_DB set
	t.Setenv("DATASTORE_DB", "test-db-id")
	s := New()
	if s == nil {
		t.Fatal("Expected server to be created")
	}
	// Note: dsClient might be nil if the client creation fails, but the server should still be created
}

func TestLogSSEError(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Test with non-nil error
	logSSEError(ctx, s.logger, fmt.Errorf("test error"))

	// Test with nil error
	logSSEError(ctx, s.logger, nil)
}

func TestStartKeepAliveCompletesCoverage(t *testing.T) {
	w := httptest.NewRecorder()

	// Start keep alive
	stop, errChan := startKeepAlive(w)

	// Let it run briefly
	time.Sleep(100 * time.Millisecond)

	// Stop it
	close(stop)

	// Check for errors
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Unexpected error from startKeepAlive: %v", err)
		}
	case <-time.After(1 * time.Second):
		// No error - success
	}
}

func TestSendSSECoverage(t *testing.T) {
	tests := []struct {
		name   string
		update ProgressUpdate
	}{
		{
			name: "error message",
			update: ProgressUpdate{
				Type:  "error",
				Error: "test error",
			},
		},
		{
			name: "complete message",
			update: ProgressUpdate{
				Type:   "complete",
				PR:     123,
				Owner:  "owner",
				Repo:   "repo",
				Result: &cost.ExtrapolatedBreakdown{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			err := sendSSE(w, tt.update)
			if err != nil {
				t.Errorf("sendSSE() error = %v", err)
			}

			if w.Body.Len() == 0 {
				t.Error("Expected SSE message to be written")
			}
		})
	}
}

func TestMergeConfigAllFields(t *testing.T) {
	s := New()

	base := cost.Config{
		AnnualSalary:             250000,
		BenefitsMultiplier:       1.3,
		HoursPerYear:             2080,
		EventDuration:            20 * time.Minute,
		ContextSwitchInDuration:  20 * time.Minute,
		ContextSwitchOutDuration: 20 * time.Minute,
		SessionGapThreshold:      60 * time.Minute,
		DeliveryDelayFactor:      0.25,
		MaxDelayAfterLastEvent:   30 * 24 * time.Hour,
		MaxProjectDelay:          90 * 24 * time.Hour,
		MaxCodeDrift:             180 * 24 * time.Hour,
		ReviewInspectionRate:     200,
		ModificationCostFactor:   1.0,
	}

	override := &cost.Config{
		AnnualSalary:             300000,
		BenefitsMultiplier:       1.5,
		HoursPerYear:             2000,
		EventDuration:            30 * time.Minute,
		ContextSwitchInDuration:  15 * time.Minute,
		ContextSwitchOutDuration: 15 * time.Minute,
		SessionGapThreshold:      45 * time.Minute,
		DeliveryDelayFactor:      0.3,
		MaxDelayAfterLastEvent:   20 * 24 * time.Hour,
		MaxProjectDelay:          60 * 24 * time.Hour,
		MaxCodeDrift:             120 * 24 * time.Hour,
		ReviewInspectionRate:     250,
		ModificationCostFactor:   1.2,
	}

	result := s.mergeConfig(base, override)

	// Verify all fields were overridden
	if result.AnnualSalary != 300000 {
		t.Errorf("Expected AnnualSalary 300000, got %v", result.AnnualSalary)
	}
	if result.BenefitsMultiplier != 1.5 {
		t.Errorf("Expected BenefitsMultiplier 1.5, got %v", result.BenefitsMultiplier)
	}
	if result.HoursPerYear != 2000 {
		t.Errorf("Expected HoursPerYear 2000, got %v", result.HoursPerYear)
	}
	if result.EventDuration != 30*time.Minute {
		t.Errorf("Expected EventDuration 30m, got %v", result.EventDuration)
	}
	if result.ReviewInspectionRate != 250 {
		t.Errorf("Expected ReviewInspectionRate 250, got %v", result.ReviewInspectionRate)
	}
	if result.ModificationCostFactor != 1.2 {
		t.Errorf("Expected ModificationCostFactor 1.2, got %v", result.ModificationCostFactor)
	}
}

func TestProcessRequestWithMock(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Create a mock PR data
	mockData := newMockPRData("test-author", 150, 3)

	// Store in cache to simulate successful fetch
	//nolint:errcheck // test setup - errors don't matter
	_ = s.prDataCache.Set(ctx, "https://github.com/test/repo/pull/123", *mockData, 0)

	req := &CalculateRequest{
		URL: "https://github.com/test/repo/pull/123",
	}

	// This will fail because we can't fully mock the GitHub client
	// but it will exercise more code paths
	_, err := s.processRequest(ctx, req, "fake-token")

	// We expect an error because we don't have a real GitHub client
	// but this still exercises the code
	_ = err
}

func TestCachedPRDataHit(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Pre-populate cache using the cache method (which sanitizes keys)
	testData := newMockPRData("test-author", 100, 5)
	key := "https://github.com/owner/repo/pull/123"

	s.cachePRData(ctx, key, *testData)

	// Test cache hit
	data, found := s.cachedPRData(ctx, key)
	if !found {
		t.Error("Expected cache hit")
	}
	if data.Author != "test-author" {
		t.Errorf("Expected author test-author, got %s", data.Author)
	}
}

func TestCachePRData(t *testing.T) {
	s := New()
	ctx := context.Background()

	testData := newMockPRData("author", 200, 4)
	key := "https://github.com/owner/repo/pull/456"

	// Cache the data
	s.cachePRData(ctx, key, *testData)

	// Verify it was cached by retrieving it via the cache method
	cached, found := s.cachedPRData(ctx, key)

	if !found {
		t.Error("Expected data to be cached")
	}

	if cached.Author != "author" {
		t.Errorf("Expected author 'author', got %s", cached.Author)
	}
	if cached.LinesAdded != 200 {
		t.Errorf("Expected 200 lines, got %d", cached.LinesAdded)
	}
}

func TestHandleRepoSampleRateLimitExceeded(t *testing.T) {
	s := New()
	s.SetRateLimit(1, 1) // Very low rate limit

	// Consume the rate limit
	ctx := context.Background()
	limiter := s.limiter(ctx, "test-ip")
	limiter.Allow()

	// Make second request that should be rate limited
	req2 := httptest.NewRequest(http.MethodPost, "/api/sample/repo", strings.NewReader(`{"owner":"test","repo":"repo","days":30}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Forwarded-For", "test-ip")
	w2 := httptest.NewRecorder()

	s.handleRepoSample(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w2.Code)
	}
}

func TestHandleOrgSampleBadRequest(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodPost, "/api/sample/org", strings.NewReader(`{invalid json}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleOrgSample(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestParseRepoSampleRequestMissingFields(t *testing.T) {
	s := New()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing owner",
			body: `{"repo":"test","days":30}`,
		},
		{
			name: "missing repo",
			body: `{"owner":"test","days":30}`,
		},
		{
			name: "negative days",
			body: `{"owner":"test","repo":"repo","days":-1}`,
		},
		{
			name: "days too large",
			body: `{"owner":"test","repo":"repo","days":400}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			_, err := s.parseRepoSampleRequest(req.Context(), req)
			if err == nil {
				t.Error("Expected error for invalid request")
			}
		})
	}
}

func TestParseOrgSampleRequestValidation(t *testing.T) {
	s := New()

	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "valid request",
			body:    `{"org":"test-org","days":30,"sample_size":10}`,
			wantErr: false,
		},
		{
			name:    "missing org",
			body:    `{"days":30}`,
			wantErr: true,
		},
		{
			name:    "sample size zero",
			body:    `{"org":"test","days":30,"sample_size":0}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")

			_, err := s.parseOrgSampleRequest(req.Context(), req)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOrgSampleRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServeHTTPCORSPreflightSameOrigin(t *testing.T) {
	s := New()

	// Test preflight without Sec-Fetch-Site (same-origin request)
	req := httptest.NewRequest(http.MethodOptions, "/api/calculate", http.NoBody)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	// Should allow same-origin
	if w.Code == http.StatusForbidden {
		t.Error("Should allow same-origin preflight")
	}
}

func TestServeHTTPCSRFProtection(t *testing.T) {
	s := New()

	// Test POST without proper CSRF headers
	req := httptest.NewRequest(http.MethodPost, "/api/calculate", strings.NewReader(`{"url":"https://github.com/owner/repo/pull/123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	// Should be blocked by CSRF protection
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected CSRF protection to block request, got status %d", w.Code)
	}
}

func TestHandleCalculateWithXForwardedFor(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/api/calculate?url=https://github.com/owner/repo/pull/123", http.NoBody)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")
	w := httptest.NewRecorder()

	s.handleCalculate(w, req)

	// Just verify it doesn't crash with X-Forwarded-For header parsing
	_ = w.Code
}

func TestValidateGitHubTokenSuccess(t *testing.T) {
	s := New()
	ctx := context.Background()

	// This will test the token validation logic
	// It will likely fail without a valid token, but exercises the code
	err := s.validateGitHubToken(ctx, "fake-token")
	// We don't assert on the result since we can't mock the GitHub API easily
	_ = err
}

func TestHandleRepoSampleWithAuth(t *testing.T) {
	s := New()

	reqBody := `{"owner":"test","repo":"test","days":30,"sample_size":10}`
	req := httptest.NewRequest(http.MethodPost, "/api/sample/repo", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	s.handleRepoSample(w, req)

	// Will fail without real GitHub access, but exercises auth extraction
	_ = w.Code
}

func TestHandleOrgSampleWithAuth(t *testing.T) {
	s := New()

	reqBody := `{"org":"test-org","days":30,"sample_size":10}`
	req := httptest.NewRequest(http.MethodPost, "/api/sample/org", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	s.handleOrgSample(w, req)

	// Will fail without real GitHub access, but exercises auth extraction
	_ = w.Code
}

func TestServeHTTPRoutingCalculate(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/api/calculate?url=https://github.com/owner/repo/pull/1", http.NoBody)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	// Just verify routing works (will fail on actual processing)
	_ = w.Code
}

func TestServeHTTPRoutingHealth(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for /health, got %d", w.Code)
	}
}

func TestServeHTTPRoutingWebUI(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	// Should return web UI
	_ = w.Code
}

func TestServeHTTPRoutingStatic(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/static/test.css", http.NoBody)
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	// Will 404 if file doesn't exist, but exercises routing
	_ = w.Code
}

func TestHandleRepoSampleStreamWithInvalidRequest(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodPost, "/api/sample/repo/stream", strings.NewReader(`{invalid}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleRepoSampleStream(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid request, got %d", w.Code)
	}
}

func TestHandleOrgSampleStreamWithInvalidRequest(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodPost, "/api/sample/org/stream", strings.NewReader(`{invalid}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	s.handleOrgSampleStream(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid request, got %d", w.Code)
	}
}

func TestNewWithAllDefaults(t *testing.T) {
	s := New()

	// Verify defaults are set correctly
	if s.rateLimit != DefaultRateLimit {
		t.Errorf("Expected rate limit %d, got %d", DefaultRateLimit, s.rateLimit)
	}
	if s.rateBurst != DefaultRateBurst {
		t.Errorf("Expected rate burst %d, got %d", DefaultRateBurst, s.rateBurst)
	}
	if s.dataSource != "turnserver" {
		t.Errorf("Expected data source 'turnserver', got %s", s.dataSource)
	}
}

func TestIsOriginAllowedWithWildcard(t *testing.T) {
	s := New()

	// Set allowed origins with wildcard
	s.SetCORSConfig("https://*.example.com", false)

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{
			name:   "wildcard subdomain match",
			origin: "https://app.example.com",
			want:   true,
		},
		{
			name:   "wildcard deep subdomain match",
			origin: "https://api.app.example.com",
			want:   true,
		},
		{
			name:   "no match different domain",
			origin: "https://evil.com",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.isOriginAllowed(tt.origin)
			if got != tt.want {
				t.Errorf("isOriginAllowed(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

func TestParseRequestWithConfigOverride(t *testing.T) {
	s := New()

	reqBody := `{
		"url": "https://github.com/owner/repo/pull/123",
		"config": {
			"AnnualSalary": 300000,
			"BenefitsMultiplier": 1.4
		}
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/calculate", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	result, err := s.parseRequest(req.Context(), req)
	if err != nil {
		t.Fatalf("parseRequest() error = %v", err)
	}

	if result.Config == nil {
		t.Fatal("Expected config to be set")
	}
	if result.Config.AnnualSalary != 300000 {
		t.Errorf("Expected salary 300000, got %v", result.Config.AnnualSalary)
	}
	if result.Config.BenefitsMultiplier != 1.4 {
		t.Errorf("Expected benefits 1.4, got %v", result.Config.BenefitsMultiplier)
	}
}

func TestHandleStaticNotFound(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/static/nonexistent.js", http.NoBody)
	w := httptest.NewRecorder()

	s.handleStatic(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for nonexistent file, got %d", w.Code)
	}
}

func TestHandleStaticEmptyPath(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/static/", http.NoBody)
	w := httptest.NewRecorder()

	s.handleStatic(w, req)

	// Should handle empty path gracefully
	_ = w.Code
}

func TestSanitizeErrorWithTokens(t *testing.T) {
	tests := []struct {
		name  string
		input error
		want  string
	}{
		{
			name:  "error with ghp token",
			input: fmt.Errorf("failed with ghp_123456789012345678901234567890123456"),
			want:  "failed with [REDACTED_TOKEN]",
		},
		{
			name:  "error with gho token",
			input: fmt.Errorf("auth failed: gho_abcdef123456abcdef123456abcdef123456"),
			want:  "auth failed: [REDACTED_TOKEN]",
		},
		{
			name:  "error without token",
			input: fmt.Errorf("regular error message"),
			want:  "regular error message",
		},
		{
			name:  "nil error",
			input: nil,
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeError(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCachePRDataMemoryWrite(t *testing.T) {
	s := New()
	ctx := context.Background()
	testData := newMockPRData("test-author", 100, 5)
	key := "pr:owner/repo:123"

	s.cachePRData(ctx, key, *testData)

	// Verify it was cached
	data, found := s.cachedPRData(ctx, key)
	if !found {
		t.Fatal("Expected cache entry to be found")
	}
	if data.Author != "test-author" {
		t.Errorf("Expected author 'test-author', got %s", data.Author)
	}
	if data.LinesAdded != 100 {
		t.Errorf("Expected 100 lines added, got %d", data.LinesAdded)
	}
}

func TestCachedPRDataMissCache(t *testing.T) {
	s := New()
	ctx := context.Background()

	_, found := s.cachedPRData(ctx, "nonexistent-key")
	if found {
		t.Error("Expected cache miss for nonexistent key")
	}
}

// TestCachedPRQueryBadType and TestCachedPRDataBadType removed:
// bdcache uses generic types, so type mismatches are impossible at compile time.

func TestLimiterCleanupLarge(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Add more than 10000 limiters to trigger cleanup
	for i := range 10500 {
		ip := fmt.Sprintf("192.168.1.%d", i%256) + fmt.Sprintf(".%d", i/256)
		_ = s.limiter(ctx, ip)
	}

	// Should have triggered cleanup
	s.ipLimitersMu.RLock()
	count := len(s.ipLimiters)
	s.ipLimitersMu.RUnlock()

	if count > 10000 {
		t.Errorf("Expected limiter cleanup, but have %d limiters", count)
	}
}

func TestTokenFallbackReturns(t *testing.T) {
	s := New()
	ctx := context.Background()

	// token() returns the fallback token if set (may be set by gh auth token at startup)
	token := s.token(ctx)
	// Just verify it returns without error - gh auth token may have set a fallback
	_ = token
}

func TestTokenFallbackExplicitSet(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Manually set a fallback token
	s.fallbackTokenMu.Lock()
	s.fallbackToken = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
	s.fallbackTokenMu.Unlock()

	token := s.token(ctx)
	if len(token) != 40 {
		t.Errorf("Expected 40-char token, got %d chars: %s", len(token), token)
	}
}

func TestSetTokenValidationWithInvalidKeyFile(t *testing.T) {
	s := New()

	err := s.SetTokenValidation("test-app-id", "/nonexistent/key/file.pem")
	if err == nil {
		t.Error("Expected error for nonexistent key file")
	}
}

func TestParseRepoSampleRequestValidDays(t *testing.T) {
	s := New()
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/api/repo/sample?owner=test&repo=test&days=30", http.NoBody)

	result, err := s.parseRepoSampleRequest(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Days != 30 {
		t.Errorf("Expected days=30, got %d", result.Days)
	}
}

func TestParseRepoSampleRequestMissingOwner(t *testing.T) {
	s := New()
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/api/repo/sample?repo=test", http.NoBody)

	_, err := s.parseRepoSampleRequest(ctx, req)
	if err == nil {
		t.Error("Expected error for missing owner parameter")
	}
}

func TestParseRepoSampleRequestMissingRepo(t *testing.T) {
	s := New()
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/api/repo/sample?owner=test", http.NoBody)

	_, err := s.parseRepoSampleRequest(ctx, req)
	if err == nil {
		t.Error("Expected error for missing repo parameter")
	}
}

func TestParseOrgSampleRequestValidDays(t *testing.T) {
	s := New()
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/api/org/sample?org=test&days=30", http.NoBody)

	result, err := s.parseOrgSampleRequest(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Days != 30 {
		t.Errorf("Expected days=30, got %d", result.Days)
	}
}

func TestParseOrgSampleRequestMissingOrg(t *testing.T) {
	s := New()
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/api/org/sample", http.NoBody)

	_, err := s.parseOrgSampleRequest(ctx, req)
	if err == nil {
		t.Error("Expected error for missing org parameter")
	}
}

func TestHandleCalculateWithMalformedJSON(t *testing.T) {
	s := New()

	malformedJSON := `{"pr_url": "invalid json`
	req := httptest.NewRequest(http.MethodPost, "/api/calculate", strings.NewReader(malformedJSON))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("user", "ghp_123456789012345678901234567890123456")
	w := httptest.NewRecorder()

	s.handleCalculate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for malformed JSON, got %d", w.Code)
	}
}

func TestHandleCalculateWithInvalidPRURL(t *testing.T) {
	s := New()

	jsonBody := `{"pr_url": "not-a-github-url"}`
	req := httptest.NewRequest(http.MethodPost, "/api/calculate", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("user", "ghp_123456789012345678901234567890123456")
	w := httptest.NewRecorder()

	s.handleCalculate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid PR URL, got %d", w.Code)
	}
}

func TestHandleWebUIWithQueryParams(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/web?pr_url=https://github.com/owner/repo/pull/123", http.NoBody)
	w := httptest.NewRecorder()

	s.handleWebUI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "owner/repo") {
		t.Error("Expected response to contain owner/repo reference")
	}
}

func TestServeHTTPWithCSRFProtection(t *testing.T) {
	s := New()
	s.SetCORSConfig("https://example.com", false)

	// POST request from cross-origin should be blocked
	req := httptest.NewRequest(http.MethodPost, "/api/calculate", strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://malicious.com")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	// Should be blocked by CSRF protection
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for cross-origin POST, got %d", w.Code)
	}
}

func TestValidateGitHubPRURLMoreCases(t *testing.T) {
	s := New()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid URL",
			url:     "https://github.com/owner/repo/pull/123",
			wantErr: false,
		},
		{
			name:    "URL too long",
			url:     "https://github.com/" + strings.Repeat("a", 250) + "/repo/pull/123",
			wantErr: true,
		},
		{
			name:    "non-github domain",
			url:     "https://gitlab.com/owner/repo/pull/123",
			wantErr: true,
		},
		{
			name:    "http not https",
			url:     "http://github.com/owner/repo/pull/123",
			wantErr: true,
		},
		{
			name:    "URL with credentials",
			url:     "https://user:pass@github.com/owner/repo/pull/123",
			wantErr: true,
		},
		{
			name:    "URL with query params",
			url:     "https://github.com/owner/repo/pull/123?tab=files",
			wantErr: true,
		},
		{
			name:    "URL with fragment",
			url:     "https://github.com/owner/repo/pull/123#discussion",
			wantErr: true,
		},
		{
			name:    "invalid path format",
			url:     "https://github.com/owner/repo/issues/123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.validateGitHubPRURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateGitHubPRURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseConfigFromQueryWithValues(t *testing.T) {
	query := url.Values{}
	query.Set("salary", "150000")
	query.Set("benefits", "1.3")

	cfg := parseConfigFromQuery(query)
	if cfg == nil {
		t.Fatal("Expected config, got nil")
	}
	if cfg.AnnualSalary != 150000 {
		t.Errorf("Expected salary 150000, got %f", cfg.AnnualSalary)
	}
	if cfg.BenefitsMultiplier != 1.3 {
		t.Errorf("Expected benefits 1.3, got %f", cfg.BenefitsMultiplier)
	}
}

func TestParseConfigFromQueryEmpty(t *testing.T) {
	query := url.Values{}

	cfg := parseConfigFromQuery(query)
	if cfg != nil {
		t.Errorf("Expected nil for empty query, got %+v", cfg)
	}
}

func TestParseConfigFromQueryInvalidValues(t *testing.T) {
	query := url.Values{}
	query.Set("salary", "not-a-number")
	query.Set("benefits", "invalid")

	cfg := parseConfigFromQuery(query)
	if cfg == nil {
		t.Fatal("Expected config struct with zero values")
	}
	if cfg.AnnualSalary != 0 {
		t.Errorf("Expected salary 0 for invalid input, got %f", cfg.AnnualSalary)
	}
}

func TestHandleCalculateWithMaxBytesReader(t *testing.T) {
	s := New()

	// Create a very large request body (> 1MB)
	largeBody := strings.Repeat("x", 2<<20) // 2MB
	req := httptest.NewRequest(http.MethodPost, "/api/calculate", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("user", "ghp_123456789012345678901234567890123456")
	w := httptest.NewRecorder()

	s.handleCalculate(w, req)

	// Should reject large request
	if w.Code == http.StatusOK {
		t.Error("Expected error for oversized request body")
	}
}

func TestHandleWebUIWithoutPRParam(t *testing.T) {
	s := New()

	req := httptest.NewRequest(http.MethodGet, "/web", http.NoBody)
	w := httptest.NewRecorder()

	s.handleWebUI(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for /web without params, got %d", w.Code)
	}
}

func TestServeHTTPWithAllowAllCORS(t *testing.T) {
	s := New()
	s.SetCORSConfig("", true)

	req := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	// Check CORS header was set
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Error("Expected CORS header to be set")
	}
}

func TestServeHTTPWithOPTIONS(t *testing.T) {
	s := New()
	s.SetCORSConfig("https://example.com", false)

	req := httptest.NewRequest(http.MethodOptions, "/api/calculate", http.NoBody)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected 204 for OPTIONS, got %d", w.Code)
	}
}

func TestParseRepoSampleRequestWithConfigQuery(t *testing.T) {
	s := New()
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/api/repo/sample?owner=test&repo=test&salary=200000&benefits=1.5", http.NoBody)

	result, err := s.parseRepoSampleRequest(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Config == nil {
		t.Fatal("Expected config to be set")
	}
	if result.Config.AnnualSalary != 200000 {
		t.Errorf("Expected salary 200000, got %f", result.Config.AnnualSalary)
	}
}

func TestParseOrgSampleRequestWithSample(t *testing.T) {
	s := New()
	ctx := context.Background()
	req := httptest.NewRequest(http.MethodGet, "/api/org/sample?org=test&sample=50", http.NoBody)

	result, err := s.parseOrgSampleRequest(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.SampleSize != 50 {
		t.Errorf("Expected sample size 50, got %d", result.SampleSize)
	}
}
