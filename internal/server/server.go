// Package server implements the HTTP server for the PR Cost API.
package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/ds9/pkg/datastore"
	"github.com/codeGROOVE-dev/gsm"
	"github.com/codeGROOVE-dev/prcost/pkg/cost"
	"github.com/codeGROOVE-dev/prcost/pkg/github"
	"golang.org/x/time/rate"
)

const (
	// DefaultRateLimit is the default requests per second limit.
	DefaultRateLimit = 100
	// DefaultRateBurst is the default burst size for rate limiting.
	DefaultRateBurst = 100
	// errorKey is the logging key for error messages.
	errorKey = "error"
	// httpClientTimeout is the timeout for HTTP client requests.
	httpClientTimeout = 30 * time.Second
	// maxURLLength is the maximum length for GitHub PR URLs.
	maxURLLength = 200
	// maxIdleConns is the maximum idle HTTP connections.
	maxIdleConns = 100
	// maxIdleConnsPerHost is the maximum idle HTTP connections per host.
	maxIdleConnsPerHost = 10
	// idleConnTimeout is the timeout for idle HTTP connections.
	idleConnTimeout = 90 * time.Second
)

// tokenPattern matches common GitHub token formats for sanitization.
var tokenPattern = regexp.MustCompile(
	`(?i)(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|` +
		`github_pat_[a-zA-Z0-9_]{82}|Bearer\s+[a-zA-Z0-9._\-]+|token\s+[a-zA-Z0-9._\-]+)`,
)

//go:embed static/*
var staticFS embed.FS

// cacheEntry holds cached data for in-memory cache.
// No TTL needed - Cloud Run kills processes frequently, providing natural cache invalidation.
type cacheEntry struct {
	data any
}

// prDataCacheEntity represents a cached PR data entry in DataStore with TTL.
type prDataCacheEntity struct {
	Data      string    `datastore:"data,noindex"` // JSON-encoded cost.PRData
	CachedAt  time.Time `datastore:"cached_at"`    // When this was cached
	ExpiresAt time.Time `datastore:"expires_at"`   // When this expires (1 hour from CachedAt)
	URL       string    `datastore:"url"`          // PR URL for debugging
}

// prQueryCacheEntity represents a cached PR query result in DataStore with TTL.
type prQueryCacheEntity struct {
	Data      string    `datastore:"data,noindex"` // JSON-encoded []github.PRSummary
	CachedAt  time.Time `datastore:"cached_at"`    // When this was cached
	ExpiresAt time.Time `datastore:"expires_at"`   // When this expires (varies by type)
	QueryType string    `datastore:"query_type"`   // "repo" or "org"
	QueryKey  string    `datastore:"query_key"`    // Full query key for debugging
}

// calcResultCacheEntity represents a cached calculation result in DataStore with TTL.
type calcResultCacheEntity struct {
	Data      string    `datastore:"data,noindex"` // JSON-encoded cost.Breakdown
	CachedAt  time.Time `datastore:"cached_at"`    // When this was cached
	ExpiresAt time.Time `datastore:"expires_at"`   // When this expires
	URL       string    `datastore:"url"`          // PR URL for debugging
	ConfigKey string    `datastore:"config_key"`   // Config hash for debugging
}

// Server handles HTTP requests for the PR Cost API.
//
//nolint:govet // fieldalignment: struct field ordering optimized for readability over memory
type Server struct {
	logger         *slog.Logger
	httpClient     *http.Client
	csrfProtection *http.CrossOriginProtection
	// Per-IP rate limiting.
	ipLimiters       map[string]*rate.Limiter
	allowedOrigins   []string
	githubAppKeyData []byte
	ipLimitersMu     sync.RWMutex
	fallbackTokenMu  sync.RWMutex
	fallbackToken    string
	serverCommit     string
	githubAppID      string
	dataSource       string
	rateLimit        int
	rateBurst        int
	allowAllCors     bool
	validateTokens   bool
	r2rCallout       bool
	// In-memory caching for PR queries and data.
	prQueryCache      map[string]*cacheEntry
	prDataCache       map[string]*cacheEntry
	calcResultCache   map[string]*cacheEntry
	prQueryCacheMu    sync.RWMutex
	prDataCacheMu     sync.RWMutex
	calcResultCacheMu sync.RWMutex
	// DataStore client for persistent caching (nil if not enabled).
	dsClient *datastore.Client
}

// CalculateRequest represents a request to calculate PR costs.
//
//nolint:govet // fieldalignment: API struct field order optimized for readability
type CalculateRequest struct {
	URL    string       `json:"url"`
	Config *cost.Config `json:"config,omitempty"`
}

// CalculateResponse represents the response from a cost calculation.
//
//nolint:govet // fieldalignment: API struct field order optimized for readability
type CalculateResponse struct {
	Breakdown      cost.Breakdown `json:"breakdown"`
	Timestamp      time.Time      `json:"timestamp"`
	Commit         string         `json:"commit"`
	SecondsInState map[string]int `json:"seconds_in_state,omitempty"` // Only populated when using turnserver
}

// RepoSampleRequest represents a request to sample and calculate costs for a repository.
//
//nolint:govet // fieldalignment: API struct field order optimized for readability
type RepoSampleRequest struct {
	Owner      string       `json:"owner"`
	Repo       string       `json:"repo"`
	SampleSize int          `json:"sample_size,omitempty"` // Default: 250
	Days       int          `json:"days,omitempty"`        // Default: 60
	Config     *cost.Config `json:"config,omitempty"`
}

// OrgSampleRequest represents a request to sample and calculate costs for an organization.
//
//nolint:govet // fieldalignment: API struct field order optimized for readability
type OrgSampleRequest struct {
	Org        string       `json:"org"`
	SampleSize int          `json:"sample_size,omitempty"` // Default: 250
	Days       int          `json:"days,omitempty"`        // Default: 60
	Config     *cost.Config `json:"config,omitempty"`
}

// SampleResponse represents the response from a sampling operation.
//
//nolint:govet // fieldalignment: API struct field order optimized for readability
type SampleResponse struct {
	Extrapolated   cost.ExtrapolatedBreakdown `json:"extrapolated"`
	Timestamp      time.Time                  `json:"timestamp"`
	Commit         string                     `json:"commit"`
	SecondsInState map[string]int             `json:"seconds_in_state,omitempty"` // Aggregated across all sampled PRs
}

// ProgressUpdate represents a progress update for streaming responses.
//
//nolint:govet // fieldalignment: API struct field order optimized for readability
type ProgressUpdate struct {
	Type           string                      `json:"type"` // "fetching", "processing", "complete", "error", "done"
	PR             int                         `json:"pr,omitempty"`
	Owner          string                      `json:"owner,omitempty"`
	Repo           string                      `json:"repo,omitempty"`
	Progress       string                      `json:"progress,omitempty"` // e.g., "5/15"
	Error          string                      `json:"error,omitempty"`
	Result         *cost.ExtrapolatedBreakdown `json:"result,omitempty"`
	Commit         string                      `json:"commit,omitempty"`
	R2RCallout     bool                        `json:"r2r_callout,omitempty"`
	SecondsInState map[string]int              `json:"seconds_in_state,omitempty"` // Only in "done" messages
}

// New creates a new Server instance.
func New() *Server {
	ctx := context.Background()
	logger := slog.Default().With("component", "prcost-server")

	// Create HTTP client with proper timeouts for reliability.
	httpClient := &http.Client{
		Timeout: httpClientTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        maxIdleConns,
			MaxIdleConnsPerHost: maxIdleConnsPerHost,
			IdleConnTimeout:     idleConnTimeout,
		},
	}

	// Configure CSRF protection using Sec-Fetch-Site and Origin headers.
	// This prevents cross-site request forgery attacks by blocking cross-origin
	// POST requests. GET, HEAD, and OPTIONS are safe methods and automatically allowed.
	// Requests without Sec-Fetch-Site or Origin headers are assumed same-origin or non-browser.
	csrfProtection := http.NewCrossOriginProtection()

	logger.InfoContext(ctx, "Server initialized with CSRF protection enabled")

	server := &Server{
		logger:          logger,
		serverCommit:    "", // Will be set via build flags
		dataSource:      "turnserver",
		httpClient:      httpClient,
		csrfProtection:  csrfProtection,
		ipLimiters:      make(map[string]*rate.Limiter),
		rateLimit:       DefaultRateLimit,
		rateBurst:       DefaultRateBurst,
		prQueryCache:    make(map[string]*cacheEntry),
		prDataCache:     make(map[string]*cacheEntry),
		calcResultCache: make(map[string]*cacheEntry),
	}

	// Load GitHub token at startup and cache in memory for performance and billing.
	// This avoids repeated GSM API calls which cost money.
	token := server.token(ctx)
	if token != "" {
		logger.InfoContext(ctx, "GitHub fallback token loaded at startup")
	} else {
		logger.InfoContext(ctx, "No fallback token available - requests must provide Authorization header")
	}

	// Note: We don't clear caches periodically because:
	// - PR data is immutable (closed PRs don't change)
	// - Memory usage is bounded by request patterns
	// - Cloud Run instances are ephemeral and restart frequently anyway
	// If needed in the future, implement LRU eviction with size limits instead of time-based clearing

	// Initialize DataStore client if DATASTORE_DB is set (persistent caching across restarts).
	if dbID := os.Getenv("DATASTORE_DB"); dbID != "" {
		dsClient, err := datastore.NewClientWithDatabase(ctx, "", dbID)
		if err != nil {
			logger.WarnContext(ctx, "Failed to initialize DataStore client - persistent caching disabled",
				"database_id", dbID, "error", err)
		} else {
			server.dsClient = dsClient
			logger.InfoContext(ctx, "DataStore persistent caching enabled",
				"database_id", dbID)
		}
	} else {
		logger.InfoContext(ctx, "DataStore persistent caching disabled (DATASTORE_DB not set)")
	}

	return server
}

// SetCommit sets the server commit hash.
func (s *Server) SetCommit(commit string) {
	s.serverCommit = commit
}

// SetCORSConfig sets the CORS configuration.
//
//nolint:revive // flag-parameter: allowAll is a clear boolean flag for CORS configuration
func (s *Server) SetCORSConfig(origins string, allowAll bool) {
	ctx := context.Background()
	if allowAll {
		s.allowAllCors = true
		s.logger.WarnContext(ctx, "🚨 CORS configured to allow all origins - DEVELOPMENT MODE ONLY")
		return
	}

	s.allowAllCors = false
	if origins != "" {
		for _, origin := range strings.Split(origins, ",") {
			origin = strings.TrimSpace(origin)

			// Validate wildcard patterns: must be *.domain.com or https://*.domain.com
			if strings.Contains(origin, "*") {
				valid := strings.HasPrefix(origin, "*.") ||
					strings.HasPrefix(origin, "https://*.") ||
					strings.HasPrefix(origin, "http://*.")
				if !valid || strings.Count(origin, "*") > 1 {
					s.logger.ErrorContext(ctx, "Invalid wildcard CORS origin", "origin", origin)
					continue
				}
			}

			s.allowedOrigins = append(s.allowedOrigins, origin)
		}
		s.logger.InfoContext(ctx, "CORS origins configured", "origins", s.allowedOrigins)
	}
}

// SetRateLimit sets the rate limiting configuration.
func (s *Server) SetRateLimit(rps int, burst int) {
	ctx := context.Background()
	s.rateLimit = rps
	s.rateBurst = burst
	s.logger.InfoContext(ctx, "Rate limit configured (per-IP)", "requests_per_sec", rps, "burst", burst)
}

// SetDataSource sets the data source for PR data fetching.
func (s *Server) SetDataSource(source string) {
	ctx := context.Background()
	if source != "turnserver" && source != "prx" {
		s.logger.WarnContext(ctx, "Invalid data source, using default", "requested", source, "default", "prx")
		s.dataSource = "prx"
		return
	}
	s.dataSource = source
	s.logger.InfoContext(ctx, "Data source configured", "source", source)
}

// SetR2RCallout enables or disables the Ready to Review promotional callout.
func (s *Server) SetR2RCallout(enabled bool) {
	s.r2rCallout = enabled
}

// limiter returns a rate limiter for the given IP address.
func (s *Server) limiter(ctx context.Context, ip string) *rate.Limiter {
	s.ipLimitersMu.RLock()
	limiter, exists := s.ipLimiters[ip]
	s.ipLimitersMu.RUnlock()

	if exists {
		return limiter
	}

	s.ipLimitersMu.Lock()
	defer s.ipLimitersMu.Unlock()

	// Double-check after acquiring write lock.
	if existingLimiter, exists := s.ipLimiters[ip]; exists {
		return existingLimiter
	}

	limiter = rate.NewLimiter(rate.Limit(s.rateLimit), s.rateBurst)
	s.ipLimiters[ip] = limiter

	// Cleanup old limiters if map grows too large (prevent memory leak).
	const maxLimiters = 10000
	if len(s.ipLimiters) > maxLimiters {
		count := 0
		target := len(s.ipLimiters) / 2
		for ip := range s.ipLimiters {
			delete(s.ipLimiters, ip)
			count++
			if count >= target {
				break
			}
		}
		s.logger.InfoContext(ctx, "Cleaned up old IP rate limiters", "removed", count, "remaining", len(s.ipLimiters))
	}

	return limiter
}

// cachedPRQuery retrieves cached PR query results from memory first, then DataStore as fallback.
func (s *Server) cachedPRQuery(ctx context.Context, key string) ([]github.PRSummary, bool) {
	// Check in-memory cache first (fast path).
	s.prQueryCacheMu.RLock()
	entry, exists := s.prQueryCache[key]
	s.prQueryCacheMu.RUnlock()

	if exists {
		prs, ok := entry.data.([]github.PRSummary)
		if ok {
			s.logger.DebugContext(ctx, "PR query cache hit (memory)", "key", key)
			return prs, true
		}
	}

	// Memory miss - try DataStore if available.
	if s.dsClient == nil {
		return nil, false
	}

	dsKey := datastore.NameKey("PRQueryCache", key, nil)
	var entity prQueryCacheEntity
	err := s.dsClient.Get(ctx, dsKey, &entity)
	if err != nil {
		if !errors.Is(err, datastore.ErrNoSuchEntity) {
			s.logger.WarnContext(ctx, "DataStore cache read failed", "key", key, "error", err)
		}
		return nil, false
	}

	// Check if expired (TTL varies by query type).
	if time.Now().After(entity.ExpiresAt) {
		s.logger.DebugContext(ctx, "DataStore cache entry expired", "key", key, "expires_at", entity.ExpiresAt)
		return nil, false
	}

	// Deserialize the cached data.
	var prs []github.PRSummary
	if err := json.Unmarshal([]byte(entity.Data), &prs); err != nil {
		s.logger.WarnContext(ctx, "Failed to deserialize cached PR query", "key", key, "error", err)
		return nil, false
	}

	s.logger.InfoContext(ctx, "PR query cache hit (DataStore)",
		"key", key, "query_type", entity.QueryType, "cached_at", entity.CachedAt, "pr_count", len(prs))

	// Populate in-memory cache for faster subsequent access.
	s.prQueryCacheMu.Lock()
	s.prQueryCache[key] = &cacheEntry{data: prs}
	s.prQueryCacheMu.Unlock()

	return prs, true
}

// cachePRQuery stores PR query results in both memory and DataStore caches.
func (s *Server) cachePRQuery(ctx context.Context, key string, prs []github.PRSummary) {
	// Write to in-memory cache first (fast path).
	s.prQueryCacheMu.Lock()
	s.prQueryCache[key] = &cacheEntry{data: prs}
	s.prQueryCacheMu.Unlock()

	// Write to DataStore if available (persistent cache).
	if s.dsClient == nil {
		return
	}

	// Serialize the PR query results.
	dataJSON, err := json.Marshal(prs)
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to serialize PR query for DataStore", "key", key, "error", err)
		return
	}

	// Determine query type and TTL from key format.
	var queryType string
	var ttl time.Duration
	switch {
	case strings.HasPrefix(key, "repo:"):
		queryType = "repo"
		ttl = 60 * time.Hour // 60 hours for repo queries
	case strings.HasPrefix(key, "org:"):
		queryType = "org"
		ttl = 60 * time.Hour // 60 hours for org queries
	default:
		s.logger.WarnContext(ctx, "Unknown query type for key, using default TTL", "key", key)
		queryType = "unknown"
		ttl = 60 * time.Hour // Default to 60 hours
	}

	now := time.Now()
	entity := prQueryCacheEntity{
		Data:      string(dataJSON),
		CachedAt:  now,
		ExpiresAt: now.Add(ttl),
		QueryType: queryType,
		QueryKey:  key,
	}

	dsKey := datastore.NameKey("PRQueryCache", key, nil)
	if _, err := s.dsClient.Put(ctx, dsKey, &entity); err != nil {
		s.logger.WarnContext(ctx, "Failed to write PR query to DataStore", "key", key, "error", err)
		return
	}

	s.logger.DebugContext(ctx, "PR query cached to DataStore",
		"key", key, "query_type", queryType, "ttl", ttl, "expires_at", entity.ExpiresAt, "pr_count", len(prs))
}

// cachedPRData retrieves cached PR data from memory first, then DataStore as fallback.
func (s *Server) cachedPRData(ctx context.Context, key string) (cost.PRData, bool) {
	// Check in-memory cache first (fast path).
	s.prDataCacheMu.RLock()
	entry, exists := s.prDataCache[key]
	s.prDataCacheMu.RUnlock()

	if exists {
		prData, ok := entry.data.(cost.PRData)
		if ok {
			s.logger.DebugContext(ctx, "PR data cache hit (memory)", "key", key)
			return prData, true
		}
	}

	// Memory miss - try DataStore if available.
	if s.dsClient == nil {
		return cost.PRData{}, false
	}

	dsKey := datastore.NameKey("PRDataCache", key, nil)
	var entity prDataCacheEntity
	err := s.dsClient.Get(ctx, dsKey, &entity)
	if err != nil {
		if !errors.Is(err, datastore.ErrNoSuchEntity) {
			s.logger.WarnContext(ctx, "DataStore cache read failed", "key", key, "error", err)
		}
		return cost.PRData{}, false
	}

	// Check if expired (1 hour TTL for PRs).
	if time.Now().After(entity.ExpiresAt) {
		s.logger.DebugContext(ctx, "DataStore cache entry expired", "key", key, "expires_at", entity.ExpiresAt)
		return cost.PRData{}, false
	}

	// Deserialize the cached data.
	var prData cost.PRData
	if err := json.Unmarshal([]byte(entity.Data), &prData); err != nil {
		s.logger.WarnContext(ctx, "Failed to deserialize cached PR data", "key", key, "error", err)
		return cost.PRData{}, false
	}

	s.logger.InfoContext(ctx, "PR data cache hit (DataStore)", "key", key, "cached_at", entity.CachedAt)

	// Populate in-memory cache for faster subsequent access.
	s.prDataCacheMu.Lock()
	s.prDataCache[key] = &cacheEntry{data: prData}
	s.prDataCacheMu.Unlock()

	return prData, true
}

// cachePRData stores PR data in both memory and DataStore caches.
func (s *Server) cachePRData(ctx context.Context, key string, prData cost.PRData) {
	// Write to in-memory cache first (fast path).
	s.prDataCacheMu.Lock()
	s.prDataCache[key] = &cacheEntry{data: prData}
	s.prDataCacheMu.Unlock()

	// Write to DataStore if available (persistent cache).
	if s.dsClient == nil {
		return
	}

	// Serialize the PR data.
	dataJSON, err := json.Marshal(prData)
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to serialize PR data for DataStore", "key", key, "error", err)
		return
	}

	now := time.Now()
	entity := prDataCacheEntity{
		Data:      string(dataJSON),
		CachedAt:  now,
		ExpiresAt: now.Add(1 * time.Hour), // 1 hour TTL for PRs
		URL:       key,
	}

	dsKey := datastore.NameKey("PRDataCache", key, nil)
	if _, err := s.dsClient.Put(ctx, dsKey, &entity); err != nil {
		s.logger.WarnContext(ctx, "Failed to write PR data to DataStore", "key", key, "error", err)
		return
	}

	s.logger.DebugContext(ctx, "PR data cached to DataStore", "key", key, "expires_at", entity.ExpiresAt)
}

// configHash creates a deterministic hash key for a cost.Config.
// Returns a short hash string suitable for use in cache keys.
func configHash(cfg cost.Config) string {
	// Create a deterministic string representation of the config
	// Use %.2f for floats to avoid floating point precision issues
	return fmt.Sprintf("s%.0f_e%.0f_ci%.0f_co%.0f_g%.0f_d%.2f",
		cfg.AnnualSalary,
		cfg.EventDuration.Minutes(),
		cfg.ContextSwitchInDuration.Minutes(),
		cfg.ContextSwitchOutDuration.Minutes(),
		cfg.SessionGapThreshold.Minutes(),
		cfg.DeliveryDelayFactor)
}

// cachedCalcResult retrieves cached calculation result from memory first, then DataStore as fallback.
func (s *Server) cachedCalcResult(ctx context.Context, prURL string, cfg cost.Config) (cost.Breakdown, bool) {
	key := fmt.Sprintf("calc:%s:%s", prURL, configHash(cfg))

	// Check in-memory cache first (fast path).
	s.calcResultCacheMu.RLock()
	entry, exists := s.calcResultCache[key]
	s.calcResultCacheMu.RUnlock()

	if exists {
		breakdown, ok := entry.data.(cost.Breakdown)
		if ok {
			return breakdown, true
		}
	}

	// Memory miss - try DataStore if available.
	if s.dsClient == nil {
		return cost.Breakdown{}, false
	}

	dsKey := datastore.NameKey("CalcResultCache", key, nil)
	var entity calcResultCacheEntity
	err := s.dsClient.Get(ctx, dsKey, &entity)
	if err != nil {
		if !errors.Is(err, datastore.ErrNoSuchEntity) {
			s.logger.WarnContext(ctx, "DataStore calc cache read failed", "key", key, "error", err)
		}
		return cost.Breakdown{}, false
	}

	// Check if expired.
	if time.Now().After(entity.ExpiresAt) {
		return cost.Breakdown{}, false
	}

	// Deserialize the cached data.
	var breakdown cost.Breakdown
	if err := json.Unmarshal([]byte(entity.Data), &breakdown); err != nil {
		s.logger.WarnContext(ctx, "Failed to deserialize cached calc result", "key", key, "error", err)
		return cost.Breakdown{}, false
	}

	// Populate in-memory cache for faster subsequent access.
	s.calcResultCacheMu.Lock()
	s.calcResultCache[key] = &cacheEntry{data: breakdown}
	s.calcResultCacheMu.Unlock()

	return breakdown, true
}

// cacheCalcResult stores calculation result in both memory and DataStore caches.
func (s *Server) cacheCalcResult(ctx context.Context, prURL string, cfg cost.Config, b *cost.Breakdown, ttl time.Duration) {
	key := fmt.Sprintf("calc:%s:%s", prURL, configHash(cfg))

	// Write to in-memory cache first (fast path).
	s.calcResultCacheMu.Lock()
	s.calcResultCache[key] = &cacheEntry{data: *b}
	s.calcResultCacheMu.Unlock()

	// Write to DataStore if available (persistent cache).
	if s.dsClient == nil {
		return
	}

	// Serialize the calculation result.
	dataJSON, err := json.Marshal(b)
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to serialize calc result for DataStore", "key", key, "error", err)
		return
	}

	now := time.Now()
	entity := calcResultCacheEntity{
		Data:      string(dataJSON),
		CachedAt:  now,
		ExpiresAt: now.Add(ttl),
		URL:       prURL,
		ConfigKey: configHash(cfg),
	}

	dsKey := datastore.NameKey("CalcResultCache", key, nil)
	if _, err := s.dsClient.Put(ctx, dsKey, &entity); err != nil {
		s.logger.WarnContext(ctx, "Failed to write calc result to DataStore", "key", key, "error", err)
		return
	}

	s.logger.DebugContext(ctx, "Calc result cached to DataStore", "key", key, "ttl", ttl, "expires_at", entity.ExpiresAt)
}

// SetTokenValidation configures GitHub token validation.
func (s *Server) SetTokenValidation(appID string, keyFile string) error {
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("read GitHub App key file: %w", err)
	}
	ctx := context.Background()
	s.validateTokens = true
	s.githubAppID = appID
	s.githubAppKeyData = keyData
	s.logger.InfoContext(ctx, "Token validation enabled", "github_app_id", appID)
	return nil
}

// Shutdown gracefully shuts down the server.
func (*Server) Shutdown() {
	// Nothing to do - in-memory structures will be garbage collected.
}

// sanitizeError removes tokens from error messages before logging.
func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	return tokenPattern.ReplaceAllString(errStr, "[REDACTED_TOKEN]")
}

// ServeHTTP implements http.Handler interface.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Apply CSRF protection FIRST - blocks cross-origin POST requests.
	// Uses Sec-Fetch-Site and Origin headers to detect cross-origin requests.
	// GET, HEAD, and OPTIONS methods are always allowed (safe methods).
	if s.csrfProtection != nil {
		if err := s.csrfProtection.Check(r); err != nil {
			s.logger.WarnContext(r.Context(), "CSRF check failed - cross-origin request denied",
				"origin", r.Header.Get("Origin"),
				"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"),
				"path", r.URL.Path,
				"method", r.Method,
				"remote_addr", r.RemoteAddr,
				"error", err)
			http.Error(w, "Cross-origin request denied", http.StatusForbidden)
			return
		}
	}

	// Security headers - defense in depth.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")

	// Handle CORS.
	origin := r.Header.Get("Origin")
	if s.allowAllCors {
		// SECURITY: Never use wildcard with credentials - validate origin even in dev mode.
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			s.logger.DebugContext(r.Context(), "CORS allowed (dev mode)", "origin", origin)
		}
	} else if origin != "" && s.isOriginAllowed(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	// Handle preflight OPTIONS request.
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Route requests.
	switch {
	case r.URL.Path == "/v1/calculate":
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleCalculate(w, r)
	case r.URL.Path == "/v1/calculate/repo":
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRepoSample(w, r)
	case r.URL.Path == "/v1/calculate/org":
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleOrgSample(w, r)
	case r.URL.Path == "/v1/calculate/repo/stream":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRepoSampleStream(w, r)
	case r.URL.Path == "/v1/calculate/org/stream":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleOrgSampleStream(w, r)
	case r.URL.Path == "/health":
		s.handleHealth(w, r)
	case strings.HasPrefix(r.URL.Path, "/static/"):
		s.handleStatic(w, r)
	case r.URL.Path == "/":
		s.handleWebUI(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleCalculate processes PR cost calculation requests.
func (s *Server) handleCalculate(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	// Extract client IP for rate limiting and logging.
	// SECURITY: X-Forwarded-For is trusted because Cloud Run (GCP) sanitizes it.
	// Cloud Run strips client-provided XFF headers and replaces with actual client IP.
	// For non-Cloud Run deployments, consider validating source or using RemoteAddr only.
	clientIP := request.RemoteAddr
	if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			clientIP = strings.TrimSpace(xff[:idx])
		} else {
			clientIP = strings.TrimSpace(xff)
		}
	} else if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		clientIP = host
	}

	// Log incoming request.
	s.logger.InfoContext(ctx, "[handleCalculate] Incoming request", "client_ip", clientIP, "method", request.Method, "path", request.URL.Path)

	// Per-IP rate limiting (SECURITY: Prevents single client from DoS-ing all users).
	limiter := s.limiter(ctx, clientIP)
	if !limiter.Allow() {
		s.logger.WarnContext(ctx, "[handleCalculate] Rate limit exceeded", "client_ip", clientIP, "path", request.URL.Path)
		http.Error(writer, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Parse request.
	req, err := s.parseRequest(ctx, request)
	if err != nil {
		s.logger.ErrorContext(ctx, "[handleCalculate] Failed to parse request", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	// Get auth token - try Authorization header first, then fallback to env/GSM.
	token := s.extractToken(request)
	if token == "" {
		// Try fallback token (GITHUB_TOKEN env var or GITHUB_SECRET from GSM)
		token = s.token(ctx)
		if token == "" {
			s.logger.WarnContext(ctx, "[handleCalculate] No GitHub token available", "remote_addr", request.RemoteAddr)
			http.Error(writer, "GitHub token required (set GITHUB_TOKEN env var or provide Authorization header)", http.StatusUnauthorized)
			return
		}
	}

	// Validate token if configured.
	if s.validateTokens {
		if err := s.validateGitHubToken(ctx, token); err != nil {
			s.logger.WarnContext(ctx, "[handleCalculate] Token validation failed", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
			http.Error(writer, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
	}

	// Process request.
	response, err := s.processRequest(ctx, req, token)
	if err != nil {
		s.logger.ErrorContext(ctx, "[handleCalculate] Error processing request",
			"remote_addr", request.RemoteAddr, "url", req.URL, errorKey, sanitizeError(err))
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Send response.
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		s.logger.ErrorContext(ctx, "[handleCalculate] Error encoding response", errorKey, err)
		// At this point, headers have been sent, so we can't change the status code.
		// Log the error for monitoring.
		return
	}

	// Log successful request.
	s.logger.InfoContext(ctx, "[handleCalculate] Request completed",
		"url", req.URL, "total_cost", response.Breakdown.TotalCost)
}

// parseRequest parses and validates the incoming request.
func (s *Server) parseRequest(ctx context.Context, r *http.Request) (*CalculateRequest, error) {
	var req CalculateRequest

	// Handle GET requests with query parameters
	if r.Method == http.MethodGet {
		query := r.URL.Query()
		req.URL = query.Get("url")
		req.Config = parseConfigFromQuery(query)
	} else {
		// Handle POST requests with JSON body
		// SECURITY: Limit request body size to prevent memory exhaustion DoS.
		const maxRequestSize = 1 << 20 // 1MB
		r.Body = http.MaxBytesReader(nil, r.Body, maxRequestSize)

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.logger.ErrorContext(ctx, "[parseRequest] Failed to decode JSON", errorKey, sanitizeError(err))
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
	}

	if req.URL == "" {
		s.logger.ErrorContext(ctx, "[parseRequest] Missing required field: url")
		return nil, errors.New("missing required field: url")
	}

	// Validate GitHub PR URL format.
	if err := s.validateGitHubPRURL(req.URL); err != nil {
		s.logger.ErrorContext(ctx, "[parseRequest] Invalid URL", "url", req.URL, errorKey, err.Error())
		return nil, err
	}

	return &req, nil
}

// parseConfigFromQuery extracts salary and benefits from query parameters.
func parseConfigFromQuery(query url.Values) *cost.Config {
	salaryStr := query.Get("salary")
	benefitsStr := query.Get("benefits")
	if salaryStr == "" && benefitsStr == "" {
		return nil
	}

	cfg := &cost.Config{}
	if salaryStr != "" {
		if salary, err := strconv.ParseFloat(salaryStr, 64); err == nil {
			cfg.AnnualSalary = salary
		}
	}
	if benefitsStr != "" {
		if benefits, err := strconv.ParseFloat(benefitsStr, 64); err == nil {
			cfg.BenefitsMultiplier = benefits
		}
	}
	return cfg
}

// validateGitHubPRURL performs strict validation of GitHub PR URLs.
func (*Server) validateGitHubPRURL(prURL string) error {
	// Length check prevents DoS attacks with extremely long URLs.
	if len(prURL) > maxURLLength {
		return errors.New("URL too long")
	}

	u, err := url.Parse(prURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only accept https://github.com URLs (prevents SSRF).
	if u.Scheme != "https" || u.Host != "github.com" {
		return errors.New("only https://github.com URLs allowed")
	}

	// Reject URLs with credentials, query params, or fragments.
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("URL must be a plain GitHub PR URL")
	}

	// Validate path: /owner/repo/pull/number
	// GitHub limits: owner ≤ 39 chars, repo ≤ 100 chars, PR number ≤ 10 digits.
	prURLPattern := regexp.MustCompile(`^/([a-zA-Z0-9][-a-zA-Z0-9]{0,38})/([a-zA-Z0-9_.-]{1,100})/pull/(\d{1,10})/?$`)
	if !prURLPattern.MatchString(u.Path) {
		return errors.New("invalid GitHub PR URL format")
	}

	return nil
}

// extractToken extracts the GitHub token from the Authorization header.
func (*Server) extractToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	// Support "Bearer token" and "token token" formats.
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	if strings.HasPrefix(auth, "token ") {
		return strings.TrimPrefix(auth, "token ")
	}

	return auth
}

// token retrieves a GitHub token from environment or Google Secret Manager.
// Results are cached in memory to avoid repeated API calls (performance and billing).
// Priority: GITHUB_TOKEN env var, then GITHUB_TOKEN from GSM.
func (s *Server) token(ctx context.Context) string {
	// Check cache first (read lock)
	s.fallbackTokenMu.RLock()
	if s.fallbackToken != "" {
		token := s.fallbackToken
		s.fallbackTokenMu.RUnlock()
		return token
	}
	s.fallbackTokenMu.RUnlock()

	// Acquire write lock to fetch token
	s.fallbackTokenMu.Lock()
	defer s.fallbackTokenMu.Unlock()

	// Double-check after acquiring write lock
	if s.fallbackToken != "" {
		return s.fallbackToken
	}

	// Try GITHUB_TOKEN environment variable first (for local development)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		s.logger.InfoContext(ctx, "Using GITHUB_TOKEN from environment variable")
		s.fallbackToken = token
		return token
	}

	// Try gh auth token if gh is in PATH
	if ghPath, err := exec.LookPath("gh"); err == nil {
		s.logger.InfoContext(ctx, "Found gh CLI in PATH", "path", ghPath)
		cmd := exec.CommandContext(ctx, "gh", "auth", "token")
		output, err := cmd.Output()
		if err == nil {
			token := strings.TrimSpace(string(output))
			if token != "" {
				s.logger.InfoContext(ctx, "Using GITHUB_TOKEN from gh auth token")
				s.fallbackToken = token
				return token
			}
		} else {
			s.logger.WarnContext(ctx, "Failed to get token from gh auth token", errorKey, err)
		}
	}

	// Try Google Secret Manager for GITHUB_TOKEN
	token, err := gsm.Fetch(ctx, "GITHUB_TOKEN")
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to fetch GITHUB_TOKEN from GSM", errorKey, err)
		return ""
	}

	if token != "" {
		s.logger.InfoContext(ctx, "Using GITHUB_TOKEN from Google Secret Manager")
		s.fallbackToken = token
		return token
	}

	s.logger.WarnContext(ctx, "No fallback GitHub token found (tried GITHUB_TOKEN env, gh auth token, and GITHUB_TOKEN GSM)")
	return ""
}

// processRequest processes the PR cost calculation request.
func (s *Server) processRequest(ctx context.Context, req *CalculateRequest, token string) (*CalculateResponse, error) {
	// Use default config if not provided, otherwise merge with defaults.
	cfg := cost.DefaultConfig()
	if req.Config != nil {
		cfg = s.mergeConfig(cfg, req.Config)
	}

	// Try calculation result cache first (includes both PR data + calculation)
	breakdown, calcCached := s.cachedCalcResult(ctx, req.URL, cfg)
	if calcCached {
		return &CalculateResponse{
			Breakdown: breakdown,
			Timestamp: time.Now(),
			Commit:    s.serverCommit,
		}, nil
	}

	// Cache miss - need to fetch PR data and calculate
	cacheKey := fmt.Sprintf("pr:%s", req.URL)
	prData, prCached := s.cachedPRData(ctx, cacheKey)
	var secondsInState map[string]int
	if !prCached {
		// Fetch PR data using configured data source
		var err error
		// For single PR requests, use 1 hour ago as reference time to enable reasonable caching
		referenceTime := time.Now().Add(-1 * time.Hour)
		if s.dataSource == "turnserver" {
			// Use turnserver for PR data with analysis
			prDataWithAnalysis, err := github.FetchPRDataWithAnalysisViaTurnserver(ctx, req.URL, token, referenceTime)
			if err != nil {
				s.logger.ErrorContext(ctx, "[processRequest] Failed to fetch PR data", "url", req.URL, "source", s.dataSource, errorKey, err)
				// Check if it's an access error (404, 403) - return error to client.
				if IsAccessError(err) {
					s.logger.WarnContext(ctx, "[processRequest] Access denied", "url", req.URL)
					return nil, NewAccessError(http.StatusForbidden, "access denied to PR")
				}
				return nil, fmt.Errorf("failed to fetch PR data: %w", err)
			}
			prData = prDataWithAnalysis.PRData
			secondsInState = prDataWithAnalysis.Analysis.SecondsInState
		} else {
			// Use prx for PR data
			prData, err = github.FetchPRData(ctx, req.URL, token, referenceTime)
			if err != nil {
				s.logger.ErrorContext(ctx, "[processRequest] Failed to fetch PR data", "url", req.URL, "source", s.dataSource, errorKey, err)
				// Check if it's an access error (404, 403) - return error to client.
				if IsAccessError(err) {
					s.logger.WarnContext(ctx, "[processRequest] Access denied", "url", req.URL)
					return nil, NewAccessError(http.StatusForbidden, "access denied to PR")
				}
				return nil, fmt.Errorf("failed to fetch PR data: %w", err)
			}
		}

		s.logger.InfoContext(ctx, "[processRequest] PR data cache miss - fetched from GitHub", "url", req.URL)
		// Cache PR data with 1 hour TTL for direct PR requests
		s.cachePRData(ctx, cacheKey, prData)
	}

	// Calculate costs.
	breakdown = cost.Calculate(prData, cfg)

	// Cache the calculation result with 1 hour TTL for direct PR requests
	s.cacheCalcResult(ctx, req.URL, cfg, &breakdown, 1*time.Hour)

	return &CalculateResponse{
		Breakdown:      breakdown,
		Timestamp:      time.Now(),
		Commit:         s.serverCommit,
		SecondsInState: secondsInState,
	}, nil
}

// isOriginAllowed checks if an origin is in the allowed list.
// Supports exact matches and wildcard subdomain patterns (*.example.com or https://*.example.com).
func (s *Server) isOriginAllowed(origin string) bool {
	// Parse origin to extract protocol and host
	if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
		return false
	}

	// Extract protocol and host from origin
	protocolEnd := strings.Index(origin, "://")
	if protocolEnd == -1 {
		return false
	}
	protocol := origin[:protocolEnd]

	host := origin[protocolEnd+3:]
	// Remove port if present
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}
	// Remove path if present
	if slashIndex := strings.Index(host, "/"); slashIndex != -1 {
		host = host[:slashIndex]
	}

	for _, allowed := range s.allowedOrigins {
		// Exact match
		if allowed == origin {
			return true
		}

		// Wildcard subdomain match
		// Handle both "*.example.com" and "https://*.example.com" formats
		if strings.Contains(allowed, "*") {
			var wildcardDomain string
			var requiredProtocol string

			switch {
			case strings.HasPrefix(allowed, "http://"), strings.HasPrefix(allowed, "https://"):
				// Format: "https://*.example.com"
				allowedProtocolEnd := strings.Index(allowed, "://")
				if allowedProtocolEnd == -1 {
					continue
				}
				requiredProtocol = allowed[:allowedProtocolEnd]
				wildcardPart := allowed[allowedProtocolEnd+3:]

				if !strings.HasPrefix(wildcardPart, "*.") {
					continue
				}
				wildcardDomain = wildcardPart[2:] // Remove "*."

				// Protocol must match
				if protocol != requiredProtocol {
					continue
				}
			case strings.HasPrefix(allowed, "*."):
				// Format: "*.example.com"
				wildcardDomain = allowed[2:] // Remove "*."
			default:
				continue
			}

			// Check if host matches the wildcard domain
			// Matches: example.com, sub.example.com, deep.sub.example.com
			// Doesn't match: notexample.com, fakeexample.com
			if host == wildcardDomain || strings.HasSuffix(host, "."+wildcardDomain) {
				return true
			}
		}
	}
	return false
}

// validateGitHubToken validates a GitHub token by making a test API call.
func (s *Server) validateGitHubToken(ctx context.Context, token string) error {
	// Simple validation by checking the user endpoint.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.ErrorContext(ctx, "[validateGitHubToken] Error closing response body", errorKey, err)
		}
	}()

	// Read and discard body to ensure connection can be reused.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		s.logger.ErrorContext(ctx, "[validateGitHubToken] Error discarding response body", errorKey, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid token (status %d)", resp.StatusCode)
	}

	return nil
}

// handleHealth provides a simple health check endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "healthy"}); err != nil {
		s.logger.ErrorContext(ctx, "[handleHealth] Error encoding response", errorKey, err)
	}
}

// handleWebUI serves the embedded web UI.
func (s *Server) handleWebUI(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Read the embedded HTML file
	htmlContent, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		s.logger.ErrorContext(ctx, "[handleWebUI] Failed to read index.html", errorKey, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(htmlContent); err != nil {
		s.logger.ErrorContext(ctx, "[handleWebUI] Error writing response", errorKey, err)
	}
}

// handleStatic serves embedded static files.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Strip leading slash to match embed.FS structure
	path := strings.TrimPrefix(r.URL.Path, "/")

	// Read the embedded file
	content, err := staticFS.ReadFile(path)
	if err != nil {
		s.logger.WarnContext(ctx, "[handleStatic] File not found", "path", path, errorKey, err)
		http.NotFound(w, r)
		return
	}

	// Set content type based on file extension
	var contentType string
	switch {
	case strings.HasSuffix(path, ".png"):
		contentType = "image/png"
	case strings.HasSuffix(path, ".jpg"), strings.HasSuffix(path, ".jpeg"):
		contentType = "image/jpeg"
	case strings.HasSuffix(path, ".ico"):
		contentType = "image/x-icon"
	case strings.HasSuffix(path, ".css"):
		contentType = "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		contentType = "application/javascript; charset=utf-8"
	default:
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(content); err != nil {
		s.logger.ErrorContext(ctx, "[handleStatic] Error writing response", errorKey, err)
	}
}

// handleRepoSample processes repository sampling requests.
func (s *Server) handleRepoSample(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	// Extract client IP for rate limiting and logging.
	// SECURITY: X-Forwarded-For is trusted because Cloud Run (GCP) sanitizes it.
	// Cloud Run strips client-provided XFF headers and replaces with actual client IP.
	// For non-Cloud Run deployments, consider validating source or using RemoteAddr only.
	clientIP := request.RemoteAddr
	if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			clientIP = strings.TrimSpace(xff[:idx])
		} else {
			clientIP = strings.TrimSpace(xff)
		}
	} else if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		clientIP = host
	}

	// Log incoming request.
	s.logger.InfoContext(ctx, "[handleRepoSample] Incoming request", "client_ip", clientIP)

	// Per-IP rate limiting.
	limiter := s.limiter(ctx, clientIP)
	if !limiter.Allow() {
		s.logger.WarnContext(ctx, "[handleRepoSample] Rate limit exceeded", "client_ip", clientIP)
		http.Error(writer, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Parse request.
	req, err := s.parseRepoSampleRequest(ctx, request)
	if err != nil {
		s.logger.ErrorContext(ctx, "[handleRepoSample] Failed to parse request", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	// Get auth token - try Authorization header first, then fallback.
	token := s.extractToken(request)
	if token == "" {
		token = s.token(ctx)
		if token == "" {
			s.logger.WarnContext(ctx, "[handleRepoSample] No GitHub token available", "remote_addr", request.RemoteAddr)
			http.Error(writer, "GitHub token required (set GITHUB_TOKEN env var or provide Authorization header)", http.StatusUnauthorized)
			return
		}
	}

	// Validate token if configured.
	if s.validateTokens {
		if err := s.validateGitHubToken(ctx, token); err != nil {
			s.logger.WarnContext(ctx, "[handleRepoSample] Token validation failed", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
			http.Error(writer, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
	}

	// Process request.
	response, err := s.processRepoSample(ctx, req, token)
	if err != nil {
		s.logger.ErrorContext(ctx, "[handleRepoSample] Error processing request",
			"remote_addr", request.RemoteAddr, "owner", req.Owner, "repo", req.Repo, errorKey, sanitizeError(err))
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Send response.
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		s.logger.ErrorContext(ctx, "[handleRepoSample] Error encoding response", errorKey, err)
		return
	}

	// Log successful request.
	s.logger.InfoContext(ctx, "[handleRepoSample] Request completed",
		"owner", req.Owner, "repo", req.Repo, "total_cost", response.Extrapolated.TotalCost)
}

// handleOrgSample processes organization sampling requests.
func (s *Server) handleOrgSample(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	// Extract client IP for rate limiting and logging.
	// SECURITY: X-Forwarded-For is trusted because Cloud Run (GCP) sanitizes it.
	// Cloud Run strips client-provided XFF headers and replaces with actual client IP.
	// For non-Cloud Run deployments, consider validating source or using RemoteAddr only.
	clientIP := request.RemoteAddr
	if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			clientIP = strings.TrimSpace(xff[:idx])
		} else {
			clientIP = strings.TrimSpace(xff)
		}
	} else if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		clientIP = host
	}

	// Log incoming request.
	s.logger.InfoContext(ctx, "[handleOrgSample] Incoming request", "client_ip", clientIP)

	// Per-IP rate limiting.
	limiter := s.limiter(ctx, clientIP)
	if !limiter.Allow() {
		s.logger.WarnContext(ctx, "[handleOrgSample] Rate limit exceeded", "client_ip", clientIP)
		http.Error(writer, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Parse request.
	req, err := s.parseOrgSampleRequest(ctx, request)
	if err != nil {
		s.logger.ErrorContext(ctx, "[handleOrgSample] Failed to parse request", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	// Get auth token - try Authorization header first, then fallback.
	token := s.extractToken(request)
	if token == "" {
		token = s.token(ctx)
		if token == "" {
			s.logger.WarnContext(ctx, "[handleOrgSample] No GitHub token available", "remote_addr", request.RemoteAddr)
			http.Error(writer, "GitHub token required (set GITHUB_TOKEN env var or provide Authorization header)", http.StatusUnauthorized)
			return
		}
	}

	// Validate token if configured.
	if s.validateTokens {
		if err := s.validateGitHubToken(ctx, token); err != nil {
			s.logger.WarnContext(ctx, "[handleOrgSample] Token validation failed", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
			http.Error(writer, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
	}

	// Process request.
	response, err := s.processOrgSample(ctx, req, token)
	if err != nil {
		s.logger.ErrorContext(ctx, "[handleOrgSample] Error processing request",
			"remote_addr", request.RemoteAddr, "org", req.Org, errorKey, sanitizeError(err))
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Send response.
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		s.logger.ErrorContext(ctx, "[handleOrgSample] Error encoding response", errorKey, err)
		return
	}

	// Log successful request.
	s.logger.InfoContext(ctx, "[handleOrgSample] Request completed",
		"org", req.Org, "total_cost", response.Extrapolated.TotalCost)
}

// parseRepoSampleRequest parses and validates repository sampling requests.
func (s *Server) parseRepoSampleRequest(ctx context.Context, r *http.Request) (*RepoSampleRequest, error) {
	var req RepoSampleRequest

	// Handle GET requests with query parameters
	if r.Method == http.MethodGet {
		query := r.URL.Query()
		req.Owner = query.Get("owner")
		req.Repo = query.Get("repo")

		// Parse optional parameters
		if sampleStr := query.Get("sample"); sampleStr != "" {
			if sample, err := strconv.Atoi(sampleStr); err == nil {
				req.SampleSize = sample
			}
		}
		if daysStr := query.Get("days"); daysStr != "" {
			if days, err := strconv.Atoi(daysStr); err == nil {
				req.Days = days
			}
		}
		req.Config = parseConfigFromQuery(query)
	} else {
		// Handle POST requests with JSON body
		const maxRequestSize = 1 << 20 // 1MB
		r.Body = http.MaxBytesReader(nil, r.Body, maxRequestSize)

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.logger.ErrorContext(ctx, "[parseRepoSampleRequest] Failed to decode JSON", errorKey, sanitizeError(err))
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
	}

	if req.Owner == "" {
		return nil, errors.New("missing required field: owner")
	}
	if req.Repo == "" {
		return nil, errors.New("missing required field: repo")
	}

	// Set defaults
	if req.SampleSize == 0 {
		req.SampleSize = 250
	}
	if req.Days == 0 {
		req.Days = 60
	}

	// Validate reasonable limits (silently cap at 250)
	if req.SampleSize < 1 {
		return nil, errors.New("sample_size must be at least 1")
	}
	if req.SampleSize > 250 {
		req.SampleSize = 250
	}
	if req.Days < 1 || req.Days > 365 {
		return nil, errors.New("days must be between 1 and 365")
	}

	return &req, nil
}

// parseOrgSampleRequest parses and validates organization sampling requests.
func (s *Server) parseOrgSampleRequest(ctx context.Context, r *http.Request) (*OrgSampleRequest, error) {
	var req OrgSampleRequest

	// Handle GET requests with query parameters
	if r.Method == http.MethodGet {
		query := r.URL.Query()
		req.Org = query.Get("org")

		// Parse optional parameters
		if sampleStr := query.Get("sample"); sampleStr != "" {
			if sample, err := strconv.Atoi(sampleStr); err == nil {
				req.SampleSize = sample
			}
		}
		if daysStr := query.Get("days"); daysStr != "" {
			if days, err := strconv.Atoi(daysStr); err == nil {
				req.Days = days
			}
		}
		req.Config = parseConfigFromQuery(query)
	} else {
		// Handle POST requests with JSON body
		const maxRequestSize = 1 << 20 // 1MB
		r.Body = http.MaxBytesReader(nil, r.Body, maxRequestSize)

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.logger.ErrorContext(ctx, "[parseOrgSampleRequest] Failed to decode JSON", errorKey, sanitizeError(err))
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
	}

	if req.Org == "" {
		return nil, errors.New("missing required field: org")
	}

	// Set defaults
	if req.SampleSize == 0 {
		req.SampleSize = 250
	}
	if req.Days == 0 {
		req.Days = 60
	}

	// Validate reasonable limits (silently cap at 250)
	if req.SampleSize < 1 {
		return nil, errors.New("sample_size must be at least 1")
	}
	if req.SampleSize > 250 {
		req.SampleSize = 250
	}
	if req.Days < 1 || req.Days > 365 {
		return nil, errors.New("days must be between 1 and 365")
	}

	return &req, nil
}

// processRepoSample processes a repository sampling request.
func (s *Server) processRepoSample(ctx context.Context, req *RepoSampleRequest, token string) (*SampleResponse, error) {
	var actualDays int
	// Use default config if not provided
	cfg := cost.DefaultConfig()
	if req.Config != nil {
		cfg = s.mergeConfig(cfg, req.Config)
	}

	// Calculate since date
	since := time.Now().AddDate(0, 0, -req.Days)

	// Fetch all PRs modified since the date (cache uses query hash internally)
	var err error
	var queryHash string
	prs, queryHash, err := github.FetchPRsFromRepo(ctx, req.Owner, req.Repo, since, token, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PRs: %w", err)
	}

	// Cache key includes query hash to invalidate when query structure changes
	cacheKey := fmt.Sprintf("repo:%s/%s:days=%d:qh=%s", req.Owner, req.Repo, req.Days, queryHash)

	s.logger.InfoContext(ctx, "Fetched PRs from repository",
		"owner", req.Owner, "repo", req.Repo, "total_prs", len(prs), "query_hash", queryHash)

	// Cache query results
	s.cachePRQuery(ctx, cacheKey, prs)

	if len(prs) == 0 {
		return nil, fmt.Errorf("no PRs found in the last %d days", req.Days)
	}

	// Calculate actual time window (may be less than requested if we hit API limit)
	actualDays, _ = github.CalculateActualTimeWindow(prs, req.Days)

	// Sample PRs
	samples := github.SamplePRs(prs, req.SampleSize)
	s.logger.InfoContext(ctx, "Sampled PRs", "sample_size", len(samples))

	// Collect breakdowns from each sample and aggregate seconds_in_state
	var breakdowns []cost.Breakdown
	aggregatedSeconds := make(map[string]int)
	for i, pr := range samples {
		prURL := fmt.Sprintf("https://github.com/%s/%s/pull/%d", req.Owner, req.Repo, pr.Number)
		s.logger.InfoContext(ctx, "Processing sample PR",
			"repo", fmt.Sprintf("%s/%s", req.Owner, req.Repo),
			"number", pr.Number,
			"progress", fmt.Sprintf("%d/%d", i+1, len(samples)))

		// Try cache first
		prCacheKey := fmt.Sprintf("pr:%s", prURL)
		prData, prCached := s.cachedPRData(ctx, prCacheKey)
		var secondsInState map[string]int
		if !prCached {
			var err error
			// Use configured data source with updatedAt for effective caching
			if s.dataSource == "turnserver" {
				var prDataWithAnalysis github.PRDataWithAnalysis
				prDataWithAnalysis, err = github.FetchPRDataWithAnalysisViaTurnserver(ctx, prURL, token, pr.UpdatedAt)
				if err == nil {
					prData = prDataWithAnalysis.PRData
					secondsInState = prDataWithAnalysis.Analysis.SecondsInState
				}
			} else {
				prData, err = github.FetchPRData(ctx, prURL, token, pr.UpdatedAt)
			}
			if err != nil {
				s.logger.WarnContext(ctx, "Failed to fetch PR data, skipping", "pr_number", pr.Number, "source", s.dataSource, errorKey, err)
				continue
			}

			// Cache PR data
			s.cachePRData(ctx, prCacheKey, prData)
		}

		// Aggregate seconds_in_state
		for state, seconds := range secondsInState {
			aggregatedSeconds[state] += seconds
		}

		breakdown := cost.Calculate(prData, cfg)
		breakdowns = append(breakdowns, breakdown)
	}

	if len(breakdowns) == 0 {
		return nil, errors.New("no samples could be processed successfully")
	}

	// Count unique authors across all PRs (not just samples)
	totalAuthors := github.CountUniqueAuthors(prs)

	// Query for actual count of open PRs (not extrapolated from samples)
	openPRCount, err := github.CountOpenPRsInRepo(ctx, req.Owner, req.Repo, token)
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to count open PRs, using 0", errorKey, err)
		openPRCount = 0
	}

	// Convert PRSummary to PRSummaryInfo for extrapolation
	prSummaryInfos := make([]cost.PRSummaryInfo, len(prs))
	for i, pr := range prs {
		prSummaryInfos[i] = cost.PRSummaryInfo{
			Owner:      pr.Owner,
			Repo:       pr.Repo,
			Author:     pr.Author,
			AuthorType: pr.AuthorType,
			CreatedAt:  pr.CreatedAt,
			UpdatedAt:  pr.UpdatedAt,
			ClosedAt:   pr.ClosedAt,
			Merged:     pr.Merged,
			State:      pr.State,
		}
	}

	// Extrapolate costs from samples
	extrapolated := cost.ExtrapolateFromSamples(breakdowns, len(prs), totalAuthors, openPRCount, actualDays, cfg, prSummaryInfos, nil)

	// Only include seconds_in_state if we have data (turnserver only)
	var secondsInState map[string]int
	if len(aggregatedSeconds) > 0 {
		secondsInState = aggregatedSeconds
	}

	return &SampleResponse{
		Extrapolated:   extrapolated,
		Timestamp:      time.Now(),
		Commit:         s.serverCommit,
		SecondsInState: secondsInState,
	}, nil
}

// processOrgSample processes an organization sampling request.
func (s *Server) processOrgSample(ctx context.Context, req *OrgSampleRequest, token string) (*SampleResponse, error) {
	var actualDays int
	// Use default config if not provided
	cfg := cost.DefaultConfig()
	if req.Config != nil {
		cfg = s.mergeConfig(cfg, req.Config)
	}

	// Calculate since date
	since := time.Now().AddDate(0, 0, -req.Days)

	// Fetch all PRs across the org modified since the date (cache uses query hash internally)
	var err error
	var queryHash string
	prs, queryHash, err := github.FetchPRsFromOrg(ctx, req.Org, since, token, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch PRs: %w", err)
	}

	// Cache key includes query hash to invalidate when query structure changes
	cacheKey := fmt.Sprintf("org:%s:days=%d:qh=%s", req.Org, req.Days, queryHash)

	s.logger.InfoContext(ctx, "Fetched PRs from organization", "org", req.Org, "total_prs", len(prs), "query_hash", queryHash)

	// Cache query results
	s.cachePRQuery(ctx, cacheKey, prs)

	if len(prs) == 0 {
		return nil, fmt.Errorf("no PRs found in the last %d days", req.Days)
	}

	// Fetch repository visibility for the organization (2x the time period for comprehensive coverage)
	reposSince := time.Now().AddDate(0, 0, -req.Days*2)
	repoVisibilityData, err := github.FetchOrgRepositoriesWithActivity(ctx, req.Org, reposSince, token)
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to fetch repository visibility, assuming all public", "error", err)
		repoVisibilityData = nil
	}

	// Convert RepoVisibility map to bool map (repo name -> isPrivate)
	var repoVisibility map[string]bool
	if repoVisibilityData != nil {
		repoVisibility = make(map[string]bool, len(repoVisibilityData))
		for name, visibility := range repoVisibilityData {
			repoVisibility[name] = visibility.IsPrivate
		}
	}

	// Calculate actual time window (may be less than requested if we hit API limit)
	actualDays, _ = github.CalculateActualTimeWindow(prs, req.Days)

	// Sample PRs
	samples := github.SamplePRs(prs, req.SampleSize)
	s.logger.InfoContext(ctx, "Sampled PRs", "sample_size", len(samples))

	// Collect breakdowns from each sample and aggregate seconds_in_state
	var breakdowns []cost.Breakdown
	aggregatedSeconds := make(map[string]int)
	for i, pr := range samples {
		prURL := fmt.Sprintf("https://github.com/%s/%s/pull/%d", pr.Owner, pr.Repo, pr.Number)
		s.logger.InfoContext(ctx, "Processing sample PR",
			"repo", fmt.Sprintf("%s/%s", pr.Owner, pr.Repo),
			"number", pr.Number,
			"progress", fmt.Sprintf("%d/%d", i+1, len(samples)))

		// Try cache first
		prCacheKey := fmt.Sprintf("pr:%s", prURL)
		prData, prCached := s.cachedPRData(ctx, prCacheKey)
		var secondsInState map[string]int
		if !prCached {
			var err error
			// Use configured data source with updatedAt for effective caching
			if s.dataSource == "turnserver" {
				var prDataWithAnalysis github.PRDataWithAnalysis
				prDataWithAnalysis, err = github.FetchPRDataWithAnalysisViaTurnserver(ctx, prURL, token, pr.UpdatedAt)
				if err == nil {
					prData = prDataWithAnalysis.PRData
					secondsInState = prDataWithAnalysis.Analysis.SecondsInState
				}
			} else {
				prData, err = github.FetchPRData(ctx, prURL, token, pr.UpdatedAt)
			}
			if err != nil {
				s.logger.WarnContext(ctx, "Failed to fetch PR data, skipping", "pr_number", pr.Number, "source", s.dataSource, errorKey, err)
				continue
			}

			// Cache PR data
			s.cachePRData(ctx, prCacheKey, prData)
		}

		// Aggregate seconds_in_state
		for state, seconds := range secondsInState {
			aggregatedSeconds[state] += seconds
		}

		breakdown := cost.Calculate(prData, cfg)
		breakdowns = append(breakdowns, breakdown)
	}

	if len(breakdowns) == 0 {
		return nil, errors.New("no samples could be processed successfully")
	}

	// Count unique authors across all PRs (not just samples)
	totalAuthors := github.CountUniqueAuthors(prs)

	// Count open PRs across the entire organization with a single query
	totalOpenPRs, err := github.CountOpenPRsInOrg(ctx, req.Org, token)
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to count open PRs in organization, using 0", errorKey, err)
		totalOpenPRs = 0
	}
	s.logger.InfoContext(ctx, "Counted total open PRs across organization", "org", req.Org, "open_prs", totalOpenPRs)

	// Convert PRSummary to PRSummaryInfo for extrapolation
	prSummaryInfos := make([]cost.PRSummaryInfo, len(prs))
	for i, pr := range prs {
		prSummaryInfos[i] = cost.PRSummaryInfo{
			Owner:      pr.Owner,
			Repo:       pr.Repo,
			Author:     pr.Author,
			AuthorType: pr.AuthorType,
			CreatedAt:  pr.CreatedAt,
			UpdatedAt:  pr.UpdatedAt,
			ClosedAt:   pr.ClosedAt,
			Merged:     pr.Merged,
			State:      pr.State,
		}
	}

	// Extrapolate costs from samples
	extrapolated := cost.ExtrapolateFromSamples(breakdowns, len(prs), totalAuthors, totalOpenPRs, actualDays, cfg, prSummaryInfos, repoVisibility)

	// Only include seconds_in_state if we have data (turnserver only)
	var secondsInState map[string]int
	if len(aggregatedSeconds) > 0 {
		secondsInState = aggregatedSeconds
	}

	return &SampleResponse{
		Extrapolated:   extrapolated,
		Timestamp:      time.Now(),
		Commit:         s.serverCommit,
		SecondsInState: secondsInState,
	}, nil
}

// mergeConfig merges a provided config with defaults.
func (*Server) mergeConfig(base cost.Config, override *cost.Config) cost.Config {
	if override == nil {
		return base
	}
	if override.AnnualSalary > 0 {
		base.AnnualSalary = override.AnnualSalary
	}
	if override.BenefitsMultiplier > 0 {
		base.BenefitsMultiplier = override.BenefitsMultiplier
	}
	if override.HoursPerYear > 0 {
		base.HoursPerYear = override.HoursPerYear
	}
	if override.EventDuration > 0 {
		base.EventDuration = override.EventDuration
	}
	if override.ContextSwitchInDuration > 0 {
		base.ContextSwitchInDuration = override.ContextSwitchInDuration
	}
	if override.ContextSwitchOutDuration > 0 {
		base.ContextSwitchOutDuration = override.ContextSwitchOutDuration
	}
	if override.SessionGapThreshold > 0 {
		base.SessionGapThreshold = override.SessionGapThreshold
	}
	if override.DeliveryDelayFactor > 0 {
		base.DeliveryDelayFactor = override.DeliveryDelayFactor
	}
	if override.MaxDelayAfterLastEvent > 0 {
		base.MaxDelayAfterLastEvent = override.MaxDelayAfterLastEvent
	}
	if override.MaxProjectDelay > 0 {
		base.MaxProjectDelay = override.MaxProjectDelay
	}
	if override.MaxCodeDrift > 0 {
		base.MaxCodeDrift = override.MaxCodeDrift
	}
	if override.ReviewInspectionRate > 0 {
		base.ReviewInspectionRate = override.ReviewInspectionRate
	}
	if override.ModificationCostFactor > 0 {
		base.ModificationCostFactor = override.ModificationCostFactor
	}
	return base
}

// handleRepoSampleStream processes repository sampling requests with Server-Sent Events for progress updates.
//
//nolint:dupl // Similar to handleOrgSampleStream but with different request types
func (s *Server) handleRepoSampleStream(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	// Extract client IP for rate limiting and logging.
	// SECURITY: X-Forwarded-For is trusted because Cloud Run (GCP) sanitizes it.
	// Cloud Run strips client-provided XFF headers and replaces with actual client IP.
	// For non-Cloud Run deployments, consider validating source or using RemoteAddr only.
	clientIP := request.RemoteAddr
	if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			clientIP = strings.TrimSpace(xff[:idx])
		} else {
			clientIP = strings.TrimSpace(xff)
		}
	} else if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		clientIP = host
	}

	s.logger.InfoContext(ctx, "[handleRepoSampleStream] Incoming request", "client_ip", clientIP)

	// Per-IP rate limiting.
	limiter := s.limiter(ctx, clientIP)
	if !limiter.Allow() {
		s.logger.WarnContext(ctx, "[handleRepoSampleStream] Rate limit exceeded", "client_ip", clientIP)
		http.Error(writer, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Parse request.
	req, err := s.parseRepoSampleRequest(ctx, request)
	if err != nil {
		//nolint:revive // line-length: acceptable for logging
		s.logger.ErrorContext(ctx, "[handleRepoSampleStream] Failed to parse request", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	// Get auth token - try Authorization header first, then fallback.
	token := s.extractToken(request)
	if token == "" {
		token = s.token(ctx)
		if token == "" {
			s.logger.WarnContext(ctx, "[handleRepoSampleStream] No GitHub token available", "remote_addr", request.RemoteAddr)
			http.Error(writer, "GitHub token required (set GITHUB_TOKEN env var or provide Authorization header)", http.StatusUnauthorized)
			return
		}
	}

	// Validate token if configured.
	if s.validateTokens {
		if err := s.validateGitHubToken(ctx, token); err != nil {
			//nolint:revive // line-length: acceptable for logging
			s.logger.WarnContext(ctx, "[handleRepoSampleStream] Token validation failed", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
			http.Error(writer, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
	}

	// Set up SSE headers.
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")

	// Flush headers immediately to establish SSE connection before processing starts.
	// This prevents the browser from closing the connection while waiting for the first event.
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}

	// Process request with progress updates.
	s.processRepoSampleWithProgress(ctx, req, token, writer)
}

// handleOrgSampleStream processes organization sampling requests with Server-Sent Events for progress updates.
//
//nolint:dupl // Similar to handleRepoSampleStream but with different request types
func (s *Server) handleOrgSampleStream(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()

	// Extract client IP for rate limiting and logging.
	// SECURITY: X-Forwarded-For is trusted because Cloud Run (GCP) sanitizes it.
	// Cloud Run strips client-provided XFF headers and replaces with actual client IP.
	// For non-Cloud Run deployments, consider validating source or using RemoteAddr only.
	clientIP := request.RemoteAddr
	if xff := request.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			clientIP = strings.TrimSpace(xff[:idx])
		} else {
			clientIP = strings.TrimSpace(xff)
		}
	} else if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		clientIP = host
	}

	s.logger.InfoContext(ctx, "[handleOrgSampleStream] Incoming request", "client_ip", clientIP)

	// Per-IP rate limiting.
	limiter := s.limiter(ctx, clientIP)
	if !limiter.Allow() {
		s.logger.WarnContext(ctx, "[handleOrgSampleStream] Rate limit exceeded", "client_ip", clientIP)
		http.Error(writer, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Parse request.
	req, err := s.parseOrgSampleRequest(ctx, request)
	if err != nil {
		s.logger.ErrorContext(ctx, "[handleOrgSampleStream] Failed to parse request", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	// Get auth token - try Authorization header first, then fallback.
	token := s.extractToken(request)
	if token == "" {
		token = s.token(ctx)
		if token == "" {
			s.logger.WarnContext(ctx, "[handleOrgSampleStream] No GitHub token available", "remote_addr", request.RemoteAddr)
			http.Error(writer, "GitHub token required (set GITHUB_TOKEN env var or provide Authorization header)", http.StatusUnauthorized)
			return
		}
	}

	// Validate token if configured.
	if s.validateTokens {
		if err := s.validateGitHubToken(ctx, token); err != nil {
			//nolint:revive // line-length: acceptable for logging
			s.logger.WarnContext(ctx, "[handleOrgSampleStream] Token validation failed", "remote_addr", request.RemoteAddr, errorKey, sanitizeError(err))
			http.Error(writer, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
	}

	// Set up SSE headers.
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")

	// Flush headers immediately to establish SSE connection before processing starts.
	// This prevents the browser from closing the connection while waiting for the first event.
	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	}

	// Process request with progress updates.
	s.processOrgSampleWithProgress(ctx, req, token, writer)
}

// sendSSE sends a Server-Sent Event to the client.
func sendSSE(w http.ResponseWriter, update ProgressUpdate) error {
	data, err := json.Marshal(update)
	if err != nil {
		return fmt.Errorf("failed to marshal progress update: %w", err)
	}

	// SSE format: "data: <json>\n\n"
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return fmt.Errorf("failed to write SSE: %w", err)
	}

	// Flush immediately to ensure client receives the update.
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	return nil
}

// startKeepAlive starts a goroutine that sends SSE keep-alive comments every 2 seconds.
// This prevents client-side timeouts during long operations.
// Returns a stop channel (to stop keep-alive) and an error channel (signals connection failure).
func startKeepAlive(w http.ResponseWriter) (stop chan struct{}, connErr <-chan error) {
	stopChan := make(chan struct{})
	errChan := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		defer close(errChan)
		for {
			select {
			case <-ticker.C:
				// Send SSE comment (keeps connection alive, ignored by client)
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					errChan <- fmt.Errorf("keepalive write failed: %w", err)
					return
				}
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
			case <-stopChan:
				return
			}
		}
	}()
	return stopChan, errChan
}

// logSSEError logs an error from sendSSE if it occurs.
// SSE errors are typically client disconnects and can be safely ignored.
func logSSEError(ctx context.Context, logger *slog.Logger, err error) {
	if err != nil {
		logger.WarnContext(ctx, "SSE write failed (client may have disconnected)", errorKey, err)
	}
}

// processRepoSampleWithProgress processes a repository sample with progress updates via SSE.
func (s *Server) processRepoSampleWithProgress(ctx context.Context, req *RepoSampleRequest, token string, writer http.ResponseWriter) {
	var actualDays int
	// Use background context for work to prevent client timeout from canceling operations
	// The request context (ctx) is only used for SSE writes and logging
	workCtx := context.Background()

	defer func() {
		s.logger.InfoContext(ctx, "[processRepoSampleWithProgress] Stream handler completed",
			"owner", req.Owner,
			"repo", req.Repo)
	}()

	// Send initial event immediately to establish SSE connection and prevent browser timeout
	if err := sendSSE(writer, ProgressUpdate{
		Type: "fetching",
		PR:   0, // No specific PR yet
	}); err != nil {
		s.logger.ErrorContext(ctx, "[processRepoSampleWithProgress] Failed to send initial SSE event", errorKey, err)
		return
	}

	// Use default config if not provided
	cfg := cost.DefaultConfig()
	if req.Config != nil {
		cfg = s.mergeConfig(cfg, req.Config)
	}

	// Calculate since date
	since := time.Now().AddDate(0, 0, -req.Days)

	// Send progress update before GraphQL query
	logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
		Type:     "fetching",
		PR:       0,
		Owner:    req.Owner,
		Repo:     req.Repo,
		Progress: fmt.Sprintf("Querying GitHub GraphQL API for %s/%s PRs (last %d days)...", req.Owner, req.Repo, req.Days),
	}))

	// Start keep-alive to prevent client timeout during GraphQL query
	stopKeepAlive, connErr := startKeepAlive(writer)
	defer close(stopKeepAlive)

	// Check for connection errors in background
	go func() {
		if err := <-connErr; err != nil {
			s.logger.WarnContext(ctx, "Client connection lost", errorKey, err)
		}
	}()

	// Fetch all PRs modified since the date with progress updates
	var err error
	var queryHash string
	progressCallback := func(queryName string, page int, prCount int) {
		logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
			Type:     "fetching",
			PR:       0,
			Owner:    req.Owner,
			Repo:     req.Repo,
			Progress: fmt.Sprintf("Fetching %s PRs (page %d, %d PRs found)...", queryName, page, prCount),
		}))
	}
	//nolint:contextcheck // Using background context intentionally to prevent client timeout from canceling work
	prs, queryHash, err := github.FetchPRsFromRepo(workCtx, req.Owner, req.Repo, since, token, progressCallback)
	if err != nil {
		logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
			Type:  "error",
			Error: fmt.Sprintf("Failed to fetch PRs: %v", err),
		}))
		return
	}

	// Cache key includes query hash to invalidate when query structure changes
	cacheKey := fmt.Sprintf("repo:%s/%s:days=%d:qh=%s", req.Owner, req.Repo, req.Days, queryHash)

	// Cache query results
	s.cachePRQuery(ctx, cacheKey, prs)

	if len(prs) == 0 {
		logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
			Type:  "error",
			Error: fmt.Sprintf("No PRs found in the last %d days", req.Days),
		}))
		return
	}

	// Calculate actual time window (may be less than requested if we hit API limit)
	actualDays, _ = github.CalculateActualTimeWindow(prs, req.Days)

	// Sample PRs
	samples := github.SamplePRs(prs, req.SampleSize)

	// Send progress update before processing samples
	logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
		Type:     "fetching",
		PR:       0,
		Owner:    req.Owner,
		Repo:     req.Repo,
		Progress: fmt.Sprintf("Processing %d sampled PRs...", len(samples)),
	}))

	// Process samples in parallel with progress updates
	breakdowns, aggregatedSeconds := s.processPRsInParallel(workCtx, ctx, samples, req.Owner, req.Repo, token, cfg, writer)

	if len(breakdowns) == 0 {
		logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
			Type:  "error",
			Error: "No samples could be processed successfully",
		}))
		return
	}

	// Count unique authors across all PRs (not just samples)
	totalAuthors := github.CountUniqueAuthors(prs)

	// Query for actual count of open PRs (not extrapolated from samples)
	//nolint:contextcheck // Using background context intentionally to prevent client timeout from canceling work
	openPRCount, err := github.CountOpenPRsInRepo(workCtx, req.Owner, req.Repo, token)
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to count open PRs, using 0", errorKey, err)
		openPRCount = 0
	}

	// Convert PRSummary to PRSummaryInfo for extrapolation
	prSummaryInfos := make([]cost.PRSummaryInfo, len(prs))
	for i, pr := range prs {
		prSummaryInfos[i] = cost.PRSummaryInfo{
			Owner:      pr.Owner,
			Repo:       pr.Repo,
			Author:     pr.Author,
			AuthorType: pr.AuthorType,
			CreatedAt:  pr.CreatedAt,
			UpdatedAt:  pr.UpdatedAt,
			ClosedAt:   pr.ClosedAt,
			Merged:     pr.Merged,
			State:      pr.State,
		}
	}

	// Extrapolate costs from samples
	extrapolated := cost.ExtrapolateFromSamples(breakdowns, len(prs), totalAuthors, openPRCount, actualDays, cfg, prSummaryInfos, nil)

	// Only include seconds_in_state if we have data (turnserver only)
	var secondsInState map[string]int
	if len(aggregatedSeconds) > 0 {
		secondsInState = aggregatedSeconds
	}

	// Send final result
	logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
		Type:           "done",
		Result:         &extrapolated,
		Commit:         s.serverCommit,
		R2RCallout:     s.r2rCallout,
		SecondsInState: secondsInState,
	}))
}

// processOrgSampleWithProgress processes an organization sample with progress updates via SSE.
func (s *Server) processOrgSampleWithProgress(ctx context.Context, req *OrgSampleRequest, token string, writer http.ResponseWriter) {
	var actualDays int
	// Use background context for work to prevent client timeout from canceling operations
	// The request context (ctx) is only used for SSE writes and logging
	workCtx := context.Background()

	defer func() {
		s.logger.InfoContext(ctx, "[processOrgSampleWithProgress] Stream handler completed",
			"org", req.Org)
	}()

	// Send initial event immediately to establish SSE connection and prevent browser timeout
	if err := sendSSE(writer, ProgressUpdate{
		Type: "fetching",
		PR:   0, // No specific PR yet
	}); err != nil {
		s.logger.ErrorContext(ctx, "[processOrgSampleWithProgress] Failed to send initial SSE event", errorKey, err)
		return
	}

	// Use default config if not provided
	cfg := cost.DefaultConfig()
	if req.Config != nil {
		cfg = s.mergeConfig(cfg, req.Config)
	}

	// Calculate since date
	since := time.Now().AddDate(0, 0, -req.Days)

	// Send progress update before GraphQL query
	logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
		Type:     "fetching",
		PR:       0,
		Progress: fmt.Sprintf("Querying GitHub Search API for %s org PRs (last %d days)...", req.Org, req.Days),
	}))

	// Start keep-alive to prevent client timeout during GraphQL query
	stopKeepAlive, connErr := startKeepAlive(writer)
	defer close(stopKeepAlive)

	// Check for connection errors in background
	go func() {
		if err := <-connErr; err != nil {
			s.logger.WarnContext(ctx, "Client connection lost", errorKey, err)
		}
	}()

	// Fetch all PRs across the org modified since the date with progress updates
	var err error
	var queryHash string
	progressCallback := func(queryName string, page int, prCount int) {
		logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
			Type:     "fetching",
			PR:       0,
			Owner:    req.Org,
			Repo:     "",
			Progress: fmt.Sprintf("Fetching %s PRs (page %d, %d PRs found)...", queryName, page, prCount),
		}))
	}
	//nolint:contextcheck // Using background context intentionally to prevent client timeout from canceling work
	prs, queryHash, err := github.FetchPRsFromOrg(workCtx, req.Org, since, token, progressCallback)
	if err != nil {
		logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
			Type:  "error",
			Error: fmt.Sprintf("Failed to fetch PRs: %v", err),
		}))
		return
	}

	// Cache key includes query hash to invalidate when query structure changes
	cacheKey := fmt.Sprintf("org:%s:days=%d:qh=%s", req.Org, req.Days, queryHash)

	// Cache query results
	s.cachePRQuery(ctx, cacheKey, prs)

	if len(prs) == 0 {
		logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
			Type:  "error",
			Error: fmt.Sprintf("No PRs found in the last %d days", req.Days),
		}))
		return
	}

	// Calculate actual time window (may be less than requested if we hit API limit)
	actualDays, _ = github.CalculateActualTimeWindow(prs, req.Days)

	// Sample PRs
	samples := github.SamplePRs(prs, req.SampleSize)

	s.logger.InfoContext(ctx, "[processOrgSampleWithProgress] Starting to process sampled PRs",
		"org", req.Org,
		"total_prs", len(prs),
		"sample_size", len(samples))

	// Send progress update before processing samples
	logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
		Type:     "fetching",
		PR:       0,
		Progress: fmt.Sprintf("Processing %d sampled PRs...", len(samples)),
	}))

	// Process samples in parallel with progress updates (org mode uses empty owner/repo since it's mixed)
	breakdowns, aggregatedSeconds := s.processPRsInParallel(workCtx, ctx, samples, "", "", token, cfg, writer)

	s.logger.InfoContext(ctx, "[processOrgSampleWithProgress] Finished processing samples",
		"org", req.Org,
		"successful_samples", len(breakdowns),
		"total_samples", len(samples))

	if len(breakdowns) == 0 {
		logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
			Type:  "error",
			Error: "No samples could be processed successfully",
		}))
		return
	}

	// Count unique authors across all PRs (not just samples)
	totalAuthors := github.CountUniqueAuthors(prs)

	// Count open PRs across the entire organization with a single GraphQL query
	//nolint:contextcheck // Using background context intentionally to prevent client timeout from canceling work
	totalOpenPRs, err := github.CountOpenPRsInOrg(workCtx, req.Org, token)
	if err != nil {
		s.logger.WarnContext(ctx, "Failed to count open PRs for organization", "org", req.Org, errorKey, err)
		totalOpenPRs = 0 // Continue with 0 if we can't get the count
	}
	s.logger.InfoContext(ctx, "Counted total open PRs across organization", "open_prs", totalOpenPRs, "org", req.Org)

	// Convert PRSummary to PRSummaryInfo for extrapolation
	prSummaryInfos := make([]cost.PRSummaryInfo, len(prs))
	for i, pr := range prs {
		prSummaryInfos[i] = cost.PRSummaryInfo{
			Owner:      pr.Owner,
			Repo:       pr.Repo,
			Author:     pr.Author,
			AuthorType: pr.AuthorType,
			CreatedAt:  pr.CreatedAt,
			UpdatedAt:  pr.UpdatedAt,
			ClosedAt:   pr.ClosedAt,
			Merged:     pr.Merged,
			State:      pr.State,
		}
	}

	// Extrapolate costs from samples
	extrapolated := cost.ExtrapolateFromSamples(breakdowns, len(prs), totalAuthors, totalOpenPRs, actualDays, cfg, prSummaryInfos, nil)

	// Only include seconds_in_state if we have data (turnserver only)
	var secondsInState map[string]int
	if len(aggregatedSeconds) > 0 {
		secondsInState = aggregatedSeconds
	}

	// Send final result
	logSSEError(ctx, s.logger, sendSSE(writer, ProgressUpdate{
		Type:           "done",
		Result:         &extrapolated,
		Commit:         s.serverCommit,
		R2RCallout:     s.r2rCallout,
		SecondsInState: secondsInState,
	}))
}

// processPRsInParallel processes PRs in parallel and sends progress updates via SSE.
//
//nolint:revive // line-length/use-waitgroup-go: long function signature acceptable, standard wg pattern
func (s *Server) processPRsInParallel(workCtx, reqCtx context.Context, samples []github.PRSummary, defaultOwner, defaultRepo, token string, cfg cost.Config, writer http.ResponseWriter) (breakdowns []cost.Breakdown, aggregatedSeconds map[string]int) {
	aggregatedSeconds = make(map[string]int)
	var mu sync.Mutex
	var sseMu sync.Mutex // Protects SSE writes to prevent corrupted chunked encoding

	// Use a buffered channel for worker pool pattern
	concurrency := 8 // Process up to 8 PRs concurrently
	semaphore := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
	totalSamples := len(samples)

	for idx, pr := range samples {
		wg.Add(1)
		go func(index int, prSummary github.PRSummary) {
			defer wg.Done()

			// Acquire semaphore slot
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Use PR's owner/repo if available, otherwise use defaults
			owner := prSummary.Owner
			repo := prSummary.Repo
			if owner == "" {
				owner = defaultOwner
			}
			if repo == "" {
				repo = defaultRepo
			}

			progress := fmt.Sprintf("%d/%d", index+1, totalSamples)

			// Send "fetching" update using request context for SSE
			sseMu.Lock()
			logSSEError(reqCtx, s.logger, sendSSE(writer, ProgressUpdate{
				Type:     "fetching",
				PR:       prSummary.Number,
				Owner:    owner,
				Repo:     repo,
				Progress: progress,
			}))
			sseMu.Unlock()

			prURL := fmt.Sprintf("https://github.com/%s/%s/pull/%d", owner, repo, prSummary.Number)

			// Try calculation result cache first (includes both PR data + calculation)
			breakdown, calcCached := s.cachedCalcResult(workCtx, prURL, cfg)
			if calcCached {
				// Already have the full calculation result
				mu.Lock()
				breakdowns = append(breakdowns, breakdown)
				mu.Unlock()

				// Send "complete" update using request context for SSE
				sseMu.Lock()
				logSSEError(reqCtx, s.logger, sendSSE(writer, ProgressUpdate{
					Type:     "complete",
					PR:       prSummary.Number,
					Owner:    owner,
					Repo:     repo,
					Progress: progress,
				}))
				sseMu.Unlock()
				return
			}

			// Cache miss - need to fetch PR data and calculate
			prCacheKey := fmt.Sprintf("pr:%s", prURL)
			prData, prCached := s.cachedPRData(workCtx, prCacheKey)
			var secondsInState map[string]int
			if !prCached {
				var err error
				// Use work context for actual API calls (not tied to client connection)
				// Use configured data source with updatedAt for effective caching
				if s.dataSource == "turnserver" {
					var prDataWithAnalysis github.PRDataWithAnalysis
					prDataWithAnalysis, err = github.FetchPRDataWithAnalysisViaTurnserver(workCtx, prURL, token, prSummary.UpdatedAt)
					if err == nil {
						prData = prDataWithAnalysis.PRData
						secondsInState = prDataWithAnalysis.Analysis.SecondsInState
					}
				} else {
					prData, err = github.FetchPRData(workCtx, prURL, token, prSummary.UpdatedAt)
				}
				if err != nil {
					s.logger.WarnContext(reqCtx, "Failed to fetch PR data, skipping", "pr_number", prSummary.Number, "source", s.dataSource, errorKey, err)
					sseMu.Lock()
					logSSEError(reqCtx, s.logger, sendSSE(writer, ProgressUpdate{
						Type:     "error",
						PR:       prSummary.Number,
						Owner:    owner,
						Repo:     repo,
						Progress: progress,
						Error:    fmt.Sprintf("Failed to fetch PR data: %v", err),
					}))
					sseMu.Unlock()
					return
				}

				s.logger.InfoContext(reqCtx, "PR data cache miss - fetched from GitHub",
					"pr_number", prSummary.Number, "owner", owner, "repo", repo)
				// Cache the PR data
				s.cachePRData(workCtx, prCacheKey, prData)
			}

			// Aggregate seconds_in_state
			mu.Lock()
			for state, seconds := range secondsInState {
				aggregatedSeconds[state] += seconds
			}
			mu.Unlock()

			// Send "processing" update using request context for SSE
			sseMu.Lock()
			logSSEError(reqCtx, s.logger, sendSSE(writer, ProgressUpdate{
				Type:     "processing",
				PR:       prSummary.Number,
				Owner:    owner,
				Repo:     repo,
				Progress: progress,
			}))
			sseMu.Unlock()

			breakdown = cost.Calculate(prData, cfg)

			// Cache the calculation result with 1 week TTL for PRs from queries
			s.cacheCalcResult(workCtx, prURL, cfg, &breakdown, 7*24*time.Hour)

			// Add to results
			mu.Lock()
			breakdowns = append(breakdowns, breakdown)
			mu.Unlock()

			// Send "complete" update using request context for SSE
			sseMu.Lock()
			logSSEError(reqCtx, s.logger, sendSSE(writer, ProgressUpdate{
				Type:     "complete",
				PR:       prSummary.Number,
				Owner:    owner,
				Repo:     repo,
				Progress: progress,
			}))
			sseMu.Unlock()
		}(idx, pr)
	}

	wg.Wait()
	return breakdowns, aggregatedSeconds
}
