package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
)

// PRSummary holds minimal information about a PR for sampling and fetching.
type PRSummary struct {
	UpdatedAt  time.Time
	CreatedAt  time.Time
	ClosedAt   *time.Time // Nil if still open
	Owner      string
	Repo       string
	Author     string
	AuthorType string // "Bot", "User", or empty if unknown
	State      string // "OPEN", "CLOSED", "MERGED"
	Number     int
	Merged     bool // Whether the PR was merged
}

// ProgressCallback is called during PR fetching to report progress.
// Parameters: queryName (e.g., "recent", "old", "early"), currentPage, totalPRsSoFar.
type ProgressCallback func(queryName string, page int, prCount int)

// IsBot determines if a PR author is likely a bot based on AuthorType and common naming patterns.
func IsBot(authorType, authorLogin string) bool {
	// Primary check: GitHub's __typename field
	if authorType == "Bot" {
		return true
	}

	// Fallback: Common bot naming patterns
	login := strings.ToLower(authorLogin)

	// Check for [bot] suffix
	if strings.HasSuffix(login, "[bot]") {
		return true
	}

	// Check for word-boundary bot patterns to avoid false positives like "robot"
	// Match bot with specific separators or as a suffix/prefix
	if strings.HasPrefix(login, "bot-") || strings.HasPrefix(login, "bot_") {
		return true
	}
	if strings.Contains(login, "-bot-") || strings.Contains(login, "_bot_") ||
		strings.Contains(login, "-bot") || strings.Contains(login, "_bot") {
		return true
	}

	// Specific bot names
	botNames := []string{
		"dependabot", "renovate", "greenkeeper",
		"github-actions", "codecov", "coveralls",
		"mergify", "snyk", "imgbot",
		"allcontributors", "stalebot",
		"netlify", "vercel",
		"codefactor-io", "deepsource-autofix",
		"pre-commit-ci", "ready-to-review",
	}
	for _, name := range botNames {
		if strings.Contains(login, name) {
			return true
		}
	}
	return false
}

// QueryHash computes a SHA256 hash of a GraphQL query string for cache key generation.
// This ensures that cache keys change when query structure changes.
func QueryHash(query string) string {
	hash := sha256.Sum256([]byte(query))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes (16 hex chars) for brevity
}

// FetchPRsFromRepo queries GitHub GraphQL API for all PRs in a repository
// modified since the specified date.
//
// Uses an adaptive multi-query strategy for comprehensive time coverage:
//  1. Query recent activity (updated DESC) - get up to 1000 PRs
//  2. If hit limit, query old activity (updated ASC) - get ~500 more
//  3. Check gap between oldest "recent" and newest "old"
//  4. If gap > 1 week, query early period (created ASC) - get ~250 more
//
// Parameters:
//   - ctx: Context for the API call
//   - owner: GitHub repository owner
//   - repo: GitHub repository name
//   - since: Only include PRs updated after this time
//   - token: GitHub authentication token
//   - progress: Optional callback for progress updates (can be nil)
//
// Returns:
//   - Slice of PRSummary for all matching PRs (deduplicated)
//   - Query hash for cache key generation
func FetchPRsFromRepo(ctx context.Context, owner, repo string, since time.Time, token string, progress ProgressCallback) ([]PRSummary, string, error) {
	// Query 1: Recent activity (updated DESC) - get up to 1000 PRs
	recent, hitLimit, queryHash, err := fetchPRsFromRepoWithSort(ctx, repoSortParams{
		owner: owner, repo: repo, since: since, token: token,
		field: "UPDATED_AT", direction: "DESC", maxPRs: 1000, queryName: "recent", progress: progress,
	})
	if err != nil {
		return nil, "", err
	}

	// If we didn't hit the limit, we got all PRs within the period - done!
	if !hitLimit {
		return recent, queryHash, nil
	}

	// Hit limit - need more coverage for earlier periods
	// Query 2: Old activity (updated ASC) - get ~500 more
	old, _, _, err := fetchPRsFromRepoWithSort(ctx, repoSortParams{
		owner: owner, repo: repo, since: since, token: token,
		field: "UPDATED_AT", direction: "ASC", maxPRs: 500, queryName: "old", progress: progress,
	})
	if err != nil {
		slog.Warn("Failed to fetch old PRs, falling back to recent only", "error", err)
		return recent, queryHash, nil
	}

	slog.Info("Fetched old PRs",
		"count", len(old))

	// Check gap between oldest "recent" and newest "old"
	if len(recent) > 0 && len(old) > 0 {
		oldestRecent := recent[len(recent)-1].UpdatedAt
		newestOld := old[0].UpdatedAt
		gap := oldestRecent.Sub(newestOld)

		slog.Info("Checking time coverage gap",
			"oldest_recent", oldestRecent.Format(time.RFC3339),
			"newest_old", newestOld.Format(time.RFC3339),
			"gap_hours", gap.Hours())

		// If gap > 1 week, we have a coverage hole - fill it
		const oneWeek = 7 * 24 * time.Hour
		if gap > oneWeek {
			slog.Info("Gap > 1 week detected, fetching early period PRs to fill coverage hole")

			// Query 3: Early period (created ASC) - get ~250 more
			early, _, _, err := fetchPRsFromRepoWithSort(ctx, repoSortParams{
				owner: owner, repo: repo, since: since, token: token,
				field: "CREATED_AT", direction: "ASC", maxPRs: 250, queryName: "early", progress: progress,
			})
			if err != nil {
				slog.Warn("Failed to fetch early PRs, proceeding with recent+old", "error", err)
				return deduplicatePRs(append(recent, old...)), queryHash, nil
			}

			slog.Info("Fetched early PRs",
				"count", len(early))

			return deduplicatePRs(append(append(recent, old...), early...)), queryHash, nil
		}
	}

	// Gap <= 1 week or no gap to check - merge recent + old
	return deduplicatePRs(append(recent, old...)), queryHash, nil
}

// repoSortParams contains parameters for sorted PR queries.
type repoSortParams struct {
	since     time.Time
	progress  ProgressCallback
	owner     string
	repo      string
	token     string
	field     string
	direction string
	queryName string
	maxPRs    int
}

// fetchPRsFromRepoWithSort queries GitHub GraphQL API with configurable sort order.
// Returns PRs, a boolean indicating if the API limit (1000) was hit, and a query hash for caching.
func fetchPRsFromRepoWithSort(ctx context.Context, params repoSortParams) ([]PRSummary, bool, string, error) {
	owner, repo := params.owner, params.repo
	since, token := params.since, params.token
	field, direction := params.field, params.direction
	maxPRs, queryName := params.maxPRs, params.queryName
	progress := params.progress

	// Build the GraphQL query - note we use %s placeholders for field/direction which vary
	// but the hash is computed from the base structure to detect field changes (like adding __typename)
	queryTemplate := `
	query($owner: String!, $name: String!, $cursor: String) {
		repository(owner: $owner, name: $name) {
			pullRequests(first: 100, after: $cursor, orderBy: {field: %s, direction: %s}) {
				totalCount
				pageInfo {
					hasNextPage
					endCursor
				}
				nodes {
					number
					createdAt
					updatedAt
					closedAt
					state
					merged
					author {
						login
						__typename
					}
				}
			}
		}
	}`
	query := fmt.Sprintf(queryTemplate, field, direction)

	// Compute hash from the template (before field/direction substitution) to detect structural changes
	queryHash := QueryHash(queryTemplate)

	var allPRs []PRSummary
	var cursor *string
	pageNum := 0
	hitLimit := false

	for {
		pageNum++
		// Build request body
		variables := map[string]any{
			"owner": owner,
			"name":  repo,
		}
		if cursor != nil {
			variables["cursor"] = *cursor
		}

		requestBody := map[string]any{
			"query":     query,
			"variables": variables,
		}

		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return nil, false, "", fmt.Errorf("failed to marshal request: %w", err)
		}

		// Make GraphQL request
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/graphql", bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, false, "", fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, false, "", fmt.Errorf("failed to execute request: %w", err)
		}
		//nolint:revive,gocritic // defer-in-loop: proper HTTP response cleanup pattern
		defer func() {
			if err := resp.Body.Close(); err != nil {
				slog.Warn("Failed to close response body", "error", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			return nil, false, "", fmt.Errorf("GraphQL request failed with status %d", resp.StatusCode)
		}

		// Parse response
		//nolint:govet // fieldalignment: anonymous GraphQL response struct
		var result struct {
			Data struct {
				Repository struct {
					PullRequests struct {
						PageInfo struct {
							HasNextPage bool
							EndCursor   string
						}
						Nodes []struct {
							Number    int
							CreatedAt time.Time
							UpdatedAt time.Time
							ClosedAt  *time.Time
							State     string
							Merged    bool
							Author    struct {
								Login    string
								TypeName string `json:"__typename"`
							}
						}
						TotalCount int
					}
				}
			}
			Errors []struct {
				Message string
			}
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, false, "", fmt.Errorf("failed to decode response: %w", err)
		}

		if len(result.Errors) > 0 {
			return nil, false, "", fmt.Errorf("GraphQL error: %s", result.Errors[0].Message)
		}

		totalCount := result.Data.Repository.PullRequests.TotalCount
		pageSize := len(result.Data.Repository.PullRequests.Nodes)
		hasNextPage := result.Data.Repository.PullRequests.PageInfo.HasNextPage

		slog.Info("GraphQL page fetched",
			"field", field,
			"direction", direction,
			"page", pageNum,
			"page_size", pageSize,
			"total_count", totalCount,
			"has_next_page", hasNextPage)

		// Filter and collect PRs modified since the date
		for _, node := range result.Data.Repository.PullRequests.Nodes {
			if node.UpdatedAt.Before(since) {
				// For DESC queries, we can stop early
				if direction == "DESC" {
					slog.Info("Stopping pagination - encountered PR older than cutoff",
						"collected_prs", len(allPRs),
						"pages_fetched", pageNum,
						"field", field,
						"direction", direction)
					return allPRs, hitLimit, queryHash, nil
				}
				// For ASC queries, skip and continue (older PRs come first)
				continue
			}
			allPRs = append(allPRs, PRSummary{
				Owner:      owner,
				Repo:       repo,
				Number:     node.Number,
				Author:     node.Author.Login,
				AuthorType: node.Author.TypeName,
				CreatedAt:  node.CreatedAt,
				UpdatedAt:  node.UpdatedAt,
				ClosedAt:   node.ClosedAt,
				State:      node.State,
				Merged:     node.Merged,
			})

			// Check if we've hit the maxPRs limit
			if len(allPRs) >= maxPRs {
				hitLimit = true
				slog.Info("Reached max PRs limit",
					"max_prs", maxPRs,
					"field", field,
					"direction", direction)
				return allPRs, hitLimit, queryHash, nil
			}
		}

		// Call progress callback after processing each page
		if progress != nil {
			progress(queryName, pageNum, len(allPRs))
		}

		// Check if we need to fetch more pages
		if !result.Data.Repository.PullRequests.PageInfo.HasNextPage {
			break
		}
		cursor = &result.Data.Repository.PullRequests.PageInfo.EndCursor
	}

	return allPRs, hitLimit, queryHash, nil
}

// deduplicatePRs removes duplicate PRs from a slice, keeping the first occurrence.
func deduplicatePRs(prs []PRSummary) []PRSummary {
	seen := make(map[int]bool)
	var unique []PRSummary

	for i := range prs {
		if !seen[prs[i].Number] {
			seen[prs[i].Number] = true
			unique = append(unique, prs[i])
		}
	}

	slog.Info("Deduplicated PRs",
		"total", len(prs),
		"unique", len(unique),
		"duplicates", len(prs)-len(unique))

	return unique
}

// FetchPRsFromOrg queries GitHub GraphQL Search API for all PRs across
// an organization modified since the specified date.
//
// Uses an adaptive multi-query strategy for comprehensive time coverage:
//  1. Query recent activity (updated desc) - get up to 1000 PRs
//  2. If hit limit, query old activity (updated asc) - get ~500 more
//  3. Check gap between oldest "recent" and newest "old"
//  4. If gap > 1 week, query early period (created asc) - get ~250 more
//
// Parameters:
//   - ctx: Context for the API call
//   - org: GitHub organization name
//   - since: Only include PRs updated after this time
//   - token: GitHub authentication token
//   - progress: Optional callback for progress updates (can be nil)
//
// Returns:
//   - Slice of PRSummary for all matching PRs (deduplicated)
//   - Query hash for cache key generation
func FetchPRsFromOrg(ctx context.Context, org string, since time.Time, token string, progress ProgressCallback) ([]PRSummary, string, error) {
	sinceStr := since.Format("2006-01-02")

	// Query 1: Recent activity (updated desc) - get up to 1000 PRs
	recent, hitLimit, queryHash, err := fetchPRsFromOrgWithSort(ctx, orgSortParams{
		org: org, sinceStr: sinceStr, token: token,
		field: "updated", direction: "desc", maxPRs: 1000, queryName: "recent", progress: progress,
	})
	if err != nil {
		return nil, "", err
	}

	slog.Info("Fetched recent PRs from org",
		"count", len(recent),
		"hit_limit", hitLimit)

	// If we didn't hit the limit, we got all PRs within the period - done!
	if !hitLimit {
		return recent, queryHash, nil
	}

	// Hit limit - need more coverage for earlier periods
	// Query 2: Old activity (updated asc) - get ~500 more
	old, _, _, err := fetchPRsFromOrgWithSort(ctx, orgSortParams{
		org: org, sinceStr: sinceStr, token: token,
		field: "updated", direction: "asc", maxPRs: 500, queryName: "old", progress: progress,
	})
	if err != nil {
		slog.Warn("Failed to fetch old PRs from org, falling back to recent only", "error", err)
		return recent, queryHash, nil
	}

	slog.Info("Fetched old PRs from org",
		"count", len(old))

	// Check gap between oldest "recent" and newest "old"
	if len(recent) > 0 && len(old) > 0 {
		oldestRecent := recent[len(recent)-1].UpdatedAt
		newestOld := old[0].UpdatedAt
		gap := oldestRecent.Sub(newestOld)

		slog.Info("Checking time coverage gap (org)",
			"oldest_recent", oldestRecent.Format(time.RFC3339),
			"newest_old", newestOld.Format(time.RFC3339),
			"gap_hours", gap.Hours())

		// If gap > 1 week, we have a coverage hole - fill it
		const oneWeek = 7 * 24 * time.Hour
		if gap > oneWeek {
			slog.Info("Gap > 1 week detected, fetching early period PRs to fill coverage hole (org)")

			// Query 3: Early period (created asc) - get ~250 more
			early, _, _, err := fetchPRsFromOrgWithSort(ctx, orgSortParams{
				org: org, sinceStr: sinceStr, token: token,
				field: "created", direction: "asc", maxPRs: 250, queryName: "early", progress: progress,
			})
			if err != nil {
				slog.Warn("Failed to fetch early PRs from org, proceeding with recent+old", "error", err)
				return deduplicatePRsByOwnerRepoNumber(append(recent, old...)), queryHash, nil
			}

			slog.Info("Fetched early PRs from org",
				"count", len(early))

			return deduplicatePRsByOwnerRepoNumber(append(append(recent, old...), early...)), queryHash, nil
		}
	}

	// Gap <= 1 week or no gap to check - merge recent + old
	return deduplicatePRsByOwnerRepoNumber(append(recent, old...)), queryHash, nil
}

// orgSortParams contains parameters for sorted org PR queries.
type orgSortParams struct {
	progress  ProgressCallback
	org       string
	sinceStr  string
	token     string
	field     string
	direction string
	queryName string
	maxPRs    int
}

// fetchPRsFromOrgWithSort queries GitHub Search API with configurable sort order.
// Returns PRs, a boolean indicating if the API limit (1000) was hit, and a query hash for caching.
func fetchPRsFromOrgWithSort(ctx context.Context, params orgSortParams) ([]PRSummary, bool, string, error) {
	org, sinceStr := params.org, params.sinceStr
	token := params.token
	field, direction := params.field, params.direction
	maxPRs, queryName := params.maxPRs, params.queryName
	progress := params.progress
	// Build search query with sort
	// Query format: org:myorg is:pr updated:>2025-07-25 sort:updated-desc
	searchQuery := fmt.Sprintf("org:%s is:pr %s:>%s sort:%s-%s", org, field, sinceStr, field, direction)

	const queryTemplate = `
	query($searchQuery: String!, $cursor: String) {
		search(query: $searchQuery, type: ISSUE, first: 100, after: $cursor) {
			issueCount
			pageInfo {
				hasNextPage
				endCursor
			}
			nodes {
				... on PullRequest {
					number
					createdAt
					updatedAt
					closedAt
					state
					merged
					author {
						login
						__typename
					}
					repository {
						owner {
							login
						}
						name
					}
				}
			}
		}
	}`

	// Compute hash from the query template to detect structural changes
	queryHash := QueryHash(queryTemplate)

	var allPRs []PRSummary
	var cursor *string
	pageNum := 0
	hitLimit := false

	for {
		pageNum++
		// Build request body
		variables := map[string]any{
			"searchQuery": searchQuery,
		}
		if cursor != nil {
			variables["cursor"] = *cursor
		}

		requestBody := map[string]any{
			"query":     queryTemplate,
			"variables": variables,
		}

		bodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			return nil, false, "", fmt.Errorf("failed to marshal request: %w", err)
		}

		// Make GraphQL request
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/graphql", bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, false, "", fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, false, "", fmt.Errorf("failed to execute request: %w", err)
		}
		//nolint:revive,gocritic // defer-in-loop: proper HTTP response cleanup pattern
		defer func() {
			if err := resp.Body.Close(); err != nil {
				slog.Warn("Failed to close response body", "error", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			return nil, false, "", fmt.Errorf("GraphQL request failed with status %d", resp.StatusCode)
		}

		// Parse response
		//nolint:govet // fieldalignment: anonymous GraphQL response struct
		var result struct {
			Data struct {
				Search struct {
					PageInfo struct {
						HasNextPage bool
						EndCursor   string
					}
					Nodes []struct {
						Number    int
						CreatedAt time.Time
						UpdatedAt time.Time
						ClosedAt  *time.Time
						State     string
						Merged    bool
						Author    struct {
							Login    string
							TypeName string `json:"__typename"`
						}
						Repository struct {
							Owner struct{ Login string }
							Name  string
						}
					}
					IssueCount int
				}
			}
			Errors []struct {
				Message string
			}
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, false, "", fmt.Errorf("failed to decode response: %w", err)
		}

		if len(result.Errors) > 0 {
			return nil, false, "", fmt.Errorf("GraphQL error: %s", result.Errors[0].Message)
		}

		totalCount := result.Data.Search.IssueCount
		pageSize := len(result.Data.Search.Nodes)
		hasNextPage := result.Data.Search.PageInfo.HasNextPage

		slog.Info("GraphQL search page fetched",
			"field", field,
			"direction", direction,
			"page", pageNum,
			"page_size", pageSize,
			"total_count", totalCount,
			"has_next_page", hasNextPage)

		// Collect PRs from this page
		for _, node := range result.Data.Search.Nodes {
			allPRs = append(allPRs, PRSummary{
				Owner:      node.Repository.Owner.Login,
				Repo:       node.Repository.Name,
				Number:     node.Number,
				Author:     node.Author.Login,
				AuthorType: node.Author.TypeName,
				CreatedAt:  node.CreatedAt,
				UpdatedAt:  node.UpdatedAt,
				ClosedAt:   node.ClosedAt,
				State:      node.State,
				Merged:     node.Merged,
			})

			// Check if we've hit the maxPRs limit
			if len(allPRs) >= maxPRs {
				hitLimit = true
				slog.Info("Reached max PRs limit (org)",
					"max_prs", maxPRs,
					"field", field,
					"direction", direction)
				return allPRs, hitLimit, queryHash, nil
			}
		}

		// Call progress callback after processing each page
		if progress != nil {
			progress(queryName, pageNum, len(allPRs))
		}

		// Check if we need to fetch more pages
		if !result.Data.Search.PageInfo.HasNextPage {
			break
		}
		cursor = &result.Data.Search.PageInfo.EndCursor
	}

	return allPRs, hitLimit, queryHash, nil
}

// deduplicatePRsByOwnerRepoNumber removes duplicate PRs from a slice using owner+repo+number as key.
func deduplicatePRsByOwnerRepoNumber(prs []PRSummary) []PRSummary {
	type key struct {
		owner  string
		repo   string
		number int
	}
	seen := make(map[key]bool)
	var unique []PRSummary

	for _, pr := range prs {
		k := key{owner: pr.Owner, repo: pr.Repo, number: pr.Number}
		if !seen[k] {
			seen[k] = true
			unique = append(unique, pr)
		}
	}

	slog.Info("Deduplicated org PRs",
		"total", len(prs),
		"unique", len(unique),
		"duplicates", len(prs)-len(unique))

	return unique
}

// CountBotPRs counts how many PRs in the list are authored by bots.
func CountBotPRs(prs []PRSummary) int {
	count := 0
	for _, pr := range prs {
		if IsBot(pr.AuthorType, pr.Author) {
			count++
		}
	}
	return count
}

// SamplePRs uses a time-bucket strategy to evenly sample PRs across the time range.
// This ensures samples are distributed throughout the period rather than clustered.
// Bot-authored PRs are excluded from sampling.
//
// Parameters:
//   - prs: List of PRs to sample from
//   - sampleSize: Desired number of samples
//
// Returns:
//   - Slice of sampled PRs (may be smaller than sampleSize if insufficient PRs)
//
// Strategy:
//   - Includes both human and bot-authored PRs
//   - Divides time range into buckets equal to sampleSize
//   - Selects most recent PR from each bucket
//   - If buckets are empty, fills with nearest unused PRs
func SamplePRs(prs []PRSummary, sampleSize int) []PRSummary {
	if len(prs) == 0 {
		return nil
	}

	// Include all PRs (both human and bot-authored)
	// Bot PRs are now tracked separately in cost calculations

	// If we have fewer PRs than samples, return all
	if len(prs) <= sampleSize {
		return prs
	}

	// Sort PRs by updatedAt (newest first)
	sorted := make([]PRSummary, len(prs))
	copy(sorted, prs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].UpdatedAt.After(sorted[j].UpdatedAt)
	})

	// Calculate time range
	newest := sorted[0].UpdatedAt
	oldest := sorted[len(sorted)-1].UpdatedAt
	totalDuration := newest.Sub(oldest)

	// Calculate bucket size
	bucketDuration := totalDuration / time.Duration(sampleSize)

	slog.Info("Time bucket sampling",
		"newest", newest.Format(time.RFC3339),
		"oldest", oldest.Format(time.RFC3339),
		"bucket_duration", bucketDuration,
		"num_buckets", sampleSize)

	// Create time buckets and assign PRs
	type bucket struct {
		startTime time.Time
		endTime   time.Time
		prs       []PRSummary
	}

	buckets := make([]bucket, sampleSize)
	for i := range sampleSize {
		buckets[i].startTime = newest.Add(-time.Duration(i+1) * bucketDuration)
		buckets[i].endTime = newest.Add(-time.Duration(i) * bucketDuration)
	}

	// Assign PRs to buckets
	for _, pr := range sorted {
		for i := range buckets {
			if (pr.UpdatedAt.After(buckets[i].startTime) || pr.UpdatedAt.Equal(buckets[i].startTime)) &&
				(pr.UpdatedAt.Before(buckets[i].endTime) || pr.UpdatedAt.Equal(buckets[i].endTime)) {
				buckets[i].prs = append(buckets[i].prs, pr)
				break
			}
		}
	}

	// Select one PR from each bucket (most recent in bucket)
	var samples []PRSummary
	used := make(map[int]bool)

	for _, b := range buckets {
		if len(b.prs) > 0 {
			// Pick most recent PR in bucket
			samples = append(samples, b.prs[0])
			used[b.prs[0].Number] = true
		}
	}

	// If some buckets were empty, fill with nearest unused PRs
	if len(samples) < sampleSize {
		for _, pr := range sorted {
			if len(samples) >= sampleSize {
				break
			}
			if !used[pr.Number] {
				samples = append(samples, pr)
				used[pr.Number] = true
			}
		}
	}

	return samples
}

// CountUniqueAuthors counts the number of unique authors in a slice of PRSummary.
// Bot authors are excluded from the count.
func CountUniqueAuthors(prs []PRSummary) int {
	uniqueAuthors := make(map[string]bool)
	for _, pr := range prs {
		if !IsBot(pr.AuthorType, pr.Author) {
			uniqueAuthors[pr.Author] = true
		}
	}
	return len(uniqueAuthors)
}

// CalculateActualTimeWindow validates time coverage for the fetched PRs.
// With the multi-query approach, we fetch PRs to cover the full requested period.
// This function logs coverage statistics but always returns the requested period.
//
// Parameters:
//   - prs: List of PRs fetched (may be from multiple queries)
//   - requestedDays: Number of days originally requested
//
// Returns:
//   - actualDays: Always returns requestedDays (multi-query ensures coverage)
//   - hitLimit: Always returns false (no period adjustment needed)
func CalculateActualTimeWindow(prs []PRSummary, requestedDays int) (actualDays int, hitLimit bool) {
	// If no PRs, return requested days
	if len(prs) == 0 {
		return requestedDays, false
	}

	// Calculate coverage statistics for logging
	requestedSince := time.Now().AddDate(0, 0, -requestedDays)
	oldestTime := prs[len(prs)-1].UpdatedAt
	timeSinceOldestPR := time.Since(oldestTime)
	requestedDuration := time.Since(requestedSince)
	coverageGap := requestedDuration - timeSinceOldestPR

	slog.Info("Time coverage analysis",
		"requested_days", requestedDays,
		"total_prs", len(prs),
		"oldest_pr_age_days", int(timeSinceOldestPR.Hours()/24.0),
		"coverage_gap_days", int(coverageGap.Hours()/24.0),
		"newest_pr", prs[0].UpdatedAt.Format(time.RFC3339),
		"oldest_pr", oldestTime.Format(time.RFC3339))

	// Always return requested period - multi-query approach ensures best possible coverage
	return requestedDays, false
}

// CountOpenPRsInRepo queries GitHub GraphQL API to get the total count of open PRs in a repository
// that were created more than 24 hours ago (PRs open <24 hours don't count as tracking overhead yet).
//
// Parameters:
//   - ctx: Context for the API call
//   - owner: GitHub repository owner
//   - repo: GitHub repository name
//   - token: GitHub authentication token
//
// Returns:
//   - count: Number of open PRs created >24 hours ago
func CountOpenPRsInRepo(ctx context.Context, owner, repo, token string) (int, error) {
	// Only count PRs created more than 24 hours ago
	// Use search API which supports created date filtering
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour).Format("2006-01-02T15:04:05Z")

	query := `query($searchQuery: String!) {
		search(query: $searchQuery, type: ISSUE, first: 0) {
			issueCount
		}
	}`

	// Search query: is:pr is:open repo:owner/repo created:<date
	searchQuery := fmt.Sprintf("is:pr is:open repo:%s/%s created:<%s", owner, repo, twentyFourHoursAgo)

	variables := map[string]any{
		"searchQuery": searchQuery,
	}

	queryJSON, err := json.Marshal(map[string]any{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/graphql", bytes.NewBuffer(queryJSON))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	slog.Info("HTTP request starting",
		"method", "POST",
		"url", "https://api.github.com/graphql",
		"host", "api.github.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best effort close

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Errors []struct {
			Message string
		}
		Data struct {
			Search struct {
				IssueCount int `json:"issueCount"`
			} `json:"search"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Errors) > 0 {
		return 0, fmt.Errorf("GraphQL error: %s", result.Errors[0].Message)
	}

	count := result.Data.Search.IssueCount

	slog.Info("Counted PRs open >24 hours in repository",
		"owner", owner,
		"repo", repo,
		"open_prs", count,
		"filter", "created >24h ago")

	return count, nil
}

// CountOpenPRsInOrg counts all open PRs across an entire GitHub organization with a single GraphQL query.
// This is much more efficient than counting PRs repo-by-repo for organizations with many repositories.
// Only counts PRs created more than 24 hours ago to exclude brand-new PRs.
func CountOpenPRsInOrg(ctx context.Context, org, token string) (int, error) {
	// Only count PRs created more than 24 hours ago
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour).Format("2006-01-02T15:04:05Z")

	query := `query($searchQuery: String!) {
		search(query: $searchQuery, type: ISSUE, first: 0) {
			issueCount
		}
	}`

	// Search query: is:pr is:open org:orgname created:<date
	searchQuery := fmt.Sprintf("is:pr is:open org:%s created:<%s", org, twentyFourHoursAgo)

	variables := map[string]any{
		"searchQuery": searchQuery,
	}

	queryJSON, err := json.Marshal(map[string]any{
		"query":     query,
		"variables": variables,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/graphql", bytes.NewBuffer(queryJSON))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	slog.Info("HTTP request starting",
		"method", "POST",
		"url", "https://api.github.com/graphql",
		"host", "api.github.com")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best effort close

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Errors []struct {
			Message string
		}
		Data struct {
			Search struct {
				IssueCount int `json:"issueCount"`
			} `json:"search"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(result.Errors) > 0 {
		return 0, fmt.Errorf("GraphQL error: %s", result.Errors[0].Message)
	}

	count := result.Data.Search.IssueCount

	slog.Info("Counted PRs open >24 hours in organization",
		"org", org,
		"open_prs", count,
		"filter", "created >24h ago")

	return count, nil
}

// RepoVisibility contains repository name and privacy status.
type RepoVisibility struct {
	Name      string
	IsPrivate bool
}

// FetchOrgRepositoriesWithActivity fetches all repositories in an organization
// that had activity (pushes) in the specified time period, along with their privacy status.
// This is useful for determining which repositories were analyzed and whether they're public or private.
//
// Parameters:
//   - ctx: Context for the API call
//   - org: GitHub organization name
//   - since: Only include repos with activity after this time
//   - token: GitHub authentication token
//
// Returns:
//   - Map of repository name to RepoVisibility struct
func FetchOrgRepositoriesWithActivity(ctx context.Context, org string, since time.Time, token string) (map[string]RepoVisibility, error) {
	query := `
		query($org: String!, $cursor: String) {
			organization(login: $org) {
				repositories(first: 100, after: $cursor, orderBy: {field: PUSHED_AT, direction: DESC}) {
					pageInfo {
						hasNextPage
						endCursor
					}
					nodes {
						name
						isPrivate
						pushedAt
					}
				}
			}
		}
	`

	repos := make(map[string]RepoVisibility)
	var cursor *string

	for {
		variables := map[string]any{
			"org":    org,
			"cursor": cursor,
		}

		payload := map[string]any{
			"query":     query,
			"variables": variables,
		}

		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com/graphql", bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close() //nolint:errcheck // best effort close on error path
			return nil, fmt.Errorf("GraphQL request failed with status %d", resp.StatusCode)
		}

		var result struct {
			Data struct {
				Organization struct {
					Repositories struct {
						PageInfo struct {
							EndCursor   string
							HasNextPage bool
						}
						Nodes []struct {
							PushedAt  time.Time
							Name      string
							IsPrivate bool
						}
					}
				}
			}
			Errors []struct {
				Message string
			}
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			_ = resp.Body.Close() //nolint:errcheck // best effort close on error path
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		_ = resp.Body.Close() //nolint:errcheck // best effort close after successful read

		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("GraphQL error: %s", result.Errors[0].Message)
		}

		// Process repositories and filter by activity date
		foundRecentActivity := false
		for _, node := range result.Data.Organization.Repositories.Nodes {
			if node.PushedAt.Before(since) {
				// Since repos are ordered by PUSHED_AT DESC, once we hit one before 'since',
				// all remaining repos will also be before 'since'
				break
			}
			foundRecentActivity = true
			repos[node.Name] = RepoVisibility{
				Name:      node.Name,
				IsPrivate: node.IsPrivate,
			}
		}

		// If we found no recent activity on this page, we can stop
		if !foundRecentActivity {
			break
		}

		// Continue to next page if there is one
		if !result.Data.Organization.Repositories.PageInfo.HasNextPage {
			break
		}

		cursor = &result.Data.Organization.Repositories.PageInfo.EndCursor
	}

	slog.Info("Fetched organization repositories with recent activity",
		"org", org,
		"since", since.Format(time.RFC3339),
		"repo_count", len(repos))

	return repos, nil
}
