package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/prcost/pkg/cost"
	"github.com/codeGROOVE-dev/prcost/pkg/github"
)

// analyzeRepository performs repository-wide cost analysis by sampling PRs.
// Uses library functions from pkg/github and pkg/cost for fetching, sampling,
// and extrapolation - all functionality is available to external clients.
func analyzeRepository(ctx context.Context, owner, repo string, sampleSize, days int, cfg cost.Config, token, dataSource string) error {
	// Calculate since date
	since := time.Now().AddDate(0, 0, -days)

	// Fetch all PRs modified since the date using library function
	prs, _, err := github.FetchPRsFromRepo(ctx, owner, repo, since, token, nil)
	if err != nil {
		return fmt.Errorf("failed to fetch PRs: %w", err)
	}

	slog.Info("Fetched PRs from repository",
		"total_prs", len(prs),
		"since", since.Format("2006-01-02"))

	if len(prs) == 0 {
		fmt.Printf("\nNo PRs modified in the last %d days\n", days)
		return nil
	}

	// Validate time coverage (logs statistics, always uses requested period)
	actualDays, _ := github.CalculateActualTimeWindow(prs, days)

	// Count bot PRs before sampling
	botPRCount := github.CountBotPRs(prs)
	humanPRCount := len(prs) - botPRCount

	// Sample PRs using time-bucket strategy (includes all PRs)
	samples := github.SamplePRs(prs, sampleSize)

	slog.Info("Sampled PRs for analysis",
		"total_prs", len(prs),
		"human_prs", humanPRCount,
		"bot_prs", botPRCount,
		"sample_size", len(samples),
		"requested_samples", sampleSize)

	if botPRCount > 0 {
		fmt.Printf("\nAnalyzing %d sampled PRs from %d total PRs (%d human, %d bot) modified in the last %d days...\n\n",
			len(samples), len(prs), humanPRCount, botPRCount, actualDays)
	} else {
		fmt.Printf("\nAnalyzing %d sampled PRs from %d total PRs modified in the last %d days...\n\n",
			len(samples), len(prs), actualDays)
	}

	// Convert samples to PRSummaryInfo format
	var summaries []cost.PRSummaryInfo
	for _, pr := range samples {
		summaries = append(summaries, cost.PRSummaryInfo{
			Owner:     pr.Owner,
			Repo:      pr.Repo,
			Number:    pr.Number,
			UpdatedAt: pr.UpdatedAt,
		})
	}

	// Create fetcher
	fetcher := &github.SimpleFetcher{
		Token:      token,
		DataSource: dataSource,
	}

	// Analyze PRs using shared code path
	result, err := cost.AnalyzePRs(ctx, &cost.AnalysisRequest{
		Samples:     summaries,
		Logger:      slog.Default(),
		Fetcher:     fetcher,
		Concurrency: 8, // Process up to 8 PRs concurrently
		Config:      cfg,
	})
	if err != nil {
		return err
	}

	breakdowns := result.Breakdowns

	// Count unique authors across all PRs (not just samples)
	totalAuthors := github.CountUniqueAuthors(prs)

	// Query for actual count of open PRs (not extrapolated from samples)
	openPRCount, err := github.CountOpenPRsInRepo(ctx, owner, repo, token)
	if err != nil {
		slog.Warn("Failed to count open PRs, using 0", "error", err)
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

	// Extrapolate costs from samples using library function (pass nil for visibility since single-repo = public)
	extrapolated := cost.ExtrapolateFromSamples(breakdowns, len(prs), totalAuthors, openPRCount, actualDays, cfg, prSummaryInfos, nil)

	// Display results in itemized format
	printExtrapolatedResults(fmt.Sprintf("%s/%s", owner, repo), actualDays, &extrapolated, cfg)

	return nil
}

// analyzeOrganization performs organization-wide cost analysis by sampling PRs across all repos.
// Uses library functions from pkg/github and pkg/cost for fetching, sampling,
// and extrapolation - all functionality is available to external clients.
func analyzeOrganization(ctx context.Context, org string, sampleSize, days int, cfg cost.Config, token, dataSource string) error {
	slog.Info("Fetching PR list from organization")

	// Calculate since date
	since := time.Now().AddDate(0, 0, -days)

	// Fetch all PRs across the org modified since the date using library function
	prs, _, err := github.FetchPRsFromOrg(ctx, org, since, token, nil)
	if err != nil {
		return fmt.Errorf("failed to fetch PRs: %w", err)
	}

	slog.Info("Fetched PRs from organization",
		"total_prs", len(prs),
		"since", since.Format("2006-01-02"))

	if len(prs) == 0 {
		fmt.Printf("\nNo PRs modified in the last %d days\n", days)
		return nil
	}

	// Validate time coverage (logs statistics, always uses requested period)
	actualDays, _ := github.CalculateActualTimeWindow(prs, days)

	// Count bot PRs before sampling
	botPRCount := github.CountBotPRs(prs)
	humanPRCount := len(prs) - botPRCount

	// Sample PRs using time-bucket strategy (includes all PRs)
	samples := github.SamplePRs(prs, sampleSize)

	slog.Info("Sampled PRs for analysis",
		"total_prs", len(prs),
		"human_prs", humanPRCount,
		"bot_prs", botPRCount,
		"sample_size", len(samples),
		"requested_samples", sampleSize)

	if botPRCount > 0 {
		fmt.Printf("\nAnalyzing %d sampled PRs from %d total PRs (%d human, %d bot) across %s (last %d days)...\n\n",
			len(samples), len(prs), humanPRCount, botPRCount, org, actualDays)
	} else {
		fmt.Printf("\nAnalyzing %d sampled PRs from %d total PRs across %s (last %d days)...\n\n",
			len(samples), len(prs), org, actualDays)
	}

	// Convert samples to PRSummaryInfo format
	var summaries []cost.PRSummaryInfo
	for _, pr := range samples {
		summaries = append(summaries, cost.PRSummaryInfo{
			Owner:     pr.Owner,
			Repo:      pr.Repo,
			Number:    pr.Number,
			UpdatedAt: pr.UpdatedAt,
		})
	}

	// Create fetcher
	fetcher := &github.SimpleFetcher{
		Token:      token,
		DataSource: dataSource,
	}

	// Analyze PRs using shared code path
	result, err := cost.AnalyzePRs(ctx, &cost.AnalysisRequest{
		Samples:     summaries,
		Logger:      slog.Default(),
		Fetcher:     fetcher,
		Concurrency: 8, // Process up to 8 PRs concurrently
		Config:      cfg,
	})
	if err != nil {
		return err
	}

	breakdowns := result.Breakdowns

	// Count unique authors across all PRs (not just samples)
	totalAuthors := github.CountUniqueAuthors(prs)

	// Count open PRs across the entire organization with a single query
	totalOpenPRs, err := github.CountOpenPRsInOrg(ctx, org, token)
	if err != nil {
		slog.Warn("Failed to count open PRs in organization, using 0", "error", err)
		totalOpenPRs = 0
	}
	slog.Info("Counted total open PRs across organization", "org", org, "open_prs", totalOpenPRs)

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

	// Extrapolate costs from samples using library function (CLI doesn't fetch visibility, assume public)
	extrapolated := cost.ExtrapolateFromSamples(breakdowns, len(prs), totalAuthors, totalOpenPRs, actualDays, cfg, prSummaryInfos, nil)

	// Display results in itemized format
	printExtrapolatedResults(fmt.Sprintf("%s (organization)", org), actualDays, &extrapolated, cfg)

	return nil
}

// Ledger formatting functions - all output must use these for consistency.

// formatItemLine formats a cost breakdown line item with 4-space indent.
func formatItemLine(label string, amount float64, timeUnit string, detail string) string {
	if amount == 0 {
		return fmt.Sprintf("    %-30s %15s    %-6s  %s\n", label, "—", timeUnit, detail)
	}
	return fmt.Sprintf("    %-30s $%14s    %-6s  %s\n", label, formatWithCommas(amount), timeUnit, detail)
}

// formatSubtotalLine formats a subtotal line with 4-space indent.
func formatSubtotalLine(amount float64, timeUnit string, detail string) string {
	return fmt.Sprintf("    %-30s $%14s    %-6s  %s\n", "Subtotal", formatWithCommas(amount), timeUnit, detail)
}

// formatSummaryLine formats a summary line (like Preventable Loss Total) with 2-space indent.
func formatSummaryLine(label string, amount float64, timeUnit string, detail string) string {
	return fmt.Sprintf("  %-30s $%14s    %-6s  %s\n", label, formatWithCommas(amount), timeUnit, detail)
}

// formatSectionDivider formats the divider line under subtotals (4-space indent, 32 chars + 14 dashes).
func formatSectionDivider() string {
	return "                                ──────────────\n"
}

// formatTimeUnit intelligently scales time units based on magnitude.
// Once a value exceeds 2x a unit, it scales to the next unit:
// - < 1 hour: show as minutes
// - >= 1 hour and < 48 hours: show as hours
// - >= 48 hours and < 14 days: show as days
// - >= 14 days and < 56 days: show as weeks
// - >= 56 days and < 730 days: show as months
// - >= 730 days: show as years.
func formatTimeUnit(hours float64) string {
	// Show minutes for values less than 1 hour
	if hours < 1.0 {
		minutes := hours * 60.0
		return fmt.Sprintf("%.1fm", minutes)
	}

	if hours < 48 {
		return fmt.Sprintf("%.1fh", hours)
	}

	days := hours / 24.0
	if days < 14 {
		return fmt.Sprintf("%.1fd", days)
	}

	weeks := days / 7.0
	if weeks < 8 {
		return fmt.Sprintf("%.1fw", weeks)
	}

	months := days / 30.0
	if months < 24 {
		return fmt.Sprintf("%.1fmo", months)
	}

	years := days / 365.0
	return fmt.Sprintf("%.1fy", years)
}

// printExtrapolatedResults displays extrapolated cost breakdown in itemized format.
//
//nolint:maintidx,revive // acceptable complexity/length for comprehensive display function
func printExtrapolatedResults(title string, days int, ext *cost.ExtrapolatedBreakdown, cfg cost.Config) {
	fmt.Println()
	fmt.Printf("  %s\n", title)
	avgOpenTime := formatTimeUnit(ext.AvgPRDurationHours)

	// Show human/bot breakdown if there are bot PRs
	if ext.BotPRs > 0 {
		avgHumanOpenTime := formatTimeUnit(ext.AvgHumanPRDurationHours)
		avgBotOpenTime := formatTimeUnit(ext.AvgBotPRDurationHours)
		fmt.Printf("  Period: Last %d days  •  Total PRs: %d (%d human, %d bot)  •  Authors: %d  •  Sampled: %d\n",
			days, ext.TotalPRs, ext.HumanPRs, ext.BotPRs, ext.TotalAuthors, ext.SuccessfulSamples)
		fmt.Printf("  Avg Open Time: %s (human: %s, bot: %s)\n", avgOpenTime, avgHumanOpenTime, avgBotOpenTime)
	} else {
		fmt.Printf("  Period: Last %d days  •  Total PRs: %d  •  Authors: %d  •  Sampled: %d  •  Avg Open Time: %s\n",
			days, ext.TotalPRs, ext.TotalAuthors, ext.SuccessfulSamples, avgOpenTime)
	}
	fmt.Println()

	// Calculate average per PR
	avgAuthorNewCodeCost := ext.AuthorNewCodeCost / float64(ext.TotalPRs)
	avgAuthorAdaptationCost := ext.AuthorAdaptationCost / float64(ext.TotalPRs)
	avgAuthorGitHubCost := ext.AuthorGitHubCost / float64(ext.TotalPRs)
	avgAuthorGitHubContextCost := ext.AuthorGitHubContextCost / float64(ext.TotalPRs)
	avgAuthorTotalCost := ext.AuthorTotalCost / float64(ext.TotalPRs)
	avgAuthorNewCodeHours := ext.AuthorNewCodeHours / float64(ext.TotalPRs)
	avgAuthorAdaptationHours := ext.AuthorAdaptationHours / float64(ext.TotalPRs)
	avgAuthorGitHubHours := ext.AuthorGitHubHours / float64(ext.TotalPRs)
	avgAuthorGitHubContextHours := ext.AuthorGitHubContextHours / float64(ext.TotalPRs)
	avgAuthorTotalHours := ext.AuthorTotalHours / float64(ext.TotalPRs)

	avgParticipantReviewCost := ext.ParticipantReviewCost / float64(ext.TotalPRs)
	avgParticipantGitHubCost := ext.ParticipantGitHubCost / float64(ext.TotalPRs)
	avgParticipantContextCost := ext.ParticipantContextCost / float64(ext.TotalPRs)
	avgParticipantTotalCost := ext.ParticipantTotalCost / float64(ext.TotalPRs)
	avgParticipantReviewHours := ext.ParticipantReviewHours / float64(ext.TotalPRs)
	avgParticipantGitHubHours := ext.ParticipantGitHubHours / float64(ext.TotalPRs)
	avgParticipantContextHours := ext.ParticipantContextHours / float64(ext.TotalPRs)
	avgParticipantTotalHours := ext.ParticipantTotalHours / float64(ext.TotalPRs)

	avgDeliveryDelayCost := ext.DeliveryDelayCost / float64(ext.TotalPRs)
	avgCodeChurnCost := ext.CodeChurnCost / float64(ext.TotalPRs)
	avgAutomatedUpdatesCost := ext.AutomatedUpdatesCost / float64(ext.TotalPRs)
	avgPRTrackingCost := ext.PRTrackingCost / float64(ext.TotalPRs)
	avgDeliveryDelayHours := ext.DeliveryDelayHours / float64(ext.TotalPRs)
	avgCodeChurnHours := ext.CodeChurnHours / float64(ext.TotalPRs)
	avgAutomatedUpdatesHours := ext.AutomatedUpdatesHours / float64(ext.TotalPRs)
	avgPRTrackingHours := ext.PRTrackingHours / float64(ext.TotalPRs)

	avgTotalCost := ext.TotalCost / float64(ext.TotalPRs)
	avgTotalHours := ext.TotalHours / float64(ext.TotalPRs)

	// Show average PR breakdown with improved visual hierarchy
	fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
	headerText := fmt.Sprintf("Average PR (sampled over %d day period)", days)

	// Box has 61 dashes, inner content area is 60 chars (1 space + 60 chars content)
	const innerWidth = 60
	if len(headerText) > innerWidth {
		headerText = headerText[:innerWidth]
	}
	fmt.Printf("  │ %-60s│\n", headerText)
	fmt.Println("  └─────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Authors section
	// Calculate total LOC for header
	avgNewLOC := float64(ext.TotalNewLines) / float64(ext.TotalPRs) / 1000.0
	avgModifiedLOC := float64(ext.TotalModifiedLines) / float64(ext.TotalPRs) / 1000.0
	avgTotalLOC := avgNewLOC + avgModifiedLOC
	totalLOCStr := formatLOC(avgTotalLOC)
	newLOCStr := formatLOC(avgNewLOC)
	modifiedLOCStr := formatLOC(avgModifiedLOC)

	fmt.Printf("  Development Costs (%d PRs, %s)\n", ext.HumanPRs, totalLOCStr)
	fmt.Println("  ────────────────────────────────────────")

	// Calculate average events and sessions
	avgAuthorEvents := float64(ext.AuthorEvents) / float64(ext.TotalPRs)
	avgAuthorSessions := float64(ext.AuthorSessions) / float64(ext.TotalPRs)

	fmt.Print(formatItemLine("New Development", avgAuthorNewCodeCost, formatTimeUnit(avgAuthorNewCodeHours), fmt.Sprintf("(%s)", newLOCStr)))
	fmt.Print(formatItemLine("Adaptation", avgAuthorAdaptationCost, formatTimeUnit(avgAuthorAdaptationHours), fmt.Sprintf("(%s)", modifiedLOCStr)))
	fmt.Print(formatItemLine("GitHub Activity", avgAuthorGitHubCost, formatTimeUnit(avgAuthorGitHubHours), fmt.Sprintf("(%.1f events)", avgAuthorEvents)))
	fmt.Print(formatItemLine("Context Switching", avgAuthorGitHubContextCost, formatTimeUnit(avgAuthorGitHubContextHours), fmt.Sprintf("(%.1f sessions)", avgAuthorSessions)))

	// Show bot PR LOC even though cost is $0
	if ext.BotPRs > 0 {
		avgBotTotalLOC := float64(ext.BotNewLines+ext.BotModifiedLines) / float64(ext.TotalPRs) / 1000.0
		botLOCStr := formatLOC(avgBotTotalLOC)
		fmt.Print(formatItemLine("Automated Updates", 0, formatTimeUnit(0.0), fmt.Sprintf("(%d PRs, %s)", ext.BotPRs, botLOCStr)))
	}
	fmt.Print(formatSectionDivider())
	pct := (avgAuthorTotalCost / avgTotalCost) * 100
	fmt.Print(formatSubtotalLine(avgAuthorTotalCost, formatTimeUnit(avgAuthorTotalHours), fmt.Sprintf("(%.1f%%)", pct)))
	fmt.Println()

	// Participants section (if any participants)
	if ext.ParticipantTotalCost > 0 {
		avgParticipantEvents := float64(ext.ParticipantEvents) / float64(ext.TotalPRs)
		avgParticipantSessions := float64(ext.ParticipantSessions) / float64(ext.TotalPRs)

		avgParticipantReviews := float64(ext.ParticipantReviews) / float64(ext.TotalPRs)

		fmt.Println("  Participant Costs")
		fmt.Println("  ─────────────────")
		if avgParticipantReviewCost > 0 {
			fmt.Print(formatItemLine("Review Activity", avgParticipantReviewCost, formatTimeUnit(avgParticipantReviewHours), fmt.Sprintf("(%.1f reviews)", avgParticipantReviews)))
		}
		if avgParticipantGitHubCost > 0 {
			fmt.Print(formatItemLine("GitHub Activity", avgParticipantGitHubCost, formatTimeUnit(avgParticipantGitHubHours), fmt.Sprintf("(%.1f events)", avgParticipantEvents)))
		}
		fmt.Print(formatItemLine("Context Switching", avgParticipantContextCost, formatTimeUnit(avgParticipantContextHours), fmt.Sprintf("(%.1f sessions)", avgParticipantSessions)))
		fmt.Print(formatSectionDivider())
		participantPct := (avgParticipantTotalCost / avgTotalCost) * 100
		fmt.Print(formatSubtotalLine(avgParticipantTotalCost, formatTimeUnit(avgParticipantTotalHours), fmt.Sprintf("(%.1f%%)", participantPct)))
		fmt.Println()
	}

	// Delay Costs section
	avgHumanOpenTime := formatTimeUnit(ext.AvgHumanPRDurationHours)
	avgBotOpenTime := formatTimeUnit(ext.AvgBotPRDurationHours)
	delayCostsHeader := fmt.Sprintf("  Delay Costs (human PRs avg %s open", avgHumanOpenTime)
	if ext.BotPRs > 0 {
		delayCostsHeader += fmt.Sprintf(", bot PRs avg %s", avgBotOpenTime)
	}
	delayCostsHeader += ")"
	fmt.Println(delayCostsHeader)
	fmt.Println("  " + strings.Repeat("─", len(delayCostsHeader)-2))
	if avgDeliveryDelayCost > 0 {
		fmt.Print(formatItemLine("Workstream blockage", avgDeliveryDelayCost, formatTimeUnit(avgDeliveryDelayHours), fmt.Sprintf("(%d PRs)", ext.HumanPRs)))
	}
	if avgAutomatedUpdatesCost > 0 {
		fmt.Print(formatItemLine("Automated Updates", avgAutomatedUpdatesCost, formatTimeUnit(avgAutomatedUpdatesHours), fmt.Sprintf("(%d PRs)", ext.BotPRs)))
	}
	if avgPRTrackingCost > 0 {
		fmt.Print(formatItemLine("PR Tracking", avgPRTrackingCost, formatTimeUnit(avgPRTrackingHours), fmt.Sprintf("(%d open PRs)", ext.OpenPRs)))
	}
	avgMergeDelayCost := avgDeliveryDelayCost + avgAutomatedUpdatesCost + avgPRTrackingCost
	avgMergeDelayHours := avgDeliveryDelayHours + avgAutomatedUpdatesHours + avgPRTrackingHours
	fmt.Print(formatSectionDivider())
	pct = (avgMergeDelayCost / avgTotalCost) * 100
	fmt.Print(formatSubtotalLine(avgMergeDelayCost, formatTimeUnit(avgMergeDelayHours), fmt.Sprintf("(%.1f%%)", pct)))
	fmt.Println()

	// Preventable Future Costs section
	if avgCodeChurnCost > 0 {
		fmt.Println("  Preventable Future Costs")
		fmt.Println("  ────────────────────────")
		fmt.Print(formatItemLine("Rework due to churn", avgCodeChurnCost, formatTimeUnit(avgCodeChurnHours), fmt.Sprintf("(%d PRs)", ext.CodeChurnPRCount)))
		fmt.Print(formatSectionDivider())
		pct = (avgCodeChurnCost / avgTotalCost) * 100
		fmt.Print(formatSubtotalLine(avgCodeChurnCost, formatTimeUnit(avgCodeChurnHours), fmt.Sprintf("(%.1f%%)", pct)))
		fmt.Println()
	}

	// Future Costs section
	avgFutureReviewCost := ext.FutureReviewCost / float64(ext.TotalPRs)
	avgFutureMergeCost := ext.FutureMergeCost / float64(ext.TotalPRs)
	avgFutureContextCost := ext.FutureContextCost / float64(ext.TotalPRs)
	avgFutureReviewHours := ext.FutureReviewHours / float64(ext.TotalPRs)
	avgFutureMergeHours := ext.FutureMergeHours / float64(ext.TotalPRs)
	avgFutureContextHours := ext.FutureContextHours / float64(ext.TotalPRs)

	hasFutureCosts := ext.FutureReviewCost > 0.01 ||
		ext.FutureMergeCost > 0.01 || ext.FutureContextCost > 0.01

	if hasFutureCosts {
		fmt.Println("  Future Costs")
		fmt.Println("  ────────────")
		if ext.FutureReviewCost > 0.01 {
			fmt.Print(formatItemLine("Review", avgFutureReviewCost, formatTimeUnit(avgFutureReviewHours), fmt.Sprintf("(%d PRs)", ext.FutureReviewPRCount)))
		}
		if ext.FutureMergeCost > 0.01 {
			fmt.Print(formatItemLine("Merge", avgFutureMergeCost, formatTimeUnit(avgFutureMergeHours), fmt.Sprintf("(%d PRs)", ext.FutureMergePRCount)))
		}
		if ext.FutureContextCost > 0.01 {
			avgFutureContextSessions := float64(ext.FutureContextSessions) / float64(ext.TotalPRs)
			fmt.Print(formatItemLine("Context Switching", avgFutureContextCost, formatTimeUnit(avgFutureContextHours), fmt.Sprintf("(%.1f sessions)", avgFutureContextSessions)))
		}
		avgFutureCost := avgFutureReviewCost + avgFutureMergeCost + avgFutureContextCost
		avgFutureHours := avgFutureReviewHours + avgFutureMergeHours + avgFutureContextHours
		fmt.Print(formatSectionDivider())
		pct = (avgFutureCost / avgTotalCost) * 100
		fmt.Print(formatSubtotalLine(avgFutureCost, formatTimeUnit(avgFutureHours), fmt.Sprintf("(%.1f%%)", pct)))
		fmt.Println()
	}

	// Average Preventable Loss Total (before grand total)
	avgPreventableCost := avgCodeChurnCost + avgDeliveryDelayCost + avgAutomatedUpdatesCost + avgPRTrackingCost
	avgPreventableHours := avgCodeChurnHours + avgDeliveryDelayHours + avgAutomatedUpdatesHours + avgPRTrackingHours
	avgPreventablePct := (avgPreventableCost / avgTotalCost) * 100
	fmt.Print(formatSummaryLine("Preventable Loss Total", avgPreventableCost, formatTimeUnit(avgPreventableHours), fmt.Sprintf("(%.1f%%)", avgPreventablePct)))

	// Average total
	fmt.Println("  ════════════════════════════════════════════════════")
	fmt.Printf("  Average Total                $%14s    %s\n",
		formatWithCommas(avgTotalCost), formatTimeUnit(avgTotalHours))
	fmt.Println()
	fmt.Println()

	// Extrapolated total section with improved visual hierarchy
	fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
	headerText = fmt.Sprintf("Estimated costs within a %d day period (extrapolated)", days)

	// Box has 61 dashes, inner content area is 60 chars (1 space + 60 chars content)
	if len(headerText) > 60 {
		headerText = headerText[:60]
	}
	fmt.Printf("  │ %-60s│\n", headerText)
	fmt.Println("  └─────────────────────────────────────────────────────────────┘")
	fmt.Println()

	// Authors section (extrapolated)
	// Calculate kLOC for display
	totalNewLOC := float64(ext.TotalNewLines) / 1000.0
	totalModifiedLOC := float64(ext.TotalModifiedLines) / 1000.0
	totalNewLOCStr := formatLOC(totalNewLOC)
	totalModifiedLOCStr := formatLOC(totalModifiedLOC)

	// Calculate total LOC for header
	totalTotalLOC := totalNewLOC + totalModifiedLOC
	totalTotalLOCStr := formatLOC(totalTotalLOC)

	fmt.Printf("  Development Costs (%d PRs, %s)\n", ext.HumanPRs, totalTotalLOCStr)
	fmt.Println("  ────────────────────────────────────────")

	fmt.Print(formatItemLine("New Development", ext.AuthorNewCodeCost, formatTimeUnit(ext.AuthorNewCodeHours), fmt.Sprintf("(%s)", totalNewLOCStr)))
	fmt.Print(formatItemLine("Adaptation", ext.AuthorAdaptationCost, formatTimeUnit(ext.AuthorAdaptationHours), fmt.Sprintf("(%s)", totalModifiedLOCStr)))
	fmt.Print(formatItemLine("GitHub Activity", ext.AuthorGitHubCost, formatTimeUnit(ext.AuthorGitHubHours), fmt.Sprintf("(%d events)", ext.AuthorEvents)))
	fmt.Print(formatItemLine("Context Switching", ext.AuthorGitHubContextCost, formatTimeUnit(ext.AuthorGitHubContextHours), fmt.Sprintf("(%d sessions)", ext.AuthorSessions)))

	// Show bot PR LOC even though cost is $0
	if ext.BotPRs > 0 {
		totalBotLOC := float64(ext.BotNewLines+ext.BotModifiedLines) / 1000.0
		botTotalLOCStr := formatLOC(totalBotLOC)
		fmt.Print(formatItemLine("Automated Updates", 0, formatTimeUnit(0.0), fmt.Sprintf("(%d PRs, %s)", ext.BotPRs, botTotalLOCStr)))
	}
	fmt.Print(formatSectionDivider())
	pct = (ext.AuthorTotalCost / ext.TotalCost) * 100
	fmt.Print(formatSubtotalLine(ext.AuthorTotalCost, formatTimeUnit(ext.AuthorTotalHours), fmt.Sprintf("(%.1f%%)", pct)))
	fmt.Println()

	// Participants section (extrapolated, if any participants)
	if ext.ParticipantTotalCost > 0 {
		fmt.Println("  Participant Costs")
		fmt.Println("  ─────────────────")
		if ext.ParticipantReviewCost > 0 {
			fmt.Print(formatItemLine("Review Activity", ext.ParticipantReviewCost, formatTimeUnit(ext.ParticipantReviewHours), fmt.Sprintf("(%d reviews)", ext.ParticipantReviews)))
		}
		if ext.ParticipantGitHubCost > 0 {
			fmt.Print(formatItemLine("GitHub Activity", ext.ParticipantGitHubCost, formatTimeUnit(ext.ParticipantGitHubHours), fmt.Sprintf("(%d events)", ext.ParticipantEvents)))
		}
		fmt.Print(formatItemLine("Context Switching", ext.ParticipantContextCost, formatTimeUnit(ext.ParticipantContextHours), fmt.Sprintf("(%d sessions)", ext.ParticipantSessions)))
		fmt.Print(formatSectionDivider())
		pct = (ext.ParticipantTotalCost / ext.TotalCost) * 100
		fmt.Print(formatSubtotalLine(ext.ParticipantTotalCost, formatTimeUnit(ext.ParticipantTotalHours), fmt.Sprintf("(%.1f%%)", pct)))
		fmt.Println()
	}

	// Delay Costs section (extrapolated)
	extAvgHumanOpenTime := formatTimeUnit(ext.AvgHumanPRDurationHours)
	extAvgBotOpenTime := formatTimeUnit(ext.AvgBotPRDurationHours)
	extDelayCostsHeader := fmt.Sprintf("  Delay Costs (human PRs avg %s open", extAvgHumanOpenTime)
	if ext.BotPRs > 0 {
		extDelayCostsHeader += fmt.Sprintf(", bot PRs avg %s", extAvgBotOpenTime)
	}
	extDelayCostsHeader += ")"
	fmt.Println(extDelayCostsHeader)
	fmt.Println("  " + strings.Repeat("─", len(extDelayCostsHeader)-2))

	if ext.DeliveryDelayCost > 0 {
		fmt.Print(formatItemLine("Workstream blockage", ext.DeliveryDelayCost, formatTimeUnit(ext.DeliveryDelayHours), fmt.Sprintf("(%d PRs)", ext.HumanPRs)))
	}
	if ext.AutomatedUpdatesCost > 0 {
		fmt.Print(formatItemLine("Automated Updates", ext.AutomatedUpdatesCost, formatTimeUnit(ext.AutomatedUpdatesHours), fmt.Sprintf("(%d PRs)", ext.BotPRs)))
	}
	if ext.PRTrackingCost > 0 {
		fmt.Print(formatItemLine("PR Tracking", ext.PRTrackingCost, formatTimeUnit(ext.PRTrackingHours), fmt.Sprintf("(%d open PRs)", ext.OpenPRs)))
	}
	extMergeDelayCost := ext.DeliveryDelayCost + ext.AutomatedUpdatesCost + ext.PRTrackingCost
	extMergeDelayHours := ext.DeliveryDelayHours + ext.AutomatedUpdatesHours + ext.PRTrackingHours
	fmt.Print(formatSectionDivider())
	pct = (extMergeDelayCost / ext.TotalCost) * 100
	fmt.Print(formatSubtotalLine(extMergeDelayCost, formatTimeUnit(extMergeDelayHours), fmt.Sprintf("(%.1f%%)", pct)))
	fmt.Println()

	// Preventable Future Costs section (extrapolated)
	if ext.CodeChurnCost > 0 {
		fmt.Println("  Preventable Future Costs")
		fmt.Println("  ────────────────────────")
		totalKLOC := float64(ext.TotalNewLines+ext.TotalModifiedLines) / 1000.0
		churnLOCStr := formatLOC(totalKLOC)
		fmt.Print(formatItemLine("Rework due to churn", ext.CodeChurnCost, formatTimeUnit(ext.CodeChurnHours), fmt.Sprintf("(%d PRs, ~%s)", ext.CodeChurnPRCount, churnLOCStr)))
		fmt.Print(formatSectionDivider())
		pct = (ext.CodeChurnCost / ext.TotalCost) * 100
		fmt.Print(formatSubtotalLine(ext.CodeChurnCost, formatTimeUnit(ext.CodeChurnHours), fmt.Sprintf("(%.1f%%)", pct)))
		fmt.Println()
	}

	// Future Costs section (extrapolated)
	extHasFutureCosts := ext.FutureReviewCost > 0.01 ||
		ext.FutureMergeCost > 0.01 || ext.FutureContextCost > 0.01

	if extHasFutureCosts {
		fmt.Println("  Future Costs")
		fmt.Println("  ────────────")
		if ext.FutureReviewCost > 0.01 {
			fmt.Print(formatItemLine("Review", ext.FutureReviewCost, formatTimeUnit(ext.FutureReviewHours), fmt.Sprintf("(%d PRs)", ext.FutureReviewPRCount)))
		}
		if ext.FutureMergeCost > 0.01 {
			fmt.Print(formatItemLine("Merge", ext.FutureMergeCost, formatTimeUnit(ext.FutureMergeHours), fmt.Sprintf("(%d PRs)", ext.FutureMergePRCount)))
		}
		if ext.FutureContextCost > 0.01 {
			fmt.Print(formatItemLine("Context Switching", ext.FutureContextCost, formatTimeUnit(ext.FutureContextHours), fmt.Sprintf("(%d sessions)", ext.FutureContextSessions)))
		}
		extFutureCost := ext.FutureReviewCost + ext.FutureMergeCost + ext.FutureContextCost
		extFutureHours := ext.FutureReviewHours + ext.FutureMergeHours + ext.FutureContextHours
		fmt.Print(formatSectionDivider())
		pct = (extFutureCost / ext.TotalCost) * 100
		fmt.Print(formatSubtotalLine(extFutureCost, formatTimeUnit(extFutureHours), fmt.Sprintf("(%.1f%%)", pct)))
		fmt.Println()
	}

	// Preventable Loss Total (before grand total)
	preventableCost := ext.CodeChurnCost + ext.DeliveryDelayCost + ext.AutomatedUpdatesCost + ext.PRTrackingCost
	preventableHours := ext.CodeChurnHours + ext.DeliveryDelayHours + ext.AutomatedUpdatesHours + ext.PRTrackingHours
	preventablePct := (preventableCost / ext.TotalCost) * 100
	fmt.Print(formatSummaryLine("Preventable Loss Total", preventableCost, formatTimeUnit(preventableHours), fmt.Sprintf("(%.1f%%)", preventablePct)))

	// Extrapolated grand total
	fmt.Println("  ════════════════════════════════════════════════════")
	fmt.Printf("  Total                        $%14s    %s\n",
		formatWithCommas(ext.TotalCost), formatTimeUnit(ext.TotalHours))
	fmt.Println()

	// Print extrapolated efficiency score + annual waste
	printExtrapolatedEfficiency(ext, days, cfg)
}

// printExtrapolatedEfficiency prints the workflow efficiency + annual waste section for extrapolated totals.
func printExtrapolatedEfficiency(ext *cost.ExtrapolatedBreakdown, days int, cfg cost.Config) {
	// Calculate preventable waste: Code Churn + All Delay Costs + Automated Updates + PR Tracking
	preventableHours := ext.CodeChurnHours + ext.DeliveryDelayHours + ext.AutomatedUpdatesHours + ext.PRTrackingHours
	preventableCost := ext.CodeChurnCost + ext.DeliveryDelayCost + ext.AutomatedUpdatesCost + ext.PRTrackingCost

	// Calculate efficiency (for display purposes - grade comes from backend)
	var efficiencyPct float64
	if ext.TotalHours > 0 {
		efficiencyPct = 100.0 * (ext.TotalHours - preventableHours) / ext.TotalHours
	} else {
		efficiencyPct = 100.0
	}

	// Use grades computed by backend (single source of truth)
	grade := ext.EfficiencyGrade
	message := ext.EfficiencyMessage
	velocityGrade := ext.MergeVelocityGrade
	velocityMessage := ext.MergeVelocityMessage

	// Calculate annual waste
	annualMultiplier := 365.0 / float64(days)
	annualWasteCost := preventableCost * annualMultiplier

	fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
	headerText := fmt.Sprintf("DEVELOPMENT EFFICIENCY: %s (%.1f%%) - %s", grade, efficiencyPct, message)

	// Box has 61 dashes, inner content area is 60 chars (1 space + 60 chars content)
	const innerWidth = 60
	if len(headerText) > innerWidth {
		headerText = headerText[:innerWidth]
	}
	fmt.Printf("  │ %-60s│\n", headerText)
	fmt.Println("  └─────────────────────────────────────────────────────────────┘")

	fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
	velocityHeader := fmt.Sprintf("MERGE VELOCITY: %s (%s) - %s", velocityGrade, formatTimeUnit(ext.AvgPRDurationHours), velocityMessage)
	if len(velocityHeader) > innerWidth {
		velocityHeader = velocityHeader[:innerWidth]
	}
	fmt.Printf("  │ %-60s│\n", velocityHeader)
	fmt.Println("  └─────────────────────────────────────────────────────────────┘")

	// Merge Success Rate box (if data available)
	if ext.MergedPRs+ext.UnmergedPRs > 0 {
		// Use grade computed by backend (single source of truth)
		fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
		mergeRateHeader := fmt.Sprintf("MERGE SUCCESS RATE: %s (%.1f%%) - %s", ext.MergeRateGrade, ext.MergeRate, ext.MergeRateGradeMessage)
		if len(mergeRateHeader) > innerWidth {
			mergeRateHeader = mergeRateHeader[:innerWidth]
		}
		fmt.Printf("  │ %-60s│\n", mergeRateHeader)
		fmt.Println("  └─────────────────────────────────────────────────────────────┘")
	}

	// Weekly waste per PR author
	if ext.WasteHoursPerAuthorPerWeek > 0 && ext.TotalAuthors > 0 {
		fmt.Printf("  Weekly waste per PR author:     $%14s    %s  (%d authors)\n",
			formatWithCommas(ext.WasteCostPerAuthorPerWeek),
			formatTimeUnit(ext.WasteHoursPerAuthorPerWeek),
			ext.TotalAuthors)
	}

	// Calculate headcount from annual waste
	annualCostPerHead := cfg.AnnualSalary * cfg.BenefitsMultiplier
	headcount := annualWasteCost / annualCostPerHead
	fmt.Printf("  If Sustained for 1 Year:        $%14s    %.1f headcount\n",
		formatWithCommas(annualWasteCost), headcount)
	fmt.Println()

	// Print merge time modeling callout if average PR duration exceeds model merge time
	if ext.AvgPRDurationHours > cfg.TargetMergeTimeHours {
		printExtrapolatedMergeTimeModelingCallout(ext, days, cfg)
	}
}

// printExtrapolatedMergeTimeModelingCallout prints a callout showing potential savings from reduced merge time.
func printExtrapolatedMergeTimeModelingCallout(ext *cost.ExtrapolatedBreakdown, days int, cfg cost.Config) {
	targetHours := cfg.TargetMergeTimeHours

	// Calculate hourly rate
	hourlyRate := (cfg.AnnualSalary * cfg.BenefitsMultiplier) / cfg.HoursPerYear

	// Recalculate average preventable costs with target merge time
	// This mirrors the logic from ExtrapolateFromSamples but with target merge time

	// Average delivery delay per PR at target merge time
	remodelDeliveryDelayPerPR := hourlyRate * cfg.DeliveryDelayFactor * targetHours

	// Code churn: minimal for short PRs (< 1 day = ~0%)
	remodelCodeChurnPerPR := 0.0

	// Automated updates: only for PRs open > 1 day
	remodelAutomatedUpdatesPerPR := 0.0

	// PR tracking: scales with open time
	remodelPRTrackingPerPR := 0.0
	if targetHours >= 1.0 { // Minimal tracking for PRs open >= 1 hour
		daysOpen := targetHours / 24.0
		remodelPRTrackingHours := (cfg.PRTrackingMinutesPerDay / 60.0) * daysOpen
		remodelPRTrackingPerPR = remodelPRTrackingHours * hourlyRate
	}

	// Calculate total remodeled preventable cost for the period
	totalPRs := float64(ext.TotalPRs)
	remodelPreventablePerPeriod := (remodelDeliveryDelayPerPR + remodelCodeChurnPerPR +
		remodelAutomatedUpdatesPerPR + remodelPRTrackingPerPR) * totalPRs

	// Current preventable cost for the period
	currentPreventablePerPeriod := ext.CodeChurnCost + ext.DeliveryDelayCost +
		ext.AutomatedUpdatesCost + ext.PRTrackingCost

	// Calculate savings for the period
	savingsPerPeriod := currentPreventablePerPeriod - remodelPreventablePerPeriod

	// Calculate efficiency improvement
	// Current efficiency: (total hours - preventable hours) / total hours
	// Modeled efficiency: (total hours - remodeled preventable hours) / total hours
	currentPreventableHours := ext.CodeChurnHours + ext.DeliveryDelayHours +
		ext.AutomatedUpdatesHours + ext.PRTrackingHours
	remodelPreventableHours := remodelPreventablePerPeriod / hourlyRate

	var currentEfficiency, modeledEfficiency, efficiencyDelta float64
	if ext.TotalHours > 0 {
		currentEfficiency = 100.0 * (ext.TotalHours - currentPreventableHours) / ext.TotalHours
		modeledEfficiency = 100.0 * (ext.TotalHours - remodelPreventableHours) / ext.TotalHours
		efficiencyDelta = modeledEfficiency - currentEfficiency
	}

	if savingsPerPeriod > 0 {
		// Annualize the savings
		weeksInPeriod := float64(days) / 7.0
		annualSavings := savingsPerPeriod * (52.0 / weeksInPeriod)

		fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
		fmt.Printf("  │ %-60s│\n", "MERGE TIME MODELING")
		fmt.Println("  └─────────────────────────────────────────────────────────────┘")
		if efficiencyDelta > 0 {
			fmt.Printf("  Reduce merge time to %s to boost team throughput by %.1f%%\n", formatTimeUnit(targetHours), efficiencyDelta)
			fmt.Printf("  and save ~$%s/yr in engineering overhead.\n", formatWithCommas(annualSavings))
		} else {
			fmt.Printf("  If you lowered your average merge time to %s, you would save\n", formatTimeUnit(targetHours))
			fmt.Printf("  ~$%s/yr in engineering overhead.\n", formatWithCommas(annualSavings))
		}
		fmt.Println()
	}
}
