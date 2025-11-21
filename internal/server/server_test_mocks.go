package server

import (
	"fmt"
	"time"

	"github.com/codeGROOVE-dev/prcost/pkg/cost"
)

// Helper functions to create test data.
func newMockPRData(author string, linesAdded int, eventCount int) *cost.PRData {
	events := make([]cost.ParticipantEvent, eventCount)
	baseTime := time.Now().Add(-24 * time.Hour)
	for i := range eventCount {
		events[i] = cost.ParticipantEvent{
			Actor:     fmt.Sprintf("actor%d", i),
			Timestamp: baseTime.Add(time.Duration(i) * time.Hour),
		}
	}
	return &cost.PRData{
		Author:     author,
		LinesAdded: linesAdded,
		CreatedAt:  baseTime,
		Events:     events,
	}
}
