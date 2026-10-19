//go:build e2e

package e2e

import "testing"

// TestSubmissionHeadroomRegression locks in the finding behind rejection
// scenarios: a recording simulation under-counts instructions because it does
// not execute the account's __check_auth. Without extra headroom, scenario E
// can fail from budget exhaustion before reaching UnknownDelegate, making a
// regression look like a successful host rejection.
//
// This is a committed fixture, not a live test: it protects the measured
// runner policy even when a contributor reproduces only the pure test suite.
func TestSubmissionHeadroomRegression(t *testing.T) {
	tests := []struct {
		name          string
		expectFailure bool
		want          uint32
	}{
		{name: "accepted scenarios use enforcing simulation resources", expectFailure: false, want: 1},
		{name: "rejection scenarios retain the measured budget allowance", expectFailure: true, want: rejectionHeadroom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := submissionHeadroom(tt.expectFailure); got != tt.want {
				t.Fatalf("submissionHeadroom(%v) = %d, want %d", tt.expectFailure, got, tt.want)
			}
		})
	}
}

func TestScenarioSummary(t *testing.T) {
	tests := []struct {
		name    string
		ran     int
		skipped int
		want    string
		passed  bool
	}{
		{name: "completed and skipped scenarios", ran: 4, skipped: 1, want: "4 ran, 1 skipped", passed: true},
		{name: "all scenarios skipped", skipped: 4, want: "0 ran, 4 skipped", passed: false},
		{name: "no scenario selection", want: "0 ran, 0 skipped", passed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, passed := scenarioSummary(tt.ran, tt.skipped)
			if got != tt.want || passed != tt.passed {
				t.Fatalf("scenarioSummary(%d, %d) = (%q, %v), want (%q, %v)",
					tt.ran, tt.skipped, got, passed, tt.want, tt.passed)
			}
		})
	}
}
