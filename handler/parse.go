package handler

import "github.com/xraph/chronicle/id"

// parseStreamID parses a stream ID string into an id.ID.
func parseStreamID(s string) (id.ID, error) {
	return id.ParseStreamID(s)
}

// parseErasureID parses an erasure ID string into an id.ID.
func parseErasureID(s string) (id.ID, error) {
	return id.ParseErasureID(s)
}

// parsePolicyID parses a policy ID string into an id.ID.
func parsePolicyID(s string) (id.ID, error) {
	return id.ParsePolicyID(s)
}

// parseReportID parses a report ID string into an id.ID.
func parseReportID(s string) (id.ID, error) {
	return id.ParseReportID(s)
}
