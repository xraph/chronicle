// Package stream defines the hash chain stream entity and store interface.
package stream

import (
	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
)

// Stream represents a hash chain stream, scoped to an app+tenant combination.
// Each stream maintains its own independent chain.
type Stream struct {
	chronicle.Entity
	ID       id.ID  `json:"id"`
	AppID    string `json:"app_id"`
	TenantID string `json:"tenant_id"`
	HeadHash string `json:"head_hash"`
	HeadSeq  uint64 `json:"head_seq"`

	// Scheme is the digest scheme this stream is pinned to, and SchemeSince the
	// first sequence it applies from. Events below SchemeSince predate the pin.
	Scheme      string `json:"scheme"`
	SchemeSince uint64 `json:"scheme_since"`
}

// ListOpts defines pagination options for listing streams.
type ListOpts struct {
	Limit  int
	Offset int
}
