package chronicle

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
)

// RecordRetention writes a retention record into the chain of every stream the
// given events belong to, and returns the IDs of the events it recorded. Only
// those may be purged.
//
// This is what keeps retention from breaking verification. A policy removes
// events scattered through a stream, one category at a time, and without a
// record a verifier cannot tell those holes from an attacker's. The record
// lists each removed event's sequence and the hashes either side of it, so the
// chain still links end to end across the hole, and it is itself a chained
// event: forging one takes the same key forging any event does, and removing
// one leaves a gap of its own.
//
// The record is written before anything is deleted. A crash between the two
// leaves a record naming events that are still present, which verifies
// cleanly, rather than deletions nothing explains.
//
// Every event is verified in its stored form first, under its stream's pin. An
// event that fails is withheld: it stays in the store, its tampering stays
// visible, and the returned error wraps ErrRetentionWithheld. Purging it would
// erase the evidence and have the record vouch for hashes that no longer match
// their content. Events already gone are skipped silently, since there is
// nothing left to purge.
//
// On error, the returned IDs are still exactly the events whose record was
// durably appended, and purging them is still correct.
func (c *Chronicle) RecordRetention(ctx context.Context, ref audit.RetentionRef, events []*audit.Event) ([]id.ID, error) {
	if c.store == nil {
		return nil, ErrNoStore
	}

	var (
		recorded []id.ID
		withheld []string
	)
	for _, group := range groupByStream(events) {
		entries, ids, held, err := c.retentionEntries(ctx, group)
		if err != nil {
			return recorded, err
		}
		withheld = append(withheld, held...)

		for start := 0; start < len(entries); start += audit.MaxRetentionEntries {
			end := min(start+audit.MaxRetentionEntries, len(entries))
			if _, err := c.appendRetentionRecord(ctx, ref, group[0], entries[start:end]); err != nil {
				return recorded, err
			}
			recorded = append(recorded, ids[start:end]...)
		}
	}

	if len(withheld) > 0 {
		return recorded, fmt.Errorf("%w: %s", ErrRetentionWithheld, strings.Join(withheld, ", "))
	}
	return recorded, nil
}

// retentionEntries verifies one stream's events and returns an entry and an ID
// for each one that may be purged, in sequence order, plus a description of
// each one withheld.
func (c *Chronicle) retentionEntries(
	ctx context.Context, group []*audit.Event,
) (entries []audit.RetentionEntry, ids []id.ID, withheld []string, err error) {
	first := group[0]
	s, err := c.store.GetStreamByScope(ctx, first.AppID, first.TenantID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("chronicle: resolve stream for retention: %w", err)
	}
	if s.ID != first.StreamID {
		// The events claim a stream their own scope does not resolve to.
		// Recording into the scope's stream would vouch for hashes from
		// somewhere else, so none of them are purged.
		for _, e := range group {
			withheld = append(withheld, fmt.Sprintf("%s (stream %s is not its scope's stream)", e.ID, e.StreamID))
		}
		return nil, nil, withheld, nil
	}
	pin := hash.Pin{Scheme: hash.Scheme(s.Scheme), Since: s.SchemeSince}

	for _, e := range group {
		if e.Category == audit.CategoryRetention {
			// Never purge a record: everything it explains would become a
			// gap. The enforcer and every store already exclude these.
			continue
		}

		// Verify what is actually stored. A store that decrypts on read would
		// hand back plaintext, which no longer matches a digest computed over
		// the sealed bytes.
		stored, getErr := getStored(ctx, c.store, e.ID)
		switch {
		case errors.Is(getErr, ErrEventNotFound):
			continue
		case getErr != nil:
			return nil, nil, nil, fmt.Errorf("chronicle: read event %s for retention: %w", e.ID, getErr)
		}
		if stored.StreamID != s.ID {
			withheld = append(withheld, fmt.Sprintf("seq %d (moved to another stream)", stored.Sequence))
			continue
		}

		res, vErr := c.hasher.VerifyWithPin(ctx, stored.PrevHash, stored, pin)
		switch {
		case vErr != nil:
			withheld = append(withheld, fmt.Sprintf("seq %d (cannot be verified: %v)", stored.Sequence, vErr))
			continue
		case res.Downgrade:
			withheld = append(withheld, fmt.Sprintf("seq %d (scheme downgrade)", stored.Sequence))
			continue
		case !res.OK:
			withheld = append(withheld, fmt.Sprintf("seq %d (digest does not match its content)", stored.Sequence))
			continue
		}

		entries = append(entries, audit.RetentionEntry{Seq: stored.Sequence, PrevHash: stored.PrevHash, Hash: stored.Hash})
		ids = append(ids, stored.ID)
	}
	return entries, ids, withheld, nil
}

// appendRetentionRecord links one retention record into like's stream and
// returns the record's sequence.
func (c *Chronicle) appendRetentionRecord(
	ctx context.Context, ref audit.RetentionRef, like *audit.Event, entries []audit.RetentionEntry,
) (uint64, error) {
	rec := audit.NewRetentionRecord(ref, like.StreamID, entries)
	rec.ID = id.NewAuditID()
	rec.Timestamp = time.Now().UTC()
	rec.AppID, rec.TenantID = like.AppID, like.TenantID

	if err := validateEvent(rec); err != nil {
		return 0, err
	}
	// No sealing: a record carries sequences and hashes, never a subject's
	// personal data, and it has to stay readable after any erasure.
	if err := c.appendToChain(ctx, rec); err != nil {
		return 0, fmt.Errorf("chronicle: record retention: %w", err)
	}
	if rec.StreamID != like.StreamID {
		// The scope resolved to a different stream between the check in
		// retentionEntries and the append. The record landed somewhere it
		// explains nothing, so report the events as unrecorded.
		return 0, fmt.Errorf("chronicle: retention record for stream %s landed in stream %s", like.StreamID, rec.StreamID)
	}
	return rec.Sequence, nil
}

// groupByStream splits events by stream, each group in sequence order, groups
// in the order their streams first appear.
func groupByStream(events []*audit.Event) [][]*audit.Event {
	index := make(map[id.ID]int)
	var groups [][]*audit.Event
	for _, e := range events {
		if e == nil {
			continue
		}
		i, ok := index[e.StreamID]
		if !ok {
			i = len(groups)
			index[e.StreamID] = i
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], e)
	}
	for _, g := range groups {
		sort.Slice(g, func(a, b int) bool { return g[a].Sequence < g[b].Sequence })
	}
	return groups
}
