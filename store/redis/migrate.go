package redis

import (
	"context"
	"fmt"
	"sort"
	"strings"

	goredis "github.com/redis/go-redis/v9"
)

// Migrate moves the scope indexes from the bare-joined key format to the v2
// format built by scopeSuffix, once. A marker key records that it has run, so
// every call after the first costs one EXISTS.
//
// The old keys joined app, tenant and category with ":", so app "a:b" with
// tenant "c" and app "a" with tenant "b:c" shared a key. Their names cannot be
// split back into parts, so Migrate does not rename them. It rebuilds each v2
// index from the entities themselves (streams, events, policies), which store
// every scope part as a separate field, and then deletes the old keys.
//
// This runs in Migrate rather than as a read-through fallback in
// GetStreamByScope. The per-scope event index has to be rebuilt anyway, and a
// sorted set cannot be patched up one lookup at a time: until it is rebuilt,
// a scoped Query, Count or retention purge silently misses every event
// recorded before the upgrade. A fallback on the stream key alone would make
// skipping Migrate look safe when it is not. GetStreamByScope instead returns
// ErrScopeKeysNotMigrated on a miss until the marker exists. A deployment that
// skips Migrate gets that error on its first event, and no tenant's chain forks.
//
// Rebuilding is idempotent, so a Migrate interrupted part way is safe to run
// again. Run it with every writer on this version: a process still on the old
// version keeps writing old-format keys, which nothing reads once the marker
// is set. If that happened, delete the key "chronicle:meta:scope-key-format"
// and run Migrate again.
//
// A collision that already happened cannot be undone here. When a second
// scope found the first scope's stream, it appended its events into that
// chain, and every later hash covers them. Moving them out would break
// verification for the rest of the chain. Migrate still finishes and indexes
// every event under the scope it was recorded with, so each tenant's queries
// see only its own events again, and the scope that created the stream keeps
// it. The other scope's next event starts a chain of its own. The shared
// chains are listed in the error, which wraps ErrScopeCollision, and kept in
// the set "chronicle:meta:scope-collisions" for whoever has to investigate.
// Only the Migrate call that does the migration returns that error.
//
// A retention policy lost to a collision cannot be found either: the old
// SavePolicy deleted it when the colliding scope saved its own. Re-save it.
func (s *Store) Migrate(ctx context.Context) error {
	done, err := s.rdb.Exists(ctx, scopeKeyFormatMarker).Result()
	if err != nil {
		return fmt.Errorf("chronicle/redis: migrate: check scope key format: %w", err)
	}
	if done == 1 {
		return nil
	}

	merged, err := s.migrateScopeKeys(ctx)
	if err != nil {
		return fmt.Errorf("chronicle/redis: migrate scope keys: %w", err)
	}

	if len(merged) > 0 {
		members := make([]any, len(merged))
		for i, m := range merged {
			members[i] = m
		}
		if err := s.rdb.SAdd(ctx, scopeCollisionsKey, members...).Err(); err != nil {
			return fmt.Errorf("chronicle/redis: migrate: record merged streams: %w", err)
		}
	}

	if err := s.rdb.Set(ctx, scopeKeyFormatMarker, "2", 0).Err(); err != nil {
		return fmt.Errorf("chronicle/redis: migrate: set scope key format: %w", err)
	}

	if len(merged) > 0 {
		return fmt.Errorf("%w: %s. Each holds events recorded under more than one app+tenant "+
			"scope, from before scope keys were length-prefixed. A chain cannot be split "+
			"without breaking its hashes, so these stay as they are; the IDs are kept in %q",
			ErrScopeCollision, strings.Join(merged, ", "), scopeCollisionsKey)
	}
	return nil
}

// scopePair is an app+tenant scope.
type scopePair struct{ app, tenant string }

// uniqueEntry is one entity behind a unique scope index.
type uniqueEntry struct {
	id     string
	legacy string // the key the old code indexed it under
	v2     string // the key it belongs under now
}

// migrateScopeKeys rebuilds the three v2 scope indexes and deletes the old
// keys. It returns the IDs of streams holding events from another scope.
func (s *Store) migrateScopeKeys(ctx context.Context) ([]string, error) {
	streamScopes, err := s.migrateStreamIndex(ctx)
	if err != nil {
		return nil, err
	}
	merged, err := s.migrateEventIndex(ctx, streamScopes)
	if err != nil {
		return nil, err
	}
	if err := s.migratePolicyIndex(ctx); err != nil {
		return nil, err
	}

	// Old keys go last: until the v2 indexes are complete, a rerun still needs
	// the old stream and policy pointers to pick which entity a scope keeps.
	for _, prefix := range []string{legacyStreamScope, legacyEventScope, legacyPolicyScope} {
		if err := s.unlinkByPrefix(ctx, prefix); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

// migrateStreamIndex points each scope's v2 key at its stream and returns every
// stream's scope, which the event pass checks events against.
func (s *Store) migrateStreamIndex(ctx context.Context) (map[string]scopePair, error) {
	ids, err := s.rdb.ZRange(ctx, zStreamAll, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("list streams: %w", err)
	}

	scopes := make(map[string]scopePair, len(ids))
	entries := make([]uniqueEntry, 0, len(ids))
	for _, streamID := range ids {
		var m streamModel
		if err := s.getEntity(ctx, entityKey(prefixStream, streamID), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("load stream %s: %w", streamID, err)
		}
		scopes[m.ID] = scopePair{m.AppID, m.TenantID}
		entries = append(entries, uniqueEntry{
			id:     m.ID,
			legacy: legacyStreamScope + m.AppID + ":" + m.TenantID,
			v2:     streamScopeKey(m.AppID, m.TenantID),
		})
	}

	if err := s.rebuildUniqueIndex(ctx, entries); err != nil {
		return nil, fmt.Errorf("stream scope index: %w", err)
	}
	return scopes, nil
}

// migrateEventIndex adds every event to the v2 sorted set of the scope it was
// recorded under, and returns the streams holding an event whose scope is not
// the stream's own.
//
// It walks the all-events index with ZSCAN, which returns every member present
// for the whole scan at least once even while other processes add or purge
// events, and does not load the whole index into memory. A member returned
// twice is harmless: ZADD of the same member and score changes nothing.
func (s *Store) migrateEventIndex(ctx context.Context, streamScopes map[string]scopePair) ([]string, error) {
	merged := make(map[string]struct{})

	var cursor uint64
	for {
		// ZSCAN replies member, score, member, score, ...
		page, next, err := s.rdb.ZScan(ctx, zEventAll, cursor, "", 1000).Result()
		if err != nil {
			return nil, fmt.Errorf("scan events: %w", err)
		}

		pipe := s.rdb.Pipeline()
		for i := 0; i+1 < len(page); i += 2 {
			eventID := page[i]
			var m eventModel
			if err := s.getEntity(ctx, entityKey(prefixEvent, eventID), &m); err != nil {
				if isNotFound(err) {
					continue
				}
				return nil, fmt.Errorf("load event %s: %w", eventID, err)
			}
			// Same score storeEvent gives the scope index.
			pipe.ZAdd(ctx, eventScopeKey(m.AppID, m.TenantID),
				goredis.Z{Score: scoreFromTime(m.Timestamp), Member: m.ID})

			if owner, ok := streamScopes[m.StreamID]; ok && owner != (scopePair{m.AppID, m.TenantID}) {
				merged[m.StreamID] = struct{}{}
			}
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return nil, fmt.Errorf("index events: %w", err)
		}

		cursor = next
		if cursor == 0 {
			break
		}
	}

	out := make([]string, 0, len(merged))
	for streamID := range merged {
		out = append(out, streamID)
	}
	sort.Strings(out)
	return out, nil
}

// migratePolicyIndex points each (app, tenant, category) v2 key at its policy.
func (s *Store) migratePolicyIndex(ctx context.Context) error {
	ids, err := s.rdb.ZRange(ctx, zPolicyAll, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}

	entries := make([]uniqueEntry, 0, len(ids))
	for _, policyID := range ids {
		var m policyModel
		if err := s.getEntity(ctx, entityKey(prefixPolicy, policyID), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return fmt.Errorf("load policy %s: %w", policyID, err)
		}
		entries = append(entries, uniqueEntry{
			id:     m.ID,
			legacy: legacyPolicyScope + m.AppID + ":" + m.TenantID + ":" + m.Category,
			v2:     policyScopeKey(m.AppID, m.TenantID, m.Category),
		})
	}

	if err := s.rebuildUniqueIndex(ctx, entries); err != nil {
		return fmt.Errorf("policy scope index: %w", err)
	}
	return nil
}

// rebuildUniqueIndex sets each entry's v2 key, in two passes, oldest entry
// first within each.
//
// The first pass takes the old pointer's word for it: an entry the old key
// still points at was its scope's live one. The second gives the rest a key
// only if nothing has claimed it. That covers an entry whose old pointer a
// colliding scope overwrote (the old CreateStream and SavePolicy both
// overwrote), without letting a stale duplicate displace the live entry.
// Either way a v2 key only ever points at an entity of that key's own scope.
func (s *Store) rebuildUniqueIndex(ctx context.Context, entries []uniqueEntry) error {
	for _, e := range entries {
		current, err := s.rdb.Get(ctx, e.legacy).Result()
		if err != nil && !isRedisNil(err) {
			return fmt.Errorf("read %q: %w", e.legacy, err)
		}
		if current != e.id {
			continue
		}
		if err := s.rdb.Set(ctx, e.v2, e.id, 0).Err(); err != nil {
			return fmt.Errorf("set %q: %w", e.v2, err)
		}
	}
	for _, e := range entries {
		if err := s.rdb.SetNX(ctx, e.v2, e.id, 0).Err(); err != nil {
			return fmt.Errorf("set %q: %w", e.v2, err)
		}
	}
	return nil
}

// unlinkByPrefix removes every key under prefix, using SCAN rather than KEYS so
// the server is never blocked for the length of the keyspace.
func (s *Store) unlinkByPrefix(ctx context.Context, prefix string) error {
	var cursor uint64
	for {
		keys, next, err := s.rdb.Scan(ctx, cursor, prefix+"*", 1000).Result()
		if err != nil {
			return fmt.Errorf("scan %q: %w", prefix+"*", err)
		}
		if len(keys) > 0 {
			if err := s.rdb.Unlink(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("unlink %d keys under %q: %w", len(keys), prefix, err)
			}
		}
		cursor = next
		if cursor == 0 {
			return nil
		}
	}
}
