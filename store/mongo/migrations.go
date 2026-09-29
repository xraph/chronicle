package mongo

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/grove/drivers/mongodriver/mongomigrate"
	"github.com/xraph/grove/migrate"
)

// Migrations is the grove migration group for the Chronicle mongo store.
var Migrations = migrate.NewGroup("chronicle")

func init() {
	Migrations.MustRegister(
		&migrate.Migration{
			Name:    "create_chronicle_streams",
			Version: "20240101000001",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*StreamModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colStreams, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*StreamModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_chronicle_events",
			Version: "20240101000002",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*EventModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colEvents, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "stream_id", Value: 1}, {Key: "sequence", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "timestamp", Value: -1}}},
					{Keys: bson.D{{Key: "category", Value: 1}, {Key: "timestamp", Value: -1}}},
					{Keys: bson.D{{Key: "action", Value: 1}, {Key: "outcome", Value: 1}, {Key: "timestamp", Value: -1}}},
					{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "timestamp", Value: -1}}},
					{Keys: bson.D{{Key: "subject_id", Value: 1}}},
					{Keys: bson.D{{Key: "severity", Value: 1}, {Key: "timestamp", Value: -1}}},
					{Keys: bson.D{{Key: "resource", Value: 1}, {Key: "resource_id", Value: 1}, {Key: "timestamp", Value: -1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*EventModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_chronicle_erasures",
			Version: "20240101000003",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*ErasureModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colErasures, []mongo.IndexModel{
					{Keys: bson.D{{Key: "subject_id", Value: 1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*ErasureModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_chronicle_retention_policies",
			Version: "20240101000004",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*RetentionPolicyModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colPolicies, policyIndexes())
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*RetentionPolicyModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_chronicle_archives",
			Version: "20240101000005",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				return mexec.CreateCollection(ctx, (*ArchiveModel)(nil))
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*ArchiveModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_chronicle_reports",
			Version: "20240101000006",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*ReportModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colReports, []mongo.IndexModel{
					{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "created_at", Value: -1}}},
				})
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*ReportModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "create_chronicle_checkpoints",
			Version: "20240101000007",
			Comment: "Signed checkpoints over a stream's sequence range",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := mexec.CreateCollection(ctx, (*CheckpointModel)(nil)); err != nil {
					return err
				}

				return mexec.CreateIndexes(ctx, colCheckpoints, checkpointIndexes())
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}
				return mexec.DropCollection(ctx, (*CheckpointModel)(nil))
			},
		},
		&migrate.Migration{
			Name:    "scope_chronicle_retention_policy_index",
			Version: "20240101000008",
			Comment: "Make a policy's category unique per (app_id, tenant_id), not globally",
			Up: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				if err := dropLegacyPolicyIndex(ctx, mexec.DB().Collection(colPolicies)); err != nil {
					return err
				}
				return mexec.CreateIndexes(ctx, colPolicies, policyIndexes())
			},
			Down: func(ctx context.Context, exec migrate.Executor) error {
				mexec, ok := exec.(*mongomigrate.Executor)
				if !ok {
					return fmt.Errorf("expected mongomigrate executor, got %T", exec)
				}

				// Fails with E11000 once two scopes share a category, which is
				// the point: going back would have to delete one of them.
				indexes := mexec.DB().Collection(colPolicies).Indexes()
				if _, err := indexes.CreateOne(ctx, mongo.IndexModel{
					Keys:    bson.D{{Key: "category", Value: 1}},
					Options: options.Index().SetUnique(true).SetName(legacyPolicyIndex),
				}); err != nil {
					return fmt.Errorf("restore %s: %w", legacyPolicyIndex, err)
				}
				return indexes.DropOne(ctx, scopedPolicyIndex)
			},
		},
	)
}

// migrationIndexes returns the index definitions for all chronicle collections.
func migrationIndexes() map[string][]mongo.IndexModel {
	return map[string][]mongo.IndexModel{
		colStreams: {
			{
				Keys:    bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
		},
		colEvents: {
			{
				Keys:    bson.D{{Key: "stream_id", Value: 1}, {Key: "sequence", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "timestamp", Value: -1}}},
			{Keys: bson.D{{Key: "category", Value: 1}, {Key: "timestamp", Value: -1}}},
			{Keys: bson.D{{Key: "action", Value: 1}, {Key: "outcome", Value: 1}, {Key: "timestamp", Value: -1}}},
			{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "timestamp", Value: -1}}},
			{
				Keys: bson.D{{Key: "session_id", Value: 1}, {Key: "timestamp", Value: -1}},
				// Only events that have a session. Partial indexes refuse
				// $ne (it is a $not underneath), and "$gt empty string"
				// selects exactly the non-empty strings.
				Options: options.Index().SetPartialFilterExpression(bson.M{"session_id": bson.M{"$gt": ""}}),
			},
			{Keys: bson.D{{Key: "subject_id", Value: 1}}},
			{Keys: bson.D{{Key: "severity", Value: 1}, {Key: "timestamp", Value: -1}}},
			{Keys: bson.D{{Key: "resource", Value: 1}, {Key: "resource_id", Value: 1}, {Key: "timestamp", Value: -1}}},
		},
		colErasures: {
			{Keys: bson.D{{Key: "subject_id", Value: 1}}},
		},
		colPolicies: policyIndexes(),
		colReports: {
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "created_at", Value: -1}}},
		},
		colCheckpoints: checkpointIndexes(),
	}
}

// Index names on chronicle_retention_policies. legacyPolicyIndex is the name
// mongo generated for the category-only index earlier releases created.
const (
	legacyPolicyIndex = "category_1"
	scopedPolicyIndex = "app_id_1_tenant_id_1_category_1"
)

// policyIndexes returns the unique index on a policy's owning scope plus its
// category, which is the uniqueness retention.Store.SavePolicy promises and
// the key its upsert filters on.
//
// Earlier releases indexed category alone. That made the first scope to save
// a policy for a category the only one that ever could: every other app or
// tenant got E11000 for the same category. dropLegacyPolicyIndex removes it.
func policyIndexes() []mongo.IndexModel {
	return []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "app_id", Value: 1},
				{Key: "tenant_id", Value: 1},
				{Key: "category", Value: 1},
			},
			Options: options.Index().SetUnique(true).SetName(scopedPolicyIndex),
		},
	}
}

// dropLegacyPolicyIndex drops the category-only unique index if it exists.
// It has to go before anything else can be fixed: while it is there, the
// scoped index is merely redundant and the collision still happens.
//
// Absent is success, so a fresh database and a re-run both pass through.
func dropLegacyPolicyIndex(ctx context.Context, col *mongo.Collection) error {
	err := col.Indexes().DropOne(ctx, legacyPolicyIndex)
	if err == nil || isIndexOrNamespaceNotFound(err) {
		return nil
	}
	return fmt.Errorf("drop %s on %s: %w", legacyPolicyIndex, colPolicies, err)
}

// isIndexOrNamespaceNotFound reports mongo's IndexNotFound (27) and
// NamespaceNotFound (26), the two ways a drop says there was nothing there.
func isIndexOrNamespaceNotFound(err error) bool {
	var ce mongo.CommandError
	if errors.As(err, &ce) {
		return ce.Code == 27 || ce.Code == 26
	}
	return false
}

// checkpointIndexes returns the unique indexes that make an overlapping
// checkpoint structurally impossible.
//
// Two, not one. (stream_id, to_seq) only decides a race between
// checkpointers that read the same head, and two replicas on a busy stream
// routinely do not: each snapshots the stream list at the top of its own
// tick, so replica A can commit 6-10 while replica B, whose read predated
// it, is still about to commit 6-15. Both succeed, and the stream then
// reports tampered forever, because checkpoints are append-only and the
// overlap cannot be removed. (stream_id, from_seq) is what stops it: both
// racers derive the same from_seq from the same stale latest checkpoint, so
// the loser fails cleanly with checkpoint.ErrExists.
//
// Defined once and used by both the migration and migrationIndexes, so the
// two cannot drift apart.
func checkpointIndexes() []mongo.IndexModel {
	return []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "stream_id", Value: 1}, {Key: "to_seq", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "stream_id", Value: 1}, {Key: "from_seq", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}
}
