package mongo

import (
	"context"
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

				return mexec.CreateIndexes(ctx, colPolicies, []mongo.IndexModel{
					{
						Keys:    bson.D{{Key: "category", Value: 1}},
						Options: options.Index().SetUnique(true),
					},
				})
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
			{Keys: bson.D{{Key: "subject_id", Value: 1}}},
			{Keys: bson.D{{Key: "severity", Value: 1}, {Key: "timestamp", Value: -1}}},
			{Keys: bson.D{{Key: "resource", Value: 1}, {Key: "resource_id", Value: 1}, {Key: "timestamp", Value: -1}}},
		},
		colErasures: {
			{Keys: bson.D{{Key: "subject_id", Value: 1}}},
		},
		colPolicies: {
			{
				Keys:    bson.D{{Key: "category", Value: 1}},
				Options: options.Index().SetUnique(true),
			},
		},
		colReports: {
			{Keys: bson.D{{Key: "app_id", Value: 1}, {Key: "tenant_id", Value: 1}, {Key: "created_at", Value: -1}}},
		},
	}
}
