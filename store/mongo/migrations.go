package mongo

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

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
