package mongo

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/mongodriver"
	"github.com/xraph/grove/migrate"

	"github.com/xraph/chronicle/id"
)

// openLiveStore connects to the mongo named by CHRONICLE_TEST_MONGO_URI and
// returns a store over a fresh, uniquely named database, dropped again when
// the test ends. It skips when the variable is unset.
//
// It refuses the default port. On the machine these tests were written on,
// that is another project's live database.
func openLiveStore(t *testing.T) (*Store, *mongodriver.MongoDB) {
	t.Helper()

	uri := os.Getenv("CHRONICLE_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("CHRONICLE_TEST_MONGO_URI not set")
	}
	if strings.Contains(uri, ":27017") {
		t.Fatalf("CHRONICLE_TEST_MONGO_URI points at the default port; refusing to write to what may be a live database")
	}

	ctx := context.Background()
	dbName := "chronicle_test_" + strings.ReplaceAll(id.NewAuditID().String(), "_", "")

	drv := mongodriver.New()
	if err := drv.Open(ctx, uri, mongodriver.WithDatabase(dbName)); err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove open: %v", err)
	}
	t.Cleanup(func() {
		_ = drv.Database().Drop(context.Background())
		_ = db.Close()
	})

	return New(db), drv
}

// runMigrationsBefore applies every grove migration that comes before the
// named one, which is what a deployment still on the previous release has.
func runMigrationsBefore(t *testing.T, mdb *mongodriver.MongoDB, name string) (migrate.Executor, *migrate.Migration) {
	t.Helper()

	executor, err := migrate.NewExecutorFor(mdb)
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}

	all := Migrations.Migrations()
	for i, m := range all {
		if m.Name != name {
			continue
		}
		for _, prev := range all[:i] {
			if upErr := prev.Up(context.Background(), executor); upErr != nil {
				t.Fatalf("migration %s: %v", prev.Name, upErr)
			}
		}
		return executor, m
	}
	t.Fatalf("migration %s not found", name)
	return nil, nil
}

// indexNames lists the indexes on a collection by name.
func indexNames(t *testing.T, mdb *mongodriver.MongoDB, col string) map[string]bson.D {
	t.Helper()

	cursor, err := mdb.Collection(col).Indexes().List(context.Background())
	if err != nil {
		t.Fatalf("list indexes on %s: %v", col, err)
	}
	var specs []struct {
		Name string `bson:"name"`
		Key  bson.D `bson:"key"`
	}
	if err := cursor.All(context.Background(), &specs); err != nil {
		t.Fatalf("decode indexes on %s: %v", col, err)
	}
	out := make(map[string]bson.D, len(specs))
	for _, s := range specs {
		out[s.Name] = s.Key
	}
	return out
}

// isDuplicateKey reports whether err is mongo's E11000.
func isDuplicateKey(err error) bool {
	var we mongo.WriteException
	if errors.As(err, &we) {
		return we.HasErrorCode(11000)
	}
	return mongo.IsDuplicateKeyError(err)
}
