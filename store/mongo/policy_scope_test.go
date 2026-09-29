package mongo

import (
	"context"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
)

// savePolicies saves one "auth" policy for each of three scopes that share the
// category: two apps, and a second tenant inside the first app. Under the old
// index the second save failed with E11000.
func savePolicies(t *testing.T, s *Store) {
	t.Helper()

	for _, sc := range []struct{ app, tenant string }{
		{"app-a", "t1"},
		{"app-b", "t1"},
		{"app-a", "t2"},
	} {
		p := &retention.Policy{
			ID: id.NewPolicyID(), Category: "auth", Duration: 30 * 24 * time.Hour,
			AppID: sc.app, TenantID: sc.tenant,
		}
		p.CreatedAt, p.UpdatedAt = time.Now().UTC(), time.Now().UTC()
		if err := s.SavePolicy(context.Background(), p); err != nil {
			t.Fatalf("SavePolicy(%s/%s/auth): %v", sc.app, sc.tenant, err)
		}
	}

	for _, app := range []string{"app-a", "app-b"} {
		got, err := s.ListPolicies(context.Background(), retention.ListPoliciesOpts{Scope: retention.Scope{AppID: app}})
		if err != nil {
			t.Fatalf("ListPolicies(%s): %v", app, err)
		}
		want := 1
		if app == "app-a" {
			want = 2
		}
		if len(got) != want {
			t.Errorf("ListPolicies(%s) = %d policies, want %d", app, len(got), want)
		}
	}
}

// assertScopedPolicyIndex checks the policies collection carries the scoped
// unique index and not the category-only one.
func assertScopedPolicyIndex(t *testing.T, s *Store) {
	t.Helper()

	idx := indexNames(t, s.mdb, colPolicies)
	if _, ok := idx[legacyPolicyIndex]; ok {
		t.Errorf("legacy index %s is still present: %v", legacyPolicyIndex, idx)
	}
	want := bson.D{{Key: "app_id", Value: int32(1)}, {Key: "tenant_id", Value: int32(1)}, {Key: "category", Value: int32(1)}}
	found := false
	for _, key := range idx {
		if len(key) == len(want) {
			match := true
			for i := range key {
				if key[i].Key != want[i].Key {
					match = false
				}
			}
			found = found || match
		}
	}
	if !found {
		t.Errorf("no (app_id, tenant_id, category) index on %s: %v", colPolicies, idx)
	}

	// Still unique within one scope.
	dup := bson.M{"_id": id.NewPolicyID().String(), "app_id": "app-a", "tenant_id": "t1", "category": "auth"}
	if _, err := s.mdb.Collection(colPolicies).InsertOne(context.Background(), dup); !isDuplicateKey(err) {
		t.Errorf("second auth policy in the same scope: err = %v, want E11000", err)
	}
}

// TestPolicyCategoryIsUniquePerScope is the regression test for the policies
// index being unique on category alone, on a fresh database through
// Store.Migrate.
func TestPolicyCategoryIsUniquePerScope(t *testing.T) {
	s, _ := openLiveStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	savePolicies(t, s)
	assertScopedPolicyIndex(t, s)
}

// TestMigrateDropsLegacyPolicyIndex covers a database that already has the
// category-only index, reached by either migration path.
func TestMigrateDropsLegacyPolicyIndex(t *testing.T) {
	legacy := mongo.IndexModel{
		Keys:    bson.D{{Key: "category", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	t.Run("Store.Migrate", func(t *testing.T) {
		s, mdb := openLiveStore(t)
		if _, err := mdb.Collection(colPolicies).Indexes().CreateOne(context.Background(), legacy); err != nil {
			t.Fatalf("seed legacy index: %v", err)
		}
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		// Twice: an upgrade that was interrupted and re-run must not fail
		// because the index it drops is already gone.
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate again: %v", err)
		}
		savePolicies(t, s)
		assertScopedPolicyIndex(t, s)
	})

	t.Run("grove migrations", func(t *testing.T) {
		s, mdb := openLiveStore(t)
		executor, m := runMigrationsBefore(t, mdb, "scope_chronicle_retention_policy_index")

		// A deployment on the previous release built the category-only index
		// in create_chronicle_retention_policies. Put it back explicitly, so
		// the test does not depend on what that migration builds today.
		if _, err := mdb.Collection(colPolicies).Indexes().CreateOne(context.Background(), legacy); err != nil {
			t.Fatalf("seed legacy index: %v", err)
		}
		if err := m.Up(context.Background(), executor); err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
		if err := m.Up(context.Background(), executor); err != nil {
			t.Fatalf("%s re-run: %v", m.Name, err)
		}
		savePolicies(t, s)
		assertScopedPolicyIndex(t, s)
	})
}
