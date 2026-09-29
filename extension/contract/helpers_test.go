package contract

// Shared test helpers for this package. Every test file uses these, so this
// is the one place they are defined. Add spies specific to one group under
// their own names; redefining any of these is a compile error.

import (
	"context"
	"path/filepath"
	"testing"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"
	_ "github.com/xraph/grove/drivers/sqlitedriver/sqlitemigrate" // registers the sqlite migrate executor

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/stream"
)

// principalWith builds a dashboard principal carrying the given claims.
func principalWith(claims map[string]any) fcontract.Principal {
	return fcontract.Principal{
		User:   &dashauth.UserInfo{Subject: "operator-1", Claims: claims},
		Claims: claims,
	}
}

// newTestDispatcher returns a dispatcher to register against, with no-op
// metrics.
func newTestDispatcher(t *testing.T) *dispatcher.Dispatcher {
	t.Helper()
	return dispatcher.New(dispatcher.NoopMetricsEmitter{})
}

// newSQLiteStore opens a migrated, file-backed SQLite store in a fresh temp
// directory, removed when the test ends. It needs no external service, which
// makes it the store for any test that must see a real backend's behavior
// rather than a stub's, such as GetStreamByScope's miss mapping to
// chronicle.ErrStreamNotFound.
func newSQLiteStore(t *testing.T) store.Store {
	t.Helper()
	ctx := context.Background()

	drv := sqlitedriver.New()
	if err := drv.Open(ctx, filepath.Join(t.TempDir(), "chronicle_contract.db")); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove.Open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := sqlite.New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	return s
}

// newStubStore returns a store.Store whose methods all return zero values
// and a nil error. That is enough for registration and for any handler path
// that must be refused before it reaches the store.
func newStubStore() store.Store { return &stubStore{} }

// storeReturning returns a store.Store whose methods all return err, with
// zero values alongside it.
func storeReturning(err error) store.Store { return &stubStore{err: err} }

// stubStore implements store.Store with zero values plus a fixed error.
type stubStore struct{ err error }

var _ store.Store = (*stubStore)(nil)

// audit.Store

func (s *stubStore) Append(context.Context, *audit.Event) error        { return s.err }
func (s *stubStore) AppendBatch(context.Context, []*audit.Event) error { return s.err }
func (s *stubStore) Get(context.Context, id.ID) (*audit.Event, error)  { return nil, s.err }
func (s *stubStore) Query(context.Context, *audit.Query) (*audit.QueryResult, error) {
	return nil, s.err
}
func (s *stubStore) Aggregate(context.Context, *audit.AggregateQuery) (*audit.AggregateResult, error) {
	return nil, s.err
}
func (s *stubStore) ByUser(context.Context, string, audit.TimeRange) (*audit.QueryResult, error) {
	return nil, s.err
}
func (s *stubStore) Count(context.Context, *audit.CountQuery) (int64, error) { return 0, s.err }
func (s *stubStore) LastSequence(context.Context, id.ID) (uint64, error)     { return 0, s.err }
func (s *stubStore) LastHash(context.Context, id.ID) (string, error)         { return "", s.err }

// stream.Store

func (s *stubStore) CreateStream(context.Context, *stream.Stream) error       { return s.err }
func (s *stubStore) GetStream(context.Context, id.ID) (*stream.Stream, error) { return nil, s.err }
func (s *stubStore) GetStreamByScope(context.Context, string, string) (*stream.Stream, error) {
	return nil, s.err
}
func (s *stubStore) ListStreams(context.Context, stream.ListOpts) ([]*stream.Stream, error) {
	return nil, s.err
}
func (s *stubStore) UpdateStreamHead(context.Context, id.ID, string, uint64) error { return s.err }
func (s *stubStore) UpdateStreamScheme(context.Context, id.ID, string, uint64) error {
	return s.err
}

// verify.Store

func (s *stubStore) EventRange(context.Context, id.ID, uint64, uint64) ([]*audit.Event, error) {
	return nil, s.err
}
func (s *stubStore) Gaps(context.Context, id.ID, uint64, uint64) ([]uint64, error) {
	return nil, s.err
}

// erasure.Store

func (s *stubStore) CountBySubject(context.Context, erasure.SubjectQuery) (int64, error) {
	return 0, s.err
}
func (s *stubStore) CountErasures(context.Context, erasure.Scope) (int64, error) { return 0, s.err }
func (s *stubStore) GetErasure(context.Context, id.ID) (*erasure.Erasure, error) { return nil, s.err }
func (s *stubStore) ListErasures(context.Context, erasure.ListOpts) ([]*erasure.Erasure, error) {
	return nil, s.err
}
func (s *stubStore) MarkErased(context.Context, erasure.SubjectQuery, id.ID) (int64, error) {
	return 0, s.err
}
func (s *stubStore) RecordErasure(context.Context, *erasure.Erasure) error { return s.err }

// retention.Store

func (s *stubStore) DeletePolicy(context.Context, id.ID) error { return s.err }
func (s *stubStore) EventsOlderThan(context.Context, retention.PurgeQuery) ([]*audit.Event, error) {
	return nil, s.err
}
func (s *stubStore) GetPolicy(context.Context, id.ID) (*retention.Policy, error) { return nil, s.err }
func (s *stubStore) ListArchives(context.Context, retention.ListOpts) ([]*retention.Archive, error) {
	return nil, s.err
}
func (s *stubStore) ListPolicies(context.Context, retention.ListPoliciesOpts) ([]*retention.Policy, error) {
	return nil, s.err
}
func (s *stubStore) PurgeEvents(context.Context, []id.ID) (int64, error)     { return 0, s.err }
func (s *stubStore) RecordArchive(context.Context, *retention.Archive) error { return s.err }
func (s *stubStore) SavePolicy(context.Context, *retention.Policy) error     { return s.err }

// compliance.ReportStore

func (s *stubStore) DeleteReport(context.Context, id.ID) error { return s.err }
func (s *stubStore) GetReport(context.Context, id.ID) (*compliance.Report, error) {
	return nil, s.err
}
func (s *stubStore) ListReports(context.Context, compliance.ListOpts) ([]*compliance.Report, error) {
	return nil, s.err
}
func (s *stubStore) SaveReport(context.Context, *compliance.Report) error { return s.err }

// checkpoint.Store

func (s *stubStore) AppendCheckpoint(context.Context, *checkpoint.Checkpoint) error { return s.err }
func (s *stubStore) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, s.err
}
func (s *stubStore) CheckpointsInRange(context.Context, id.ID, uint64, uint64) ([]*checkpoint.Checkpoint, error) {
	return nil, s.err
}
func (s *stubStore) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, s.err
}
func (s *stubStore) ListCheckpoints(context.Context, id.ID, checkpoint.ListOpts) ([]*checkpoint.Checkpoint, error) {
	return nil, s.err
}

// lifecycle

func (s *stubStore) Migrate(context.Context) error { return s.err }
func (s *stubStore) Ping(context.Context) error    { return s.err }
func (s *stubStore) Close() error                  { return s.err }

// stubCheckpointStore is a checkpoint.Store that holds no checkpoints:
// LatestCheckpoint and GetCheckpoint answer checkpoint.ErrNotFound, the lists
// answer empty, and AppendCheckpoint accepts and discards.
type stubCheckpointStore struct{}

var _ checkpoint.Store = stubCheckpointStore{}

func (stubCheckpointStore) AppendCheckpoint(context.Context, *checkpoint.Checkpoint) error {
	return nil
}
func (stubCheckpointStore) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrNotFound
}
func (stubCheckpointStore) CheckpointsInRange(context.Context, id.ID, uint64, uint64) ([]*checkpoint.Checkpoint, error) {
	return nil, nil
}
func (stubCheckpointStore) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrNotFound
}
func (stubCheckpointStore) ListCheckpoints(context.Context, id.ID, checkpoint.ListOpts) ([]*checkpoint.Checkpoint, error) {
	return nil, nil
}

// stubSigner is a checkpoint.Signer that signs nothing and verifies
// everything. It exists so a test can say "a signer is configured" without
// key material; never use it where a signature's validity is under test.
type stubSigner struct{}

var _ checkpoint.Signer = stubSigner{}

func (stubSigner) Sign(context.Context, []byte) ([]byte, string, string, error) {
	return []byte("stub-signature"), "stub-key", checkpoint.AlgorithmEd25519, nil
}
func (stubSigner) Verify(context.Context, []byte, []byte, string) error { return nil }
func (stubSigner) PublicKey(context.Context, string) ([]byte, error)    { return nil, nil }
