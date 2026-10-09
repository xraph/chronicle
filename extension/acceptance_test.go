package extension_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xraph/forge"
	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/pgdriver"

	"encoding/json"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/extension"
	"github.com/xraph/chronicle/internal/acceptancetest"
	"github.com/xraph/chronicle/internal/pgtest"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/store/postgres"
	"github.com/xraph/chronicle/store/sealedstore"
	"github.com/xraph/chronicle/verify"
)

type countedKeys struct {
	crypto.KeyStore
	calls   atomic.Int64
	offline atomic.Bool
}

func (k *countedKeys) GetOrCreate(id string) ([]byte, string, error) {
	k.calls.Add(1)
	if k.offline.Load() {
		return nil, "", errors.New("key service unavailable")
	}
	return k.KeyStore.GetOrCreate(id)
}
func (k *countedKeys) Get(id string) ([]byte, error) {
	if k.offline.Load() {
		return nil, errors.New("key service unavailable")
	}
	return k.KeyStore.Get(id)
}

func TestReliableAcceptanceThroughSealedExtension(t *testing.T) {
	testSealedAcceptance(t, memory.New())
}

func TestReliableAcceptanceThroughPostgresExtension(t *testing.T) {
	dsn := os.Getenv("CHRONICLE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CHRONICLE_TEST_POSTGRES_DSN not set")
	}
	driver := pgdriver.New()
	if err := driver.Open(context.Background(), pgtest.Schema(t, dsn)); err != nil {
		t.Fatal(err)
	}
	db, err := grove.Open(driver)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	testSealedAcceptance(t, postgres.New(db))
}

func testSealedAcceptance(t *testing.T, backing store.Store) {
	t.Helper()
	ks := &countedKeys{KeyStore: crypto.NewInMemoryKeyStore()}
	makeExtension := func() *extension.Extension {
		app := forge.New(forge.WithAppName("acceptance"))
		ext := extension.New(extension.WithStore(backing), extension.WithUnauthenticatedAPI(), extension.WithCryptoErasure(true), extension.WithKeyStore(ks), extension.WithDigestScheme("hmac"), extension.WithKeyProvider(stubKeyProvider{key: make([]byte, 32), activeID: "hmac-1"}))
		if err := ext.Register(app); err != nil {
			t.Fatal(err)
		}
		if err := ext.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := ext.Stop(context.Background()); err != nil {
				t.Error(err)
			}
		})
		return ext
	}
	a, b := makeExtension(), makeExtension()
	r := acceptancetest.Request()
	r.Event.SubjectID = "subject"
	r.Event.Reason = "private reason"
	r.Event.UserAgent = "personal agent"
	ctx := context.Background()
	const n = 16
	receipts := make([]*acceptance.Receipt, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			c := a.Chronicle()
			if i%2 == 1 {
				c = b.Chronicle()
			}
			var err error
			receipts[i], err = c.RecordOnce(ctx, r)
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	for _, receipt := range receipts {
		if receipt == nil || !reflect.DeepEqual(receipt, receipts[0]) {
			t.Fatalf("receipt mismatch: %+v", receipts)
		}
	}
	if ks.calls.Load() != 1 {
		t.Fatalf("key creation/resolution called %d times", ks.calls.Load())
	}
	stored, err := backing.Get(ctx, receipts[0].EventID)
	if err != nil || !crypto.IsSealed(stored) || stored.Reason == r.Event.Reason {
		t.Fatalf("not sealed: %+v %v", stored, err)
	}
	shown, err := a.Chronicle().Store().Get(ctx, receipts[0].EventID)
	if err != nil || shown.Reason != r.Event.Reason {
		t.Fatalf("not opened: %+v %v", shown, err)
	}
	if r.Event.EncryptionKeyID != "" || !r.Event.ID.IsNil() {
		t.Fatal("mutated caller")
	}
	if shown.Metadata["fraction"] != json.Number("0.123456789012345678901234567890123456789") {
		t.Fatalf("decryption rounded metadata: %+v", shown.Metadata)
	}
	erased, eraseErr := erasure.NewService(backing, ks).Erase(ctx, &erasure.Input{SubjectID: r.Event.SubjectID, Reason: "test"}, r.Event.AppID, r.Event.TenantID)
	if eraseErr != nil || !erased.KeyDestroyed {
		t.Fatalf("erasure: %+v %v", erased, eraseErr)
	}
	ks.offline.Store(true)
	replay, err := b.Chronicle().RecordOnce(ctx, r)
	if err != nil || !reflect.DeepEqual(replay, receipts[0]) {
		t.Fatalf("erased unavailable-key retry: %+v %v", replay, err)
	}
	if ks.calls.Load() != 1 {
		t.Fatal("retry attempted to recreate erased key")
	}
	ks.offline.Store(false)
	if _, err = ks.Get(stored.EncryptionKeyID); !errors.Is(err, chronicle.ErrErasureKeyNotFound) {
		t.Fatalf("key recreated: %v", err)
	}
	shown, err = a.Chronicle().Store().Get(ctx, receipts[0].EventID)
	if err != nil || shown.Reason != crypto.ErasedMarker {
		t.Fatalf("erased view: %+v %v", shown, err)
	}
	report, err := a.Chronicle().VerifyChain(ctx, &verify.Input{AppID: r.Event.AppID, TenantID: r.Event.TenantID})
	if err != nil || !report.Valid || report.Verified != 1 {
		t.Fatalf("sealed verification: %+v %v", report, err)
	}
}

type legacyOnly struct{ store.Store }

func TestReliableUnsupportedSurvivesWrappers(t *testing.T) {
	legacy := legacyOnly{Store: memory.New()}
	s := sealedstore.New(legacy, crypto.NewSealer(crypto.NewInMemoryKeyStore()))
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := c.RecordOnce(context.Background(), acceptancetest.Request())
	if !errors.Is(err, acceptance.ErrUnsupported) || receipt != nil {
		t.Fatalf("unsupported: %+v %v", receipt, err)
	}
}
