package chronicle_test

import (
	"context"
	"testing"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/internal/acceptancetest"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
)

func TestEncryptedMetadataEncodingCannotChangeWithoutDetection(t *testing.T) {
	for _, scheme := range []hash.Scheme{hash.SchemePlainV4, hash.SchemeHMACV5} {
		t.Run(string(scheme), func(t *testing.T) {
			backing := memory.New()
			c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(backing)), chronicle.WithDigestScheme(scheme), chronicle.WithKeyProvider(stubProvider{key: make([]byte, 32), activeID: "hmac-1"}), chronicle.WithSealer(crypto.NewSealer(crypto.NewInMemoryKeyStore())))
			if err != nil {
				t.Fatal(err)
			}
			r := acceptancetest.Request()
			r.Event.SubjectID = "subject"
			receipt, err := c.RecordOnce(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			persisted, err := backing.Get(context.Background(), receipt.EventID)
			if err != nil {
				t.Fatal(err)
			}
			if !crypto.IsSealed(persisted) || !persisted.ExactMetadata {
				t.Fatal("fixture is not an encrypted reliable event")
			}
			persisted.ExactMetadata = false
			if _, err = backing.PurgeEvents(context.Background(), []id.ID{persisted.ID}); err != nil {
				t.Fatal(err)
			}
			if err = backing.Append(context.Background(), persisted); err != nil {
				t.Fatal(err)
			}
			valid, err := c.VerifyEvent(context.Background(), receipt.EventID)
			if err != nil || valid {
				t.Fatalf("encoding change went undetected: valid=%v err=%v", valid, err)
			}
		})
	}
}
