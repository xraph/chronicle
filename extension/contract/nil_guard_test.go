package contract

import (
	"context"
	"errors"
	"testing"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// nilCheckpointStore answers GetCheckpoint with (nil, nil).
type nilCheckpointStore struct{ stubCheckpointStore }

func (nilCheckpointStore) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, nil
}

// A store that answers a fetch by ID with (nil, nil) instead of a not-found
// error means the same thing, and dereferencing that nil for its scope would
// panic the request. Each detail handler answers NOT_FOUND. The stub store
// returns (nil, nil) from every fetch.
func TestDetailHandlersAnswerNotFoundForAStoreThatReturnsNilAndNoError(t *testing.T) {
	ctx := context.Background()
	viewer := principalWith(map[string]any{"app_id": "app-1"})
	deps := Deps{
		Store:            newStubStore(),
		Chronicle:        &chronicle.Chronicle{},
		CheckpointStore:  nilCheckpointStore{},
		CheckpointSigner: stubSigner{},
	}

	cases := map[string]func() error{
		"events.detail": func() error {
			_, err := eventsDetailHandler(deps)(ctx, GetEventInput{ID: id.NewAuditID().String()}, viewer)
			return err
		},
		"verify.event": func() error {
			_, err := verifyEventHandler(deps)(ctx, VerifyEventInput{EventID: id.NewAuditID().String()}, viewer)
			return err
		},
		"erasures.detail": func() error {
			_, err := erasuresDetailHandler(deps)(ctx, GetErasureInput{ID: id.NewErasureID().String()}, viewer)
			return err
		},
		"checkpoints.detail": func() error {
			_, err := checkpointsDetailHandler(deps)(ctx, GetCheckpointInput{ID: id.NewCheckpointID().String()}, viewer)
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			err := call()
			if !errors.Is(err, fcontract.ErrNotFound) {
				t.Fatalf("err = %v, want NOT_FOUND", err)
			}
		})
	}
}
