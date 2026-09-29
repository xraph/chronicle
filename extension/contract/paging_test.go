package contract

import (
	"context"
	"errors"
	"testing"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

func TestPageBounds(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		limit, offset        int
		wantLimit, wantOff   int
		wantBadRequest       bool
		defaultLimit, maxLim int
	}{
		{name: "zero limit is the default", limit: 0, offset: 0, wantLimit: 50, defaultLimit: 50, maxLim: 200},
		{name: "in range is untouched", limit: 75, offset: 10, wantLimit: 75, wantOff: 10, defaultLimit: 50, maxLim: 200},
		{name: "at the cap is untouched", limit: 200, wantLimit: 200, defaultLimit: 50, maxLim: 200},
		{name: "over the cap is capped", limit: 201, wantLimit: 200, defaultLimit: 50, maxLim: 200},
		{name: "the cap is the caller's own", limit: 5000, wantLimit: 1000, defaultLimit: 50, maxLim: 1000},
		{name: "negative limit", limit: -1, wantBadRequest: true, defaultLimit: 50, maxLim: 200},
		{name: "negative offset", offset: -1, wantBadRequest: true, defaultLimit: 50, maxLim: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit, offset, err := pageBounds(tc.limit, tc.offset, tc.defaultLimit, tc.maxLim)
			if tc.wantBadRequest {
				if !errors.Is(err, fcontract.ErrBadRequest) {
					t.Fatalf("err = %v, want BAD_REQUEST", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("pageBounds: %v", err)
			}
			if limit != tc.wantLimit || offset != tc.wantOff {
				t.Fatalf("got limit %d offset %d, want %d and %d", limit, offset, tc.wantLimit, tc.wantOff)
			}
		})
	}
}

// Every list follows the one rule: a negative limit or offset is BAD_REQUEST.
// Each is run against a store that fails every call, so a request that got
// past the refusal would come back INTERNAL and not BAD_REQUEST.
func TestEveryListRefusesANegativeLimitOrOffset(t *testing.T) {
	deps := Deps{
		Store:            storeReturning(errors.New("the store must not be reached")),
		CheckpointStore:  stubCheckpointStore{},
		CheckpointSigner: stubSigner{},
	}
	viewer := principalWith(map[string]any{"app_id": "app-1"})
	ctx := context.Background()

	lists := map[string]func(limit, offset int) error{
		"streams.list": func(l, o int) error {
			_, err := streamsListHandler(deps)(ctx, StreamListInput{Limit: l, Offset: o}, viewer)
			return err
		},
		"checkpoints.list": func(l, o int) error {
			_, err := checkpointsListHandler(deps)(ctx, CheckpointListInput{Limit: l, Offset: o}, viewer)
			return err
		},
		"events.list": func(l, o int) error {
			_, err := eventsListHandler(deps)(ctx, EventListInput{Limit: l, Offset: o}, viewer)
			return err
		},
		"events.byUser": func(l, o int) error {
			_, err := eventsByUserHandler(deps)(ctx, EventsByUserInput{UserID: "u", Limit: l, Offset: o}, viewer)
			return err
		},
		"erasures.list": func(l, o int) error {
			_, err := erasuresListHandler(deps)(ctx, ErasureListInput{Limit: l, Offset: o}, viewer)
			return err
		},
		"retention.archives": func(l, o int) error {
			_, err := retentionArchivesHandler(deps)(ctx, ArchiveListInput{Limit: l, Offset: o}, viewer)
			return err
		},
		"reports.list": func(l, o int) error {
			_, err := reportsListHandler(deps)(ctx, ReportListInput{Limit: l, Offset: o}, viewer)
			return err
		},
	}
	for name, call := range lists {
		t.Run(name+" negative limit", func(t *testing.T) {
			if err := call(-1, 0); !errors.Is(err, fcontract.ErrBadRequest) {
				t.Fatalf("err = %v, want BAD_REQUEST", err)
			}
		})
		t.Run(name+" negative offset", func(t *testing.T) {
			if err := call(0, -1); !errors.Is(err, fcontract.ErrBadRequest) {
				t.Fatalf("err = %v, want BAD_REQUEST", err)
			}
		})
	}
}
