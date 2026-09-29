package contract

import (
	"context"
	"errors"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
)

// SettingsDetail is what this deployment is configured to do, which for
// Chronicle is mostly a statement about how much its verification is worth.
//
// The digest, checkpoint and backend fields are the reason this intent
// exists. The templ settings page showed batch sizes and intervals, which
// nobody needs, and said nothing about the digest scheme, checkpointing or
// the backend, which is what tells an operator what a "verified" result
// means here.
type SettingsDetail struct {
	BatchSize           int    `json:"batchSize"`
	FlushInterval       string `json:"flushInterval"`
	RetentionInterval   string `json:"retentionInterval"`
	EnableCryptoErasure bool   `json:"enableCryptoErasure"`

	// DigestScheme is what this process writes under now. Existing chains may
	// be pinned to a different scheme below their pin: a chain that had HMAC
	// turned on later is unkeyed below it forever. streams.mine reports that
	// per chain.
	DigestScheme string `json:"digestScheme"`

	// Keyed is whether DigestScheme depends on key material. It is derived
	// from the scheme and not from the presence of a key provider, so it
	// cannot disagree with DigestScheme.
	Keyed bool `json:"keyed"`

	// CheckpointingConfigured is true only when a checkpoint store AND a
	// signer are both present.
	CheckpointingConfigured bool `json:"checkpointingConfigured"`

	BackendName string `json:"backendName"`

	// BackendHoldsCheckpoints is false only when the backend has said it
	// cannot store checkpoints at all (redis does this).
	BackendHoldsCheckpoints bool `json:"backendHoldsCheckpoints"`
}

func settingsRegistrations() []registration {
	return []registration{
		query("settings.detail", settingsDetailHandler),
	}
}

// settingsDetailHandler answers settings.detail.
//
// It reads deployment configuration, not tenant data, so it would work for a
// principal with no app. It refuses one anyway: every intent in this contract
// answers a session with no app scope the same way, and an exception here
// would be the one place a caller could probe the deployment unauthenticated
// by scope.
func settingsDetailHandler(deps Deps) func(context.Context, struct{}, fcontract.Principal) (SettingsDetail, error) {
	return func(ctx context.Context, _ struct{}, p fcontract.Principal) (SettingsDetail, error) {
		if _, err := scopeFromPrincipal(p); err != nil {
			return SettingsDetail{}, err
		}

		// A nil chain is what an unconfigured deployment has, and that is
		// exactly a plain chain, so it is reported as one.
		scheme := hash.SchemePlainV4
		if deps.HashChain != nil {
			scheme = deps.HashChain.Scheme()
		}

		return SettingsDetail{
			BatchSize:               deps.Config.BatchSize,
			FlushInterval:           deps.Config.FlushInterval,
			RetentionInterval:       deps.Config.RetentionInterval,
			EnableCryptoErasure:     deps.Config.EnableCryptoErasure,
			DigestScheme:            string(scheme),
			Keyed:                   hash.Keyed(scheme),
			CheckpointingConfigured: deps.checkpointingConfigured(),
			BackendName:             deps.Config.BackendName,
			BackendHoldsCheckpoints: backendHoldsCheckpoints(ctx, deps),
		}, nil
	}
}

// backendHoldsCheckpoints asks the store whether it knows about checkpoints
// at all, with the same probe extension.go's buildCheckpointer uses so the
// two cannot disagree: LatestCheckpoint against the nil stream ID.
//
// Only checkpoint.ErrUnsupported establishes that the backend cannot hold
// them. ErrNotFound means it can and holds none, and any other error means
// the probe failed without telling us anything about capability, so it is
// logged and the backend is reported as capable rather than failing a
// settings page over a probe.
func backendHoldsCheckpoints(ctx context.Context, deps Deps) bool {
	_, err := deps.Store.LatestCheckpoint(ctx, id.Nil)
	switch {
	case err == nil, errors.Is(err, checkpoint.ErrNotFound):
		return true
	case errors.Is(err, checkpoint.ErrUnsupported):
		return false
	default:
		deps.logger().Error("chronicle/contract: checkpoint capability probe failed",
			log.String("contributor", contributorName),
			log.String("op", "settings.detail"),
			log.Error(err),
		)
		return true
	}
}
