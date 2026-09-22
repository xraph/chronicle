package chronicle

import (
	"time"

	"github.com/xraph/chronicle/hash"
)

// Config holds the configuration for a Chronicle instance.
type Config struct {
	// BatchSize is the maximum number of events to accumulate before flushing.
	//
	// Not applied by [Chronicle.Record], which writes each event synchronously:
	// linking an event into the hash chain needs the previous event's hash, so
	// appends are inherently sequential. The batcher package implements batching
	// for callers that drive it directly.
	BatchSize int

	// FlushInterval is the maximum time to wait before flushing accumulated events.
	//
	// Not applied by [Chronicle.Record]. See BatchSize.
	FlushInterval time.Duration

	// ShutdownTimeout is the maximum time to wait for graceful shutdown.
	ShutdownTimeout time.Duration

	// EnableCryptoErasure encrypts each subject's personal payload under a
	// per-subject key, so destroying the key makes it irrecoverable.
	//
	// Requires a sealer from [WithSealer]; see [ErrCryptoErasureUnavailable].
	EnableCryptoErasure bool

	// RetentionCheckInterval is how often the retention enforcer runs.
	RetentionCheckInterval time.Duration

	// DigestScheme selects how each event's digest is computed. The default,
	// hash.SchemePlain, is unkeyed and reproducible by anyone who can read the
	// store, so it detects corruption rather than tampering.
	//
	// hash.SchemeHMAC requires a key provider; see [ErrHMACKeyUnavailable].
	DigestScheme hash.Scheme
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		BatchSize:              100,
		FlushInterval:          time.Second,
		ShutdownTimeout:        30 * time.Second,
		EnableCryptoErasure:    false,
		RetentionCheckInterval: 24 * time.Hour,
		DigestScheme:           hash.SchemePlain,
	}
}
