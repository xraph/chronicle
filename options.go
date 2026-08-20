package chronicle

import (
	"time"

	log "github.com/xraph/go-utils/log"
)

// Option configures a Chronicle instance.
type Option func(*Chronicle) error

// WithStore sets the backing store for Chronicle.
func WithStore(s Storer) Option {
	return func(c *Chronicle) error {
		c.store = s
		return nil
	}
}

// WithLogger sets the logger for Chronicle.
func WithLogger(l log.Logger) Option {
	return func(c *Chronicle) error {
		c.logger = l
		return nil
	}
}

// WithBatchSize sets the maximum batch size before flushing.
//
// Record writes each event synchronously, so this does not currently change how
// events are persisted; see [Config].BatchSize.
func WithBatchSize(n int) Option {
	return func(c *Chronicle) error {
		c.config.BatchSize = n
		return nil
	}
}

// WithFlushInterval sets the maximum time between flushes.
//
// Record writes each event synchronously, so this does not currently change how
// events are persisted; see [Config].BatchSize.
func WithFlushInterval(d time.Duration) Option {
	return func(c *Chronicle) error {
		c.config.FlushInterval = d
		return nil
	}
}

// WithCryptoErasure enables or disables per-subject encryption for GDPR.
//
// Enabling it requires a sealer from [WithSealer]; without one, New returns
// [ErrCryptoErasureUnavailable] rather than accepting a flag that would promise
// an Article 17 guarantee nothing implements.
//
// With it on, every event carrying a SubjectID has its metadata, reason and IP
// encrypted under a per-subject key before being hashed and stored. Destroying
// that key leaves the payload unrecoverable while the operational record and the
// hash chain stay intact. See crypto.Sealer for exactly which fields are covered.
func WithCryptoErasure(enabled bool) Option {
	return func(c *Chronicle) error {
		c.config.EnableCryptoErasure = enabled
		return nil
	}
}

// WithSealer supplies the encryptor used when crypto-erasure is enabled.
//
// Pass crypto.NewSealer(keyStore). The key store owns the per-subject keys, so
// its durability decides whether sealed events can be read back: losing it is
// indistinguishable from erasing every subject.
func WithSealer(s EventSealer) Option {
	return func(c *Chronicle) error {
		c.sealer = s
		return nil
	}
}
