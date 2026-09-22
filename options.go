package chronicle

import (
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/keys"
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

// WithDigestScheme selects how event digests are computed.
//
// hash.SchemeHMAC requires [WithKeyProvider]; without one, New returns
// [ErrHMACKeyUnavailable] rather than accepting a flag that promises a
// guarantee nothing implements. The two options may be given in either order.
func WithDigestScheme(s hash.Scheme) Option {
	return func(c *Chronicle) error {
		c.config.DigestScheme = s
		return nil
	}
}

// WithKeyProvider supplies the key material for keyed digest schemes.
//
// Rotation lives in the provider: retiring a key stops new digests using it
// while keeping old events verifiable through Provider.ByID.
func WithKeyProvider(p keys.Provider) Option {
	return func(c *Chronicle) error {
		c.keys = p
		return nil
	}
}

// WithCheckpointSigner supplies the signer VerifyChain checks signed
// checkpoints under. Pass the same signer the Checkpointer writes with.
//
// It is a separate option rather than something derived from
// [WithKeyProvider] because the two key sources are genuinely independent.
// A deployment can checkpoint a plain, unkeyed chain, which has no key
// provider at all; another can digest with HMAC from one keyset and sign
// checkpoints from a different one. Deriving the signer from the digest's
// provider got both of those wrong: the first never checked a checkpoint,
// and the second failed every verification with "key not found" because the
// signature had been made under a key the digest's provider had never heard
// of.
//
// Leave it unset and verification behaves exactly as it did before
// checkpoints existed: no checkpoint is fetched, and coverage tops out at
// keyed.
func WithCheckpointSigner(s checkpoint.Signer) Option {
	return func(c *Chronicle) error {
		c.checkpointSigner = s
		return nil
	}
}
