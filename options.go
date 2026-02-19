package chronicle

import (
	"log/slog"
	"time"
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
func WithLogger(l *slog.Logger) Option {
	return func(c *Chronicle) error {
		c.logger = l
		return nil
	}
}

// WithBatchSize sets the maximum batch size before flushing.
func WithBatchSize(n int) Option {
	return func(c *Chronicle) error {
		c.config.BatchSize = n
		return nil
	}
}

// WithFlushInterval sets the maximum time between flushes.
func WithFlushInterval(d time.Duration) Option {
	return func(c *Chronicle) error {
		c.config.FlushInterval = d
		return nil
	}
}

// WithCryptoErasure enables or disables per-subject encryption for GDPR.
func WithCryptoErasure(enabled bool) Option {
	return func(c *Chronicle) error {
		c.config.EnableCryptoErasure = enabled
		return nil
	}
}
