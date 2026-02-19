package extension

import (
	"log/slog"
	"time"

	"github.com/xraph/chronicle/sink"
	"github.com/xraph/chronicle/store"
)

// options holds the configuration for the Chronicle extension.
type options struct {
	store               store.Store
	batchSize           int
	flushInterval       time.Duration
	enableCryptoErasure bool
	retentionInterval   time.Duration
	archiveSink         sink.Sink
	logger              *slog.Logger
	disableRoutes       bool
	disableMigrate      bool
}

func defaultOptions() options {
	return options{
		batchSize:         100,
		flushInterval:     time.Second,
		retentionInterval: 24 * time.Hour,
	}
}

// Option configures the Chronicle extension.
type Option func(*options)

// WithStore provides the composite store for the extension.
func WithStore(s store.Store) Option {
	return func(o *options) { o.store = s }
}

// WithBatchSize sets the event batch size.
func WithBatchSize(n int) Option {
	return func(o *options) { o.batchSize = n }
}

// WithFlushInterval sets the batch flush interval.
func WithFlushInterval(d time.Duration) Option {
	return func(o *options) { o.flushInterval = d }
}

// WithCryptoErasure enables GDPR crypto-erasure support.
func WithCryptoErasure(enabled bool) Option {
	return func(o *options) { o.enableCryptoErasure = enabled }
}

// WithRetentionInterval sets how often retention policies are enforced.
// Set to 0 to disable automatic retention.
func WithRetentionInterval(d time.Duration) Option {
	return func(o *options) { o.retentionInterval = d }
}

// WithArchiveSink sets the archive sink for retention.
func WithArchiveSink(s sink.Sink) Option {
	return func(o *options) { o.archiveSink = s }
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) { o.logger = l }
}

// WithDisableRoutes disables automatic route registration in the Forge router.
func WithDisableRoutes(disable bool) Option {
	return func(o *options) { o.disableRoutes = disable }
}

// WithDisableMigrate disables automatic database migration on Start.
func WithDisableMigrate(disable bool) Option {
	return func(o *options) { o.disableMigrate = disable }
}
