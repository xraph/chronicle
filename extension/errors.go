package extension

import "errors"

// Errors returned while configuring the extension.
var (
	// ErrAuthNotConfigured is returned when the admin API would be mounted with
	// no authentication and the operator has not said that is intentional.
	//
	// The API can permanently destroy audit data: POST /v1/retention/enforce
	// purges events, DELETE /v1/retention/:id disables retention, and
	// POST /v1/erasures cannot be undone. Chronicle's scope check keeps tenants
	// out of each other's data but does not gate these operations, so an
	// unauthenticated mount means any caller that reaches the routes can destroy
	// an app's history.
	ErrAuthNotConfigured = errors.New(
		"chronicle: admin API would be mounted without authentication. " +
			"Set auth.provider to a registered forge auth provider (with " +
			"auth.read_scopes / auth.write_scopes / auth.admin_scopes), or set " +
			"auth.allow_unauthenticated: true to accept that any caller reaching " +
			"these routes can purge audit history, or disable_routes: true to not " +
			"mount the API at all",
	)

	// ErrKeyStoreRequired is returned when crypto-erasure is enabled without a
	// key store to hold the per-subject keys.
	//
	// The key store decides whether sealed events can ever be read again, so it
	// cannot be defaulted: an in-memory one would silently make every event
	// unreadable after a restart, which looks identical to having erased every
	// subject.
	ErrKeyStoreRequired = errors.New(
		"chronicle: enable_crypto_erasure requires a key store; " +
			"pass extension.WithKeyStore(...) with a durable implementation, or " +
			"disable enable_crypto_erasure",
	)

	// ErrAuthProviderUnavailable is returned when an auth provider is named but
	// the forge auth registry is not in the DI container, so nothing could
	// enforce it. Failing here rather than mounting unprotected routes keeps a
	// misconfiguration from silently becoming an open API.
	ErrAuthProviderUnavailable = errors.New(
		"chronicle: auth.provider is set but no forge auth registry is " +
			"registered in the container; add the forge auth extension so the " +
			"provider can be resolved",
	)

	// ErrKeyProviderRequired is returned when a keyed digest is configured with
	// no key source.
	ErrKeyProviderRequired = errors.New(
		"chronicle: tamper_evidence.digest is hmac but no key source was configured; " +
			"set tamper_evidence.keys.provider and path, or pass extension.WithKeyProvider",
	)

	// ErrStoreCannotReceiveHasher is returned when tamper_evidence.digest is
	// hmac and the store passed to WithStore is of a type chronicle does not
	// recognise and cannot be given the chain after construction.
	//
	// WithStore bypasses buildStoreFromGroveDB, which is the only place a
	// pg/sqlite store otherwise gets WithHasher. A store that recomputes the
	// digest inside its own Append and never receives the configured chain
	// keeps re-linking every event under a default plain chain while Chronicle
	// writes HMAC digests -- silently, since the writes still succeed.
	//
	// Chronicle's own mongo, redis and memory backends do not recompute, so
	// they are accepted as they are; they were never the problem and have no
	// WithHasher option to point anyone at. Any other type is refused, because
	// whether it recomputes cannot be determined from outside and guessing
	// wrong produces the silent unkeyed chain above.
	ErrStoreCannotReceiveHasher = errors.New(
		"chronicle: tamper_evidence.digest is hmac but the store passed to WithStore " +
			"is not a store chronicle can hand the keyed chain to; give it a " +
			"SetHasher(*hash.Chain) method (chronicle's pg and sqlite stores have one) " +
			"so it re-links under the configured chain, or drop WithStore and let " +
			"chronicle build the store itself with the chain already wired in",
	)
)
