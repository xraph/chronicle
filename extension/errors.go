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
)
