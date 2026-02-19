package extension

// Config holds the configuration for the Chronicle Forge extension.
type Config struct {
	// DisableRoutes disables automatic route registration.
	DisableRoutes bool

	// DisableMigrate disables automatic database migration on Start.
	DisableMigrate bool
}
