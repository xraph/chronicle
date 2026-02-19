// Package chronicle provides a composable, immutable audit trail for Go.
//
// Chronicle records tamper-proof audit events linked by SHA-256 hash chains,
// supports tenant-scoped queries, GDPR crypto-erasure, compliance reporting
// (SOC2, HIPAA, EU AI Act), and pluggable sinks and reporters.
//
// It is designed as a library — import it into your application, configure a
// store backend, and start recording events. No separate daemon required.
//
//	c, err := chronicle.New(
//	    chronicle.WithStore(memStore),
//	    chronicle.WithBatchSize(50),
//	)
//
// Chronicle integrates with the Forge ecosystem via forge.Scope for automatic
// tenant scoping and the Emitter interface for dependency injection.
package chronicle
