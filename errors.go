package chronicle

import "errors"

// Sentinel errors for Chronicle operations.
var (
	// ErrNoStore is returned when no store has been configured.
	ErrNoStore = errors.New("chronicle: no store configured")

	// ErrEventNotFound is returned when an audit event cannot be found.
	ErrEventNotFound = errors.New("chronicle: event not found")

	// ErrStreamNotFound is returned when a hash chain stream cannot be found.
	ErrStreamNotFound = errors.New("chronicle: stream not found")

	// ErrChainBroken is returned when hash chain verification detects tampering.
	ErrChainBroken = errors.New("chronicle: hash chain broken")

	// ErrSubjectNotFound is returned when a GDPR subject cannot be found.
	ErrSubjectNotFound = errors.New("chronicle: subject not found")

	// ErrPolicyNotFound is returned when a retention policy cannot be found.
	ErrPolicyNotFound = errors.New("chronicle: retention policy not found")

	// ErrReportNotFound is returned when a compliance report cannot be found.
	ErrReportNotFound = errors.New("chronicle: report not found")

	// ErrErasureNotFound is returned when an erasure record cannot be found.
	ErrErasureNotFound = errors.New("chronicle: erasure not found")

	// ErrErasureKeyNotFound is returned when a per-subject encryption key cannot be found.
	ErrErasureKeyNotFound = errors.New("chronicle: erasure key not found")

	// ErrInvalidQuery is returned when a query has invalid parameters.
	ErrInvalidQuery = errors.New("chronicle: invalid query")

	// ErrUnauthorized is returned when a caller lacks permission for the requested operation.
	ErrUnauthorized = errors.New("chronicle: unauthorized")

	// ErrStoreClosed is returned when an operation is attempted on a closed store.
	ErrStoreClosed = errors.New("chronicle: store closed")

	// ErrMigrationFailed is returned when database migrations fail.
	ErrMigrationFailed = errors.New("chronicle: migration failed")
)
