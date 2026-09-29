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

	// ErrCryptoErasureUnavailable is returned when crypto-erasure is enabled
	// without a sealer to perform the encryption.
	//
	// Accepting the flag without one would store subject data as plaintext while
	// the operator believed a key deletion made it unrecoverable. Refusing to
	// start is the safer failure: a compliance guarantee that silently does not
	// hold is worse than one that is explicitly unavailable.
	ErrCryptoErasureUnavailable = errors.New(
		"chronicle: crypto-erasure is enabled but no sealer was provided; " +
			"pass chronicle.WithSealer(crypto.NewSealer(keyStore)) so subject " +
			"payloads are encrypted, or disable enable_crypto_erasure",
	)

	// ErrHMACKeyUnavailable is returned when a keyed digest scheme is selected
	// without a key provider to supply the key.
	//
	// The reasoning matches ErrCryptoErasureUnavailable: an operator who set
	// digest: hmac believes their chain cannot be recomputed from the stored
	// rows alone. Writing unkeyed digests under that belief is worse than
	// refusing to start.
	ErrHMACKeyUnavailable = errors.New(
		"chronicle: digest scheme hmac is selected but no key provider was given; " +
			"pass chronicle.WithKeyProvider(keys.NewFileProvider(path)) so digests " +
			"are keyed, or leave the digest scheme unset",
	)

	// ErrSchemeWeakeningRefused is returned when a stream is pinned to a
	// stronger digest scheme than the one this process is configured to write.
	//
	// Chronicle moves a stream's pin up on its own, because that is the only way
	// turning HMAC on takes effect on streams that already exist. It will not
	// move one down. A pin that drops on its own is indistinguishable from an
	// attacker lowering it, and once it has dropped every event written under
	// the weaker scheme verifies clean, so the operator sees green while the
	// guarantee they configured is gone. Refusing the write is loud, reversible,
	// and leaves the existing chain intact.
	ErrSchemeWeakeningRefused = errors.New(
		"chronicle: this stream is pinned to a stronger digest scheme than this " +
			"process writes; restore the stronger scheme (tamper_evidence.digest " +
			"and its key source, or chronicle.WithDigestScheme plus " +
			"chronicle.WithKeyProvider), or if the weaker scheme is genuinely " +
			"intended, record that decision and lower the stream's pin " +
			"deliberately through the store",
	)

	// ErrRetentionWithheld is returned when retention was asked to remove
	// events that no longer verify.
	//
	// Purging an event destroys the evidence of anything done to it, and a
	// retention record would then vouch for its hashes as if it had been
	// intact. So an event whose digest fails is kept, with its tampering still
	// on the record for verification to report, and the rest of the batch is
	// purged as usual. The same holds for an event that cannot be verified at
	// all, such as one digested under a key that can no longer be resolved.
	ErrRetentionWithheld = errors.New(
		"chronicle: retention withheld events that do not verify; they are kept as evidence",
	)

	// ErrBackfillUnkeyed is returned when a retention backfill is asked to
	// run against a stream that is not pinned to chronicle/v5, or by a
	// process that does not write chronicle/v5.
	//
	// A backfill turns gaps into retained sequences on the strength of
	// archived copies of the purged events. That is only evidence when
	// nobody but the chain writer could have produced those copies. Under an
	// unkeyed scheme anyone with write access to the store can compute a
	// valid digest, fabricate an archive to match, and have the backfill
	// excuse a deletion. The result would be an attestation dressed up as a
	// proof, so it is refused outright.
	ErrBackfillUnkeyed = errors.New(
		"chronicle: retention backfill needs a keyed chronicle/v5 chain; under an unkeyed " +
			"scheme an archived copy proves nothing, because anyone who can write the store " +
			"can fabricate one",
	)
)
