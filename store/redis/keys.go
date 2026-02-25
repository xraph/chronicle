package redis

// Key prefixes for primary entity storage.
const (
	prefixEvent   = "chronicle:evt:"
	prefixStream  = "chronicle:str:"
	prefixErasure = "chronicle:era:"
	prefixPolicy  = "chronicle:pol:"
	prefixArchive = "chronicle:arc:"
	prefixReport  = "chronicle:rpt:"
)

// Key prefixes for sorted set indexes.
const (
	// Events
	zEventAll      = "chronicle:z:evt:all"
	zEventStream   = "chronicle:z:evt:stream:"   // + stream ID
	zEventScope    = "chronicle:z:evt:scope:"    // + appID:tenantID
	zEventCategory = "chronicle:z:evt:category:" // + category
	zEventUser     = "chronicle:z:evt:user:"     // + user ID
	zEventSubject  = "chronicle:z:evt:subject:"  // + subject ID

	// Streams
	zStreamAll = "chronicle:z:str:all"

	// Erasures
	zErasureAll = "chronicle:z:era:all"

	// Policies
	zPolicyAll = "chronicle:z:pol:all"

	// Archives
	zArchiveAll = "chronicle:z:arc:all"

	// Reports
	zReportAll = "chronicle:z:rpt:all"
)

// Key prefixes for unique indexes.
const (
	uniqueStreamScope    = "chronicle:u:str:scope:" // + appID:tenantID
	uniquePolicyCategory = "chronicle:u:pol:cat:"   // + category
)

// entityKey returns the primary key for an entity.
func entityKey(prefix, id string) string {
	return prefix + id
}
