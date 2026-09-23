package hash

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/xraph/chronicle/audit"
)

// ComputeV2ForTest produces a digest under the frozen v2 content encoding.
//
// NewChain refuses to write v2, which is the whole point of v4 existing. Tests
// still need to build the historical rows that verification has to keep
// accepting, and this is the only way left to make one. It compiles into the
// test binary alone, so nothing shippable can reach it.
func ComputeV2ForTest(prevHash string, event *audit.Event) string {
	sum := sha256.Sum256([]byte(contentV2(prevHash, event)))
	return hex.EncodeToString(sum[:])
}
