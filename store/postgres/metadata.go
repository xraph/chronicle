package postgres

import (
	"errors"

	"github.com/xraph/chronicle/internal/metajson"
)

// exactMetadata leaves number spelling intact until toEvent selects the row's
// encoding. Reliable rows use fixed-point exact decimals. Legacy rows retain
// metajson's historical float/int formatting for their existing hash schemes.
type exactMetadata map[string]any

func (m *exactMetadata) UnmarshalJSON(data []byte) error {
	decoded, err := metajson.DecodeExact(data)
	if err != nil {
		return err
	}

	*m = decoded
	return nil
}
func (m *exactMetadata) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*m = nil
		return nil
	case []byte:
		return m.UnmarshalJSON(v)
	case string:
		return m.UnmarshalJSON([]byte(v))
	default:
		return errors.New("chronicle: metadata column is not text")
	}
}
