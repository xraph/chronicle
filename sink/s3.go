package sink

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/xraph/chronicle/audit"
)

// S3Writer defines the minimal interface for writing objects to S3.
// This abstracts away the specific AWS SDK to keep the dependency optional.
type S3Writer interface {
	// PutObject uploads data to S3 at the given key.
	PutObject(ctx context.Context, bucket, key string, body io.Reader) error
}

// S3Sink archives events to S3 as gzip-compressed JSONL files.
//
// Key format: {prefix}/{category}/{year}/{month}/{day}/events-{digest}.jsonl.gz
//
// The digest is over the batch's compressed bytes. A fixed name per
// category+day meant a second flush on the same day replaced the first archive,
// and since the retention enforcer purges the source rows once the archive
// write returns, the first batch was lost from both S3 and the database.
// Deriving the suffix from content also makes a retried flush idempotent: the
// same batch resolves to the same key rather than accumulating duplicates.
type S3Sink struct {
	writer S3Writer
	bucket string
	prefix string

	mu     sync.Mutex
	buffer []*audit.Event
}

// NewS3Sink creates a new S3 archive sink.
func NewS3Sink(writer S3Writer, bucket, prefix string) *S3Sink {
	return &S3Sink{
		writer: writer,
		bucket: bucket,
		prefix: prefix,
	}
}

// Name returns the sink name.
func (s *S3Sink) Name() string { return "s3" }

// Write buffers events for the next flush.
func (s *S3Sink) Write(_ context.Context, events []*audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buffer = append(s.buffer, events...)
	return nil
}

// Flush compresses buffered events as gzip JSONL and uploads to S3.
// Events are partitioned by category and date.
//
// The buffer is only cleared once every partition has uploaded. A failed flush
// leaves the events in place so the caller can retry, rather than dropping the
// batch on the floor.
func (s *S3Sink) Flush(ctx context.Context) error {
	s.mu.Lock()
	events := s.buffer
	s.mu.Unlock()

	if len(events) == 0 {
		return nil
	}

	// Partition events by category + date.
	partitions := make(map[string][]*audit.Event)
	for _, e := range events {
		prefix := fmt.Sprintf("%s/%s/%d/%02d/%02d",
			s.prefix, escapeKeySegment(e.Category),
			e.Timestamp.Year(), int(e.Timestamp.Month()), e.Timestamp.Day(),
		)
		partitions[prefix] = append(partitions[prefix], e)
	}

	for prefix, batch := range partitions {
		data, err := compressJSONL(batch)
		if err != nil {
			return fmt.Errorf("s3 sink: compress: %w", err)
		}

		digest := sha256.Sum256(data)
		key := fmt.Sprintf("%s/events-%s.jsonl.gz", prefix, hex.EncodeToString(digest[:8]))

		if err := s.writer.PutObject(ctx, s.bucket, key, bytes.NewReader(data)); err != nil {
			return fmt.Errorf("s3 sink: put object %s: %w", key, err)
		}
	}

	// Drop only what was uploaded; concurrent writers may have added more.
	s.mu.Lock()
	s.buffer = s.buffer[len(events):]
	s.mu.Unlock()

	return nil
}

// escapeKeySegment makes a value safe to embed as one S3 key segment, so a
// category cannot steer the object path with separators or traversal.
func escapeKeySegment(v string) string {
	if v == "" {
		return "unknown"
	}

	var b strings.Builder
	b.Grow(len(v))
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}

	// A segment of only dots would still read as a traversal.
	out := b.String()
	if strings.Trim(out, ".") == "" {
		return "unknown"
	}
	return out
}

// Close flushes any remaining events.
func (s *S3Sink) Close() error {
	// We don't flush on close since we have no context.
	// Callers should call Flush before Close.
	return nil
}

// compressJSONL encodes events as gzip-compressed JSONL.
func compressJSONL(events []*audit.Event) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)

	enc := json.NewEncoder(gz)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return nil, fmt.Errorf("encode event: %w", err)
		}
	}

	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}

	return buf.Bytes(), nil
}
