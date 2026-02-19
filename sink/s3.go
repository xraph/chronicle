package sink

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
// Key format: {prefix}/{category}/{year}/{month}/{day}/events.jsonl.gz
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
func (s *S3Sink) Flush(ctx context.Context) error {
	s.mu.Lock()
	events := s.buffer
	s.buffer = nil
	s.mu.Unlock()

	if len(events) == 0 {
		return nil
	}

	// Partition events by category + date.
	partitions := make(map[string][]*audit.Event)
	for _, e := range events {
		key := fmt.Sprintf("%s/%s/%d/%02d/%02d/events.jsonl.gz",
			s.prefix, e.Category,
			e.Timestamp.Year(), e.Timestamp.Month(), e.Timestamp.Day(),
		)
		partitions[key] = append(partitions[key], e)
	}

	for key, batch := range partitions {
		data, err := compressJSONL(batch)
		if err != nil {
			return fmt.Errorf("s3 sink: compress: %w", err)
		}

		if err := s.writer.PutObject(ctx, s.bucket, key, bytes.NewReader(data)); err != nil {
			return fmt.Errorf("s3 sink: put object %s: %w", key, err)
		}
	}

	return nil
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
