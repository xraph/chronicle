package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xraph/chronicle/audit"
)

// FileSink writes events as JSONL to a file with optional rotation.
type FileSink struct {
	mu          sync.Mutex
	dir         string
	prefix      string
	maxSize     int64 // bytes; 0 = no rotation
	currentFile *os.File
	currentSize int64
	fileCount   int // counter for unique filenames
}

// FileOption configures a FileSink.
type FileOption func(*FileSink)

// WithMaxSize sets the maximum file size in bytes before rotation.
func WithMaxSize(bytes int64) FileOption {
	return func(s *FileSink) {
		s.maxSize = bytes
	}
}

// NewFileSink creates a FileSink writing JSONL to dir/prefix-*.jsonl.
func NewFileSink(dir, prefix string, opts ...FileOption) *FileSink {
	s := &FileSink{
		dir:    dir,
		prefix: prefix,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *FileSink) Name() string { return "file" }

func (s *FileSink) Write(_ context.Context, events []*audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range events {
		if err := s.ensureFile(); err != nil {
			return err
		}

		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		data = append(data, '\n')

		n, err := s.currentFile.Write(data)
		if err != nil {
			return err
		}
		s.currentSize += int64(n)
	}
	return nil
}

func (s *FileSink) Flush(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentFile != nil {
		return s.currentFile.Sync()
	}
	return nil
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentFile != nil {
		err := s.currentFile.Close()
		s.currentFile = nil
		return err
	}
	return nil
}

// ensureFile opens or rotates the file as needed. Must be called with mu held.
func (s *FileSink) ensureFile() error {
	if s.currentFile != nil && (s.maxSize <= 0 || s.currentSize < s.maxSize) {
		return nil
	}

	// Rotate: close current file.
	if s.currentFile != nil {
		_ = s.currentFile.Close()
		s.currentFile = nil
	}

	// Create directory if needed.
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return err
	}

	// Open new file with timestamp and counter suffix.
	s.fileCount++
	name := fmt.Sprintf("%s-%s-%04d.jsonl", s.prefix, time.Now().UTC().Format("20060102T150405Z"), s.fileCount)
	path := filepath.Join(s.dir, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}

	s.currentFile = f
	s.currentSize = 0
	return nil
}
