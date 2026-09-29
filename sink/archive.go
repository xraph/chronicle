package sink

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xraph/chronicle/audit"
)

// ArchiveReader reads back the events an archive sink wrote.
//
// Sinks are write-only, and for everything but retention that is all they need
// to be. Reading exists for one job: recovering the evidence for purges that
// happened before retention records did (see Chronicle.BackfillRetention). A
// reader hands back what the archive holds and vouches for none of it. Anyone
// who can write to the archive can put anything there, so every event must be
// verified before it is believed.
type ArchiveReader interface {
	// Name identifies the archive. It is written into the chain on any record
	// recovered from it, so it should say where the archive lives.
	Name() string

	// ReadEvents calls fn for every event in the archive. loc says where the
	// event was found, for reports. Returning an error from fn stops the read
	// and returns that error.
	ReadEvents(ctx context.Context, fn func(e *audit.Event, loc string) error) error
}

// gzipMagic opens every gzip stream.
var gzipMagic = []byte{0x1f, 0x8b}

// DecodeArchive decodes one archive object: JSONL as FileSink and StdoutSink
// write it, or gzip-compressed JSONL as S3Sink writes it. The compression is
// detected from the content, not a file name.
//
// Numbers in metadata decode as json.Number, not float64. A digest covers the
// metadata's JSON encoding, and json.Number re-encodes as exactly the literal
// that was archived, where a float64 loses integers above 2^53.
//
// A malformed record stops the decode with an error naming it. Skipping it
// could never make a backfill accept something it should not, but it would
// quietly drop evidence, and an operator should see that.
func DecodeArchive(r io.Reader, name string, fn func(e *audit.Event, loc string) error) error {
	br := bufio.NewReader(r)
	head, err := br.Peek(len(gzipMagic))
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("archive %s: %w", name, err)
	}

	var src io.Reader = br
	if bytes.Equal(head, gzipMagic) {
		gz, gzErr := gzip.NewReader(br)
		if gzErr != nil {
			return fmt.Errorf("archive %s: %w", name, gzErr)
		}
		defer func() { _ = gz.Close() }()
		src = gz
	}

	dec := json.NewDecoder(src)
	dec.UseNumber()
	for n := 1; ; n++ {
		var e audit.Event
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("archive %s: record %d: %w", name, n, err)
		}
		if err := fn(&e, fmt.Sprintf("%s#%d", name, n)); err != nil {
			return err
		}
	}
}

// FileArchive reads what a FileSink wrote: every prefix-*.jsonl file in a
// directory, oldest name first. Files compressed after rotation, named
// prefix-*.jsonl.gz, are read too.
type FileArchive struct {
	dir    string
	prefix string
}

// NewFileArchive reads the archive a NewFileSink(dir, prefix) wrote.
func NewFileArchive(dir, prefix string) *FileArchive {
	return &FileArchive{dir: dir, prefix: prefix}
}

// Name returns "file:" and the archive's directory and prefix.
func (a *FileArchive) Name() string {
	return "file:" + filepath.Join(a.dir, a.prefix)
}

// ReadEvents decodes every archive file in name order.
func (a *FileArchive) ReadEvents(ctx context.Context, fn func(e *audit.Event, loc string) error) error {
	var files []string
	for _, pattern := range []string{a.prefix + "-*.jsonl", a.prefix + "-*.jsonl.gz"} {
		matches, err := filepath.Glob(filepath.Join(a.dir, pattern))
		if err != nil {
			return fmt.Errorf("file archive: %w", err)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)

	for _, path := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.readFile(path, fn); err != nil {
			return err
		}
	}
	return nil
}

func (a *FileArchive) readFile(file string, fn func(e *audit.Event, loc string) error) error {
	// #nosec G304 -- path comes from globbing the operator-configured archive
	// directory for the operator-configured prefix.
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("file archive: %w", err)
	}
	defer func() { _ = f.Close() }()
	return DecodeArchive(f, file, fn)
}

// S3Reader is the read half of what an S3Sink needs, kept to two calls for
// the same reason S3Writer is: no AWS SDK dependency.
type S3Reader interface {
	// ListObjects returns every key in bucket that starts with prefix.
	ListObjects(ctx context.Context, bucket, prefix string) ([]string, error)

	// GetObject opens the object at key.
	GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, error)
}

// S3Archive reads what an S3Sink wrote: every events-*.jsonl.gz object under
// its prefix, in key order.
type S3Archive struct {
	reader S3Reader
	bucket string
	prefix string
}

// NewS3Archive reads the archive a NewS3Sink(writer, bucket, prefix) wrote.
func NewS3Archive(reader S3Reader, bucket, prefix string) *S3Archive {
	return &S3Archive{reader: reader, bucket: bucket, prefix: prefix}
}

// Name returns the archive's s3:// URL.
func (a *S3Archive) Name() string {
	return "s3://" + a.bucket + "/" + a.prefix
}

// ReadEvents decodes every archive object in key order.
func (a *S3Archive) ReadEvents(ctx context.Context, fn func(e *audit.Event, loc string) error) error {
	// List under "prefix/" so a prefix of "audit" does not also pick up an
	// unrelated "audit-old/..." written by something else.
	listPrefix := a.prefix
	if listPrefix != "" && !strings.HasSuffix(listPrefix, "/") {
		listPrefix += "/"
	}
	keys, err := a.reader.ListObjects(ctx, a.bucket, listPrefix)
	if err != nil {
		return fmt.Errorf("s3 archive: list %s: %w", listPrefix, err)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if !strings.HasSuffix(key, ".jsonl.gz") || !strings.HasPrefix(path.Base(key), "events-") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := a.readObject(ctx, key, fn); err != nil {
			return err
		}
	}
	return nil
}

func (a *S3Archive) readObject(ctx context.Context, key string, fn func(e *audit.Event, loc string) error) error {
	body, err := a.reader.GetObject(ctx, a.bucket, key)
	if err != nil {
		return fmt.Errorf("s3 archive: get %s: %w", key, err)
	}
	defer func() { _ = body.Close() }()
	return DecodeArchive(body, "s3://"+a.bucket+"/"+key, fn)
}
