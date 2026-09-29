package sink_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/sink"
)

func (f *fakeS3) ListObjects(_ context.Context, _, prefix string) ([]string, error) {
	var out []string
	for _, k := range f.keys() {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeS3) GetObject(_ context.Context, _, key string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return io.NopCloser(bytes.NewReader(f.objects[key])), nil
}

func readAll(t *testing.T, a sink.ArchiveReader) ([]*audit.Event, []string) {
	t.Helper()
	var (
		events []*audit.Event
		locs   []string
	)
	err := a.ReadEvents(context.Background(), func(e *audit.Event, loc string) error {
		events = append(events, e)
		locs = append(locs, loc)
		return nil
	})
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	return events, locs
}

// TestFileArchiveReadsBackRotatedFiles reads what a rotating FileSink wrote,
// across every file it rotated into.
func TestFileArchiveReadsBackRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	fs := sink.NewFileSink(dir, "audit", sink.WithMaxSize(1))
	written := []*audit.Event{testEvent(), testEvent(), testEvent()}
	if err := fs.Write(context.Background(), written); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Another prefix in the same directory is not this archive.
	other := sink.NewFileSink(dir, "other")
	if err := other.Write(context.Background(), []*audit.Event{testEvent()}); err != nil {
		t.Fatalf("Write other: %v", err)
	}
	_ = other.Close()

	got, locs := readAll(t, sink.NewFileArchive(dir, "audit"))
	if len(got) != len(written) {
		t.Fatalf("read %d events, want %d", len(got), len(written))
	}
	seen := make(map[string]bool)
	for _, e := range got {
		seen[e.ID.String()] = true
	}
	for _, e := range written {
		if !seen[e.ID.String()] {
			t.Errorf("event %s not read back", e.ID)
		}
	}
	if !strings.HasSuffix(locs[0], "#1") {
		t.Errorf("location %q does not name the record", locs[0])
	}
}

// TestS3ArchiveReadsBackWhatTheSinkWrote round-trips through S3Sink's gzip
// JSONL objects, and ignores objects that are not its own.
func TestS3ArchiveReadsBackWhatTheSinkWrote(t *testing.T) {
	fake := newFakeS3()
	s := sink.NewS3Sink(fake, "bucket", "archives")
	day := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	written := []*audit.Event{s3TestEvent("auth", day), s3TestEvent("billing", day.Add(48*time.Hour))}
	if err := s.Write(context.Background(), written); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	fake.objects["archives/README.txt"] = []byte("not an archive")
	fake.objects["archives-old/auth/2024/03/05/events-0.jsonl.gz"] = []byte("not this archive")

	archive := sink.NewS3Archive(fake, "bucket", "archives")
	got, locs := readAll(t, archive)
	if len(got) != 2 {
		t.Fatalf("read %d events, want 2", len(got))
	}
	if !strings.HasPrefix(locs[0], "s3://bucket/archives/") {
		t.Errorf("location = %q", locs[0])
	}
	if archive.Name() != "s3://bucket/archives" {
		t.Errorf("name = %q", archive.Name())
	}
}

// TestArchivedDigestSurvivesTheRoundTrip is the property a backfill depends
// on: an event read back from the archive recomputes to the digest it was
// written with. The large integer is the trap. Decoded as float64 it comes
// back one lower, and the digest no longer matches.
func TestArchivedDigestSurvivesTheRoundTrip(t *testing.T) {
	ctx := context.Background()
	e := testEvent()
	e.Sequence = 1
	e.Metadata = map[string]any{"n": int64(9007199254740993), "nested": map[string]any{"f": 1.5}}
	chain := &hash.Chain{}
	digest, _, err := chain.Compute(ctx, "", e)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	e.Hash, e.HashScheme = digest, string(hash.SchemePlainV4)

	for _, gz := range []bool{false, true} {
		var buf bytes.Buffer
		w := io.Writer(&buf)
		var zw *gzip.Writer
		if gz {
			zw = gzip.NewWriter(&buf)
			w = zw
		}
		if err := sink.NewStdoutSink(w).Write(ctx, []*audit.Event{e}); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if zw != nil {
			_ = zw.Close()
		}

		var got *audit.Event
		if err := sink.DecodeArchive(&buf, "mem", func(ev *audit.Event, _ string) error {
			got = ev
			return nil
		}); err != nil {
			t.Fatalf("DecodeArchive (gzip=%v): %v", gz, err)
		}
		res, err := chain.VerifyWithPin(ctx, got.PrevHash, got, hash.Pin{})
		if err != nil || !res.OK {
			t.Errorf("gzip=%v: archived copy no longer verifies (ok=%v err=%v)", gz, res.OK, err)
		}
	}
}

// TestDecodeArchiveNamesAMalformedRecord: a broken line stops the read and
// says where, rather than quietly dropping evidence.
func TestDecodeArchiveNamesAMalformedRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-x-0001.jsonl")
	if err := os.WriteFile(path, []byte("{\"action\":\"a\"}\n{\"action\":\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := sink.NewFileArchive(dir, "audit").ReadEvents(context.Background(), func(*audit.Event, string) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "record 2") {
		t.Fatalf("err = %v, want it to name record 2", err)
	}
}
