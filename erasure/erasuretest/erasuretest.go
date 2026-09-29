// Package erasuretest holds checks every erasure.Store implementation must
// pass, so each backend runs the same scenario against its own engine.
package erasuretest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
)

// Appender stores one event. A backend whose events need a parent row (a
// stream, say) creates it here before appending.
type Appender func(t *testing.T, e *audit.Event)

// SubjectKeyUsage checks that s groups a subject's events by app, tenant, key
// ID and erased flag, across every scope, and leaves other subjects out.
//
// suffix is appended to every ID the scenario writes, so runs sharing one
// database cannot see each other's rows.
func SubjectKeyUsage(t *testing.T, s erasure.Store, appendEvent Appender, suffix string) {
	t.Helper()
	ctx := context.Background()

	subject := "user-42-" + suffix
	app1, tenantA := "app-1-"+suffix, "tenant-a-"+suffix
	app2, tenantB := "app-2-"+suffix, "tenant-b-"+suffix
	scoped := crypto.ScopedKeyID(app1, tenantA, subject)

	base := time.Now().UTC().Truncate(time.Second)
	seed := func(appID, tenantID, subjectID, keyID string, n int) {
		for range n {
			appendEvent(t, &audit.Event{
				ID:              id.NewAuditID(),
				StreamID:        id.NewStreamID(),
				Hash:            randomHash(t),
				Timestamp:       base,
				AppID:           appID,
				TenantID:        tenantID,
				Action:          "export",
				Resource:        "user",
				Category:        "data",
				Outcome:         audit.OutcomeSuccess,
				Severity:        audit.SeverityInfo,
				SubjectID:       subjectID,
				EncryptionKeyID: keyID,
			})
		}
	}

	seed(app1, tenantA, subject, subject, 2) // sealed before keys were scoped
	seed(app1, tenantA, subject, scoped, 1)  // sealed after
	seed(app1, tenantA, subject, "", 1)      // never sealed
	seed(app2, tenantB, subject, subject, 1) // another app on the shared legacy key
	seed(app1, tenantA, "someone-else-"+suffix, "", 1)

	marked, err := s.MarkErased(ctx, erasure.SubjectQuery{
		Scope:     erasure.Scope{AppID: app2, TenantID: tenantB},
		SubjectID: subject,
	}, id.NewErasureID())
	if err != nil || marked != 1 {
		t.Fatalf("MarkErased app-2 = %d, %v; want 1", marked, err)
	}

	got, err := s.SubjectKeyUsage(ctx, subject)
	if err != nil {
		t.Fatalf("SubjectKeyUsage: %v", err)
	}

	want := []erasure.KeyUsage{
		{Scope: erasure.Scope{AppID: app1, TenantID: tenantA}, EncryptionKeyID: "", Events: 1},
		{Scope: erasure.Scope{AppID: app1, TenantID: tenantA}, EncryptionKeyID: scoped, Events: 1},
		{Scope: erasure.Scope{AppID: app1, TenantID: tenantA}, EncryptionKeyID: subject, Events: 2},
		{Scope: erasure.Scope{AppID: app2, TenantID: tenantB}, EncryptionKeyID: subject, Erased: true, Events: 1},
	}
	if g, w := render(got), render(want); g != w {
		t.Errorf("SubjectKeyUsage(%q):\n got %s\nwant %s", subject, g, w)
	}
}

// render prints usage in a stable order so two results compare as strings.
func render(usage []erasure.KeyUsage) string {
	rows := make([]string, 0, len(usage))
	for _, u := range usage {
		rows = append(rows, fmt.Sprintf("{%s %s %q erased=%v n=%d}",
			u.AppID, u.TenantID, u.EncryptionKeyID, u.Erased, u.Events))
	}
	sort.Strings(rows)
	return fmt.Sprint(rows)
}

func randomHash(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("random hash: %v", err)
	}
	return hex.EncodeToString(b[:])
}
