package contract

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
)

// An app-wide viewer reads records from every tenant in its app. Without the
// tenant on the wire it cannot tell which tenant a record belongs to, so each
// record the dashboard lists or opens carries it.
func TestRecordsCarryTheirTenant(t *testing.T) {
	ev := &audit.Event{ID: id.NewAuditID(), AppID: "app-1", TenantID: "tenant-a"}
	if got := projectEventSummary(ev).TenantID; got != "tenant-a" {
		t.Errorf("EventSummary.TenantID = %q, want tenant-a", got)
	}
	if got := projectEventDetail(ev).TenantID; got != "tenant-a" {
		t.Errorf("EventDetail.TenantID = %q, want tenant-a", got)
	}
	if got := projectErasureSummary(&erasure.Erasure{ID: id.NewErasureID(), AppID: "app-1", TenantID: "tenant-a"}).TenantID; got != "tenant-a" {
		t.Errorf("ErasureSummary.TenantID = %q, want tenant-a", got)
	}
	if got := projectReportSummary(&compliance.Report{ID: id.NewReportID(), AppID: "app-1", TenantID: "tenant-a"}).TenantID; got != "tenant-a" {
		t.Errorf("ReportSummary.TenantID = %q, want tenant-a", got)
	}
}

// An app-level record has no tenant, and says so with an empty tenantId. The
// field is never left off: a server from before it existed sends nothing, and
// the page must be able to tell that apart from "app level".
func TestAnAppLevelRecordSendsAnEmptyTenant(t *testing.T) {
	for name, v := range map[string]any{
		"event":   projectEventDetail(&audit.Event{ID: id.NewAuditID(), AppID: "app-1"}),
		"erasure": projectErasureSummary(&erasure.Erasure{ID: id.NewErasureID(), AppID: "app-1"}),
		"report":  projectReportSummary(&compliance.Report{ID: id.NewReportID(), AppID: "app-1"}),
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if !strings.Contains(string(b), `"tenantId":""`) {
			t.Errorf("%s: an app-level record did not send an empty tenantId: %s", name, b)
		}
	}
}

// The encryption key ID is on the detail only, and sent empty for an event
// never sealed. It is not covered by the event's digest, which the page has
// to say, and a list has no room to.
func TestEventDetailCarriesTheEncryptionKeyIDAndTheSummaryDoesNot(t *testing.T) {
	ev := &audit.Event{ID: id.NewAuditID(), AppID: "app-1", SubjectID: "subject-1", EncryptionKeyID: "key-1"}
	d := projectEventDetail(ev)
	if d.EncryptionKeyID != "key-1" {
		t.Errorf("EventDetail.EncryptionKeyID = %q, want key-1", d.EncryptionKeyID)
	}
	b, err := json.Marshal(projectEventSummary(ev))
	if err != nil {
		t.Fatalf("marshal summary: %v", err)
	}
	if strings.Contains(string(b), "encryptionKeyId") {
		t.Errorf("EventSummary sent encryptionKeyId: %s", b)
	}
	b, err = json.Marshal(projectEventDetail(&audit.Event{ID: id.NewAuditID(), AppID: "app-1"}))
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	if !strings.Contains(string(b), `"encryptionKeyId":""`) {
		t.Errorf("an event never sealed did not send an empty encryptionKeyId: %s", b)
	}
}
