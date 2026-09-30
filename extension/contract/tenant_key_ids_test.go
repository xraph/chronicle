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

// An app-level record has no tenant. The field is left off the wire rather
// than sent as "", so the page can tell "app level" from a tenant whose name
// is empty, which no tenant has.
func TestAnAppLevelRecordSendsNoTenant(t *testing.T) {
	for name, v := range map[string]any{
		"event":   projectEventDetail(&audit.Event{ID: id.NewAuditID(), AppID: "app-1"}),
		"erasure": projectErasureSummary(&erasure.Erasure{ID: id.NewErasureID(), AppID: "app-1"}),
		"report":  projectReportSummary(&compliance.Report{ID: id.NewReportID(), AppID: "app-1"}),
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if strings.Contains(string(b), `"tenantId"`) {
			t.Errorf("%s: an app-level record sent a tenantId: %s", name, b)
		}
	}
}

// The encryption key ID is on the detail only. It is not covered by the
// event's digest, which the page has to say, and a list has no room to.
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
	if strings.Contains(string(b), "encryptionKeyId") {
		t.Errorf("an event never sealed sent an encryptionKeyId: %s", b)
	}
}
