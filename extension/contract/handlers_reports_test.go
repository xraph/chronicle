package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// ──────────────────────────────────────────────────
// Test doubles and seeding. Named after this task so they cannot collide
// with another task's.
// ──────────────────────────────────────────────────

// reportsSpyStore records the report-store and audit-store calls a handler
// makes, and answers with fixed data. Embedding stubStore keeps every other
// method a zero-value no-op.
type reportsSpyStore struct {
	stubStore
	report *compliance.Report // answered by GetReport, when set
	list   []*compliance.Report

	saveCalls int
	getCalls  int
	listOpts  []compliance.ListOpts

	queries    []*audit.Query
	aggregates []*audit.AggregateQuery
}

func (s *reportsSpyStore) SaveReport(context.Context, *compliance.Report) error {
	s.saveCalls++
	return nil
}

func (s *reportsSpyStore) GetReport(context.Context, id.ID) (*compliance.Report, error) {
	s.getCalls++
	if s.report == nil {
		return nil, chronicle.ErrReportNotFound
	}
	return s.report, nil
}

func (s *reportsSpyStore) ListReports(_ context.Context, opts compliance.ListOpts) ([]*compliance.Report, error) {
	s.listOpts = append(s.listOpts, opts)
	return s.list, nil
}

func (s *reportsSpyStore) Query(_ context.Context, q *audit.Query) (*audit.QueryResult, error) {
	s.queries = append(s.queries, q)
	return &audit.QueryResult{}, nil
}

func (s *reportsSpyStore) Aggregate(_ context.Context, q *audit.AggregateQuery) (*audit.AggregateResult, error) {
	s.aggregates = append(s.aggregates, q)
	return &audit.AggregateResult{}, nil
}

// reportsEngineOver builds a real engine whose audit, verify and report
// stores are all the given store.
func reportsEngineOver(s store.Store) *compliance.Engine {
	return compliance.NewEngine(s, s, s, nil)
}

func reportsViewer(app, tenant string) fcontract.Principal {
	claims := map[string]any{"app_id": app}
	if tenant != "" {
		claims["tenant_id"] = tenant
	}
	return principalWith(claims)
}

// reportsFixture is a stored report owned by app/tenant, with a real ID.
func reportsFixture(app, tenant string) *compliance.Report {
	now := time.Now().UTC()
	r := &compliance.Report{
		Entity:      chronicle.NewEntity(),
		ID:          id.NewReportID(),
		Title:       "SOC2 Type II Compliance Report",
		Type:        "soc2",
		Period:      compliance.DateRange{From: now.Add(-24 * time.Hour), To: now},
		AppID:       app,
		TenantID:    tenant,
		GeneratedBy: "operator-1",
		Format:      compliance.FormatJSON,
		Stats:       &compliance.Stats{TotalEvents: 3, CriticalEvents: 1},
		Sections: []compliance.Section{{
			Title:           "CC6.2 Authentication Events",
			Notes:           "auth",
			Events:          []*audit.Event{{ID: id.NewAuditID(), Action: "login", Resource: "session", Category: "auth", Outcome: "success", Severity: "info", Timestamp: now}},
			MatchedEvents:   5,
			EventsTruncated: true,
			Stats:           &audit.AggregateResult{Total: 5, Groups: []audit.AggregateGroup{{Outcome: "success", Severity: "info", Count: 5}}},
		}},
	}
	r.CreatedAt = now
	return r
}

func reportsSeedStream(t *testing.T, s store.Store, app string) id.ID {
	t.Helper()
	st := &stream.Stream{ID: id.NewStreamID(), AppID: app}
	if err := s.CreateStream(context.Background(), st); err != nil {
		t.Fatalf("create stream %s: %v", app, err)
	}
	return st.ID
}

func reportsSeedEvent(t *testing.T, s store.Store, streamID id.ID, app, userID string) {
	t.Helper()
	ts := time.Now().UTC().Add(-time.Hour)
	ev := &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  streamID,
		Hash:      "hash-" + userID,
		AppID:     app,
		UserID:    userID,
		Action:    "login",
		Resource:  "session",
		Category:  "auth",
		Outcome:   "success",
		Severity:  "info",
		Timestamp: ts,
	}
	if err := s.Append(context.Background(), ev); err != nil {
		t.Fatalf("append event: %v", err)
	}
}

func reportsWantCode(t *testing.T, err error, code fcontract.ErrorCode, what string) {
	t.Helper()
	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != code {
		t.Fatalf("%s: err = %v, want code %s", what, err, code)
	}
}

// ──────────────────────────────────────────────────
// Against a real store and a real engine
// ──────────────────────────────────────────────────

// reportsConfinementFlow runs the whole path once with nothing stubbed:
// generate as app-1's viewer over events from two apps, then list, fetch and
// export the result. The report must describe only app-1, and app-2 must
// neither see it nor be able to fetch or export it by ID.
//
// It takes the store and the generate call so the same assertions run on
// sqlite with a custom report and on the memory store with SOC2. They cannot
// both use SOC2: the sqlite store's multi-value filters (category IN (?) and
// its siblings) fail on a []string argument, which every fixed framework's
// sections use, so SOC2, HIPAA and EU AI Act generation fails on sqlite.
func reportsConfinementFlow(
	t *testing.T, s store.Store,
	generate func(Deps, fcontract.Principal) (GenerateReportResponse, error),
) {
	t.Helper()
	ctx := context.Background()
	deps := Deps{Store: s, Engine: reportsEngineOver(s)}

	stream1 := reportsSeedStream(t, s, "app-1")
	stream2 := reportsSeedStream(t, s, "app-2")
	reportsSeedEvent(t, s, stream1, "app-1", "user-of-app-1")
	reportsSeedEvent(t, s, stream1, "app-1", "second-user-of-app-1")
	reportsSeedEvent(t, s, stream2, "app-2", "user-of-app-2")

	app1, app2 := reportsViewer("app-1", ""), reportsViewer("app-2", "")

	gen, err := generate(deps, app1)
	if err != nil {
		t.Fatalf("reports.generate: %v", err)
	}
	if gen.ID == "" || gen.ID != gen.Report.ID {
		t.Fatalf("generate answered id %q with summary id %q", gen.ID, gen.Report.ID)
	}
	if gen.Report.GeneratedBy != "operator-1" {
		t.Errorf("generatedBy = %q, want the principal's subject", gen.Report.GeneratedBy)
	}
	if gen.Report.Stats == nil || gen.Report.Stats.TotalEvents != 2 {
		t.Fatalf("stats = %+v, want exactly app-1's 2 events", gen.Report.Stats)
	}

	// Listed once, not twice: the engine saved it and nothing saved it again.
	list, err := reportsListHandler(deps)(ctx, ReportListInput{}, app1)
	if err != nil {
		t.Fatalf("reports.list: %v", err)
	}
	if len(list.Reports) != 1 || list.Reports[0].ID != gen.ID || list.HasMore {
		t.Fatalf("app-1 list = %+v, want exactly the one generated report", list)
	}
	if other, _ := reportsListHandler(deps)(ctx, ReportListInput{}, app2); len(other.Reports) != 0 {
		t.Fatalf("app-2 lists %d of app-1's reports", len(other.Reports))
	}

	detail, err := reportsDetailHandler(deps)(ctx, GetReportInput{ID: gen.ID}, app1)
	if err != nil {
		t.Fatalf("reports.detail: %v", err)
	}
	seen := 0
	for _, sec := range detail.Sections {
		for _, ev := range sec.Events {
			seen++
			if ev.UserID == "user-of-app-2" {
				t.Fatalf("section %q carries app-2's event", sec.Title)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no section carries any event: the test proves nothing")
	}
	if detail.Verification != nil {
		t.Error("a freshly generated report reported a verification nothing wrote")
	}

	// Every format renders, and the JSON one names only app-1 in every event.
	for _, format := range []string{"json", "csv", "markdown", "html"} {
		out, err := reportsExportHandler(deps)(ctx, ExportReportInput{ID: gen.ID, Format: format}, app1)
		if err != nil {
			t.Fatalf("export %s: %v", format, err)
		}
		if out.Content == "" || out.ContentType == "" || !strings.HasPrefix(out.Filename, "report-"+gen.ID+".") {
			t.Errorf("export %s = %+v", format, out)
		}
		if strings.Contains(out.Content, "user-of-app-2") {
			t.Errorf("export %s carries app-2's event", format)
		}
	}
	jsonOut, _ := reportsExportHandler(deps)(ctx, ExportReportInput{ID: gen.ID, Format: "json"}, app1)
	var exported compliance.Report
	if err := json.Unmarshal([]byte(jsonOut.Content), &exported); err != nil {
		t.Fatalf("exported JSON does not parse: %v", err)
	}
	if exported.AppID != "app-1" {
		t.Errorf("exported report app_id = %q", exported.AppID)
	}
	for _, sec := range exported.Sections {
		for _, ev := range sec.Events {
			if ev.AppID != "app-1" {
				t.Fatalf("exported event from app %q", ev.AppID)
			}
		}
	}

	// The other app cannot reach it by ID, for either read or export, and
	// cannot tell it from a report that does not exist.
	_, err = reportsDetailHandler(deps)(ctx, GetReportInput{ID: gen.ID}, app2)
	reportsWantCode(t, err, fcontract.CodeNotFound, "app-2 detail of app-1's report")
	_, err = reportsExportHandler(deps)(ctx, ExportReportInput{ID: gen.ID, Format: "json"}, app2)
	reportsWantCode(t, err, fcontract.CodeNotFound, "app-2 export of app-1's report")
}

func TestReportsOverARealSQLiteStoreAreConfinedToTheViewersApp(t *testing.T) {
	reportsConfinementFlow(t, newSQLiteStore(t), func(d Deps, p fcontract.Principal) (GenerateReportResponse, error) {
		return reportsGenerateCustomHandler(d)(context.Background(), GenerateCustomReportInput{
			Title:    "Logins",
			Sections: []CustomReportSection{{Title: "Everything"}},
		}, p)
	})
}

func TestReportsSOC2OverARealEngineIsConfinedToTheViewersApp(t *testing.T) {
	reportsConfinementFlow(t, memory.New(), func(d Deps, p fcontract.Principal) (GenerateReportResponse, error) {
		return reportsGenerateHandler(d)(context.Background(), GenerateReportInput{Type: "soc2"}, p)
	})
}

// Each generator, including the custom one, saves exactly once through the
// engine, and a custom report's filters and scope reach the events.
func TestReportsGenerateHIPAAEUAIActAndCustomEachPersistOnce(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	deps := Deps{Store: s, Engine: reportsEngineOver(s)}
	st := reportsSeedStream(t, s, "app-1")
	reportsSeedEvent(t, s, st, "app-1", "u1")
	stOther := reportsSeedStream(t, s, "app-2")
	reportsSeedEvent(t, s, stOther, "app-2", "u2")
	viewer := reportsViewer("app-1", "")

	if _, err := reportsGenerateHandler(deps)(ctx, GenerateReportInput{Type: "hipaa"}, viewer); err != nil {
		t.Fatalf("hipaa: %v", err)
	}
	eu, err := reportsGenerateHandler(deps)(ctx, GenerateReportInput{Type: "euaiact"}, viewer)
	if err != nil {
		t.Fatalf("euaiact: %v", err)
	}
	if eu.Report.Type != "eu_ai_act" {
		t.Errorf("type = %q, want the engine's stored value", eu.Report.Type)
	}
	custom, err := reportsGenerateCustomHandler(deps)(ctx, GenerateCustomReportInput{
		Title:    "Logins",
		Sections: []CustomReportSection{{Title: "All logins", Actions: []string{"login"}}},
	}, viewer)
	if err != nil {
		t.Fatalf("custom: %v", err)
	}
	if custom.Report.Title != "Logins" || custom.Report.Type != "custom" {
		t.Errorf("custom summary = %+v", custom.Report)
	}
	if custom.Report.Stats == nil || custom.Report.Stats.TotalEvents != 1 {
		t.Errorf("custom report stats = %+v, want only app-1's event", custom.Report.Stats)
	}

	list, err := reportsListHandler(deps)(ctx, ReportListInput{}, viewer)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Reports) != 3 {
		t.Fatalf("listed %d reports after three generations, want 3 (one save each)", len(list.Reports))
	}
}

// ──────────────────────────────────────────────────
// reports.generate and reports.generateCustom
// ──────────────────────────────────────────────────

// The engine persists the report itself. Saving it again stored every
// dashboard-generated report twice in the templ path.
func TestGenerateNeverCallsSaveReportItself(t *testing.T) {
	spy := &reportsSpyStore{}
	deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}
	viewer := reportsViewer("app-1", "")

	for _, typ := range []string{"soc2", "hipaa", "euaiact"} {
		before := spy.saveCalls
		if _, err := reportsGenerateHandler(deps)(context.Background(), GenerateReportInput{Type: typ}, viewer); err != nil {
			t.Fatalf("generate %s: %v", typ, err)
		}
		// The engine's own save is the one expected call.
		if got := spy.saveCalls - before; got != 1 {
			t.Errorf("%s: SaveReport called %d times, want exactly the engine's own 1", typ, got)
		}
	}

	before := spy.saveCalls
	_, err := reportsGenerateCustomHandler(deps)(context.Background(), GenerateCustomReportInput{
		Title: "t", Sections: []CustomReportSection{{Title: "s"}},
	}, viewer)
	if err != nil {
		t.Fatalf("generateCustom: %v", err)
	}
	if got := spy.saveCalls - before; got != 1 {
		t.Errorf("custom: SaveReport called %d times, want exactly the engine's own 1", got)
	}
}

// The engine's inputs carry the viewer's scope, never anything from the
// request, and never empty: an empty AppID aggregates every app.
func TestGenerateHandsTheEngineTheViewersScope(t *testing.T) {
	viewer := reportsViewer("app-1", "tenant-a")

	run := func(name string, call func(Deps) error) {
		spy := &reportsSpyStore{}
		if err := call(Deps{Store: spy, Engine: reportsEngineOver(spy)}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(spy.queries) == 0 || len(spy.aggregates) == 0 {
			t.Fatalf("%s: the engine read nothing, so the test proves nothing", name)
		}
		for _, q := range spy.queries {
			if q.AppID != "app-1" || q.TenantID != "tenant-a" {
				t.Errorf("%s: section query scope = %q/%q", name, q.AppID, q.TenantID)
			}
		}
		for _, a := range spy.aggregates {
			if a.AppID != "app-1" || a.TenantID != "tenant-a" {
				t.Errorf("%s: aggregate scope = %q/%q", name, a.AppID, a.TenantID)
			}
		}
	}

	for _, typ := range []string{"soc2", "hipaa", "euaiact"} {
		run(typ, func(d Deps) error {
			_, err := reportsGenerateHandler(d)(context.Background(), GenerateReportInput{Type: typ}, viewer)
			return err
		})
	}
	run("custom", func(d Deps) error {
		_, err := reportsGenerateCustomHandler(d)(context.Background(), GenerateCustomReportInput{
			Title: "t", Sections: []CustomReportSection{{Title: "s"}},
		}, viewer)
		return err
	})
}

func TestGenerateRecordsThePrincipalsSubjectAsGeneratedBy(t *testing.T) {
	s := memory.New()
	deps := Deps{Store: s, Engine: reportsEngineOver(s)}
	p := fcontract.Principal{
		User:   &dashauth.UserInfo{Subject: "auditor-7"},
		Claims: map[string]any{"app_id": "app-1"},
	}
	out, err := reportsGenerateHandler(deps)(context.Background(), GenerateReportInput{Type: "soc2"}, p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if out.Report.GeneratedBy != "auditor-7" {
		t.Fatalf("generatedBy = %q, want auditor-7", out.Report.GeneratedBy)
	}
}

func TestGenerateDefaultsThePeriodToTheLastNinetyDays(t *testing.T) {
	spy := &reportsSpyStore{}
	deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}
	before := time.Now()
	if _, err := reportsGenerateHandler(deps)(context.Background(), GenerateReportInput{Type: "soc2"}, reportsViewer("app-1", "")); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(spy.aggregates) == 0 {
		t.Fatal("no aggregate recorded")
	}
	a := spy.aggregates[0]
	if d := a.Before.Sub(before); d < -time.Minute || d > time.Minute {
		t.Errorf("period ends %v from now, want now", d)
	}
	if got := a.Before.Sub(a.After); got < 89*24*time.Hour || got > 91*24*time.Hour {
		t.Errorf("default period = %v, want about 90 days", got)
	}
}

func TestGenerateUsesAnExplicitPeriod(t *testing.T) {
	spy := &reportsSpyStore{}
	deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}
	from, to := "2026-01-01T00:00:00Z", "2026-03-31T23:59:59Z"
	_, err := reportsGenerateHandler(deps)(context.Background(),
		GenerateReportInput{Type: "hipaa", Period: &ReportPeriod{From: from, To: to}}, reportsViewer("app-1", ""))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	a := spy.aggregates[0]
	if a.After.Format(time.RFC3339) != from || a.Before.Format(time.RFC3339) != to {
		t.Errorf("period = %v to %v, want %s to %s", a.After, a.Before, from, to)
	}
}

// Everything a caller can get wrong is refused before the engine is touched.
// The spy store sits under a real engine, so any engine work shows as a
// recorded query, aggregate or save.
func TestGenerateRefusesBadInputBeforeTheEngineIsTouched(t *testing.T) {
	good := &ReportPeriod{From: "2026-01-01T00:00:00Z", To: "2026-02-01T00:00:00Z"}
	tests := []struct {
		name string
		in   GenerateReportInput
	}{
		{"unknown type", GenerateReportInput{Type: "pci"}},
		{"empty type", GenerateReportInput{}},
		{"upper case type", GenerateReportInput{Type: "SOC2"}},
		{"mixed case type", GenerateReportInput{Type: "Hipaa"}},
		{"padded type", GenerateReportInput{Type: " soc2"}},
		{"eu_ai_act spelling", GenerateReportInput{Type: "eu_ai_act"}},
		{"malformed from", GenerateReportInput{Type: "soc2", Period: &ReportPeriod{From: "yesterday", To: good.To}}},
		{"malformed to", GenerateReportInput{Type: "soc2", Period: &ReportPeriod{From: good.From, To: "2026-13-45"}}},
		{"date without time", GenerateReportInput{Type: "soc2", Period: &ReportPeriod{From: "2026-01-01", To: "2026-02-01"}}},
		{"to before from", GenerateReportInput{Type: "soc2", Period: &ReportPeriod{From: good.To, To: good.From}}},
		{"only from", GenerateReportInput{Type: "soc2", Period: &ReportPeriod{From: good.From}}},
		{"only to", GenerateReportInput{Type: "soc2", Period: &ReportPeriod{To: good.To}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &reportsSpyStore{}
			deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}
			_, err := reportsGenerateHandler(deps)(context.Background(), tt.in, reportsViewer("app-1", ""))
			reportsWantCode(t, err, fcontract.CodeBadRequest, tt.name)
			if len(spy.queries)+len(spy.aggregates)+spy.saveCalls != 0 {
				t.Fatalf("the engine ran for a refused request")
			}
		})
	}
}

func TestGenerateCustomRefusesBadInputBeforeTheEngineIsTouched(t *testing.T) {
	sec := []CustomReportSection{{Title: "s"}}
	tooMany := make([]CustomReportSection, maxCustomReportSections+1)
	for i := range tooMany {
		tooMany[i] = CustomReportSection{Title: "s"}
	}
	tests := []struct {
		name string
		in   GenerateCustomReportInput
	}{
		{"missing title", GenerateCustomReportInput{Sections: sec}},
		{"blank title", GenerateCustomReportInput{Title: "  \t", Sections: sec}},
		{"no sections", GenerateCustomReportInput{Title: "t"}},
		{"empty sections", GenerateCustomReportInput{Title: "t", Sections: []CustomReportSection{}}},
		{"untitled section", GenerateCustomReportInput{Title: "t", Sections: []CustomReportSection{{Title: "ok"}, {Notes: "n"}}}},
		{"too many sections", GenerateCustomReportInput{Title: "t", Sections: tooMany}},
		{"bad period", GenerateCustomReportInput{Title: "t", Sections: sec, Period: &ReportPeriod{From: "x", To: "y"}}},
		{"to before from", GenerateCustomReportInput{Title: "t", Sections: sec, Period: &ReportPeriod{From: "2026-02-01T00:00:00Z", To: "2026-01-01T00:00:00Z"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &reportsSpyStore{}
			deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}
			_, err := reportsGenerateCustomHandler(deps)(context.Background(), tt.in, reportsViewer("app-1", ""))
			reportsWantCode(t, err, fcontract.CodeBadRequest, tt.name)
			if len(spy.queries)+len(spy.aggregates)+spy.saveCalls != 0 {
				t.Fatalf("the engine ran for a refused request")
			}
		})
	}
}

// A compliance report has to name who generated it. No user, or a user with
// no subject, is refused before anything runs, for both commands.
func TestGenerateRefusesAPrincipalWithNoUser(t *testing.T) {
	claims := map[string]any{"app_id": "app-1"}
	principals := map[string]fcontract.Principal{
		"nil user":      {Claims: claims},
		"empty subject": {User: &dashauth.UserInfo{Subject: ""}, Claims: claims},
	}
	for name, p := range principals {
		t.Run(name, func(t *testing.T) {
			spy := &reportsSpyStore{}
			deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}

			_, err := reportsGenerateHandler(deps)(context.Background(), GenerateReportInput{Type: "soc2"}, p)
			reportsWantCode(t, err, fcontract.CodeUnauthenticated, "generate")
			_, err = reportsGenerateCustomHandler(deps)(context.Background(), GenerateCustomReportInput{
				Title: "t", Sections: []CustomReportSection{{Title: "s"}},
			}, p)
			reportsWantCode(t, err, fcontract.CodeUnauthenticated, "generateCustom")

			if len(spy.queries)+len(spy.aggregates)+spy.saveCalls != 0 {
				t.Fatal("the engine ran for a principal with no user")
			}
		})
	}
}

func TestGenerateRefusesAPrincipalWithNoAppScope(t *testing.T) {
	spy := &reportsSpyStore{}
	deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}
	p := principalWith(map[string]any{})
	_, err := reportsGenerateHandler(deps)(context.Background(), GenerateReportInput{Type: "soc2"}, p)
	reportsWantCode(t, err, fcontract.CodePermissionDenied, "generate")
	_, err = reportsGenerateCustomHandler(deps)(context.Background(), GenerateCustomReportInput{
		Title: "t", Sections: []CustomReportSection{{Title: "s"}},
	}, p)
	reportsWantCode(t, err, fcontract.CodePermissionDenied, "generateCustom")
}

func TestGenerateAnswersUnavailableWithNoEngine(t *testing.T) {
	deps := Deps{Store: newStubStore()}
	_, err := reportsGenerateHandler(deps)(context.Background(), GenerateReportInput{Type: "soc2"}, reportsViewer("app-1", ""))
	reportsWantCode(t, err, fcontract.CodeUnavailable, "generate")
	_, err = reportsGenerateCustomHandler(deps)(context.Background(), GenerateCustomReportInput{
		Title: "t", Sections: []CustomReportSection{{Title: "s"}},
	}, reportsViewer("app-1", ""))
	reportsWantCode(t, err, fcontract.CodeUnavailable, "generateCustom")
	_, err = reportsExportHandler(Deps{Store: &reportsSpyStore{report: reportsFixture("app-1", "")}})(
		context.Background(), ExportReportInput{ID: id.NewReportID().String(), Format: "json"}, reportsViewer("app-1", ""))
	reportsWantCode(t, err, fcontract.CodeUnavailable, "export")
}

func TestGenerateMapsAStoreFailureToAnInternalErrorWithoutItsText(t *testing.T) {
	boom := errors.New("pq: relation audit_events does not exist")
	deps := Deps{Store: storeReturning(boom), Engine: reportsEngineOver(storeReturning(boom))}
	_, err := reportsGenerateHandler(deps)(context.Background(), GenerateReportInput{Type: "soc2"}, reportsViewer("app-1", ""))
	reportsWantCode(t, err, fcontract.CodeInternal, "generate")
	if strings.Contains(err.Error(), "audit_events") {
		t.Errorf("error leaks the driver text: %v", err)
	}
}

// ──────────────────────────────────────────────────
// reports.list
// ──────────────────────────────────────────────────

func TestReportListStampsTheViewersScope(t *testing.T) {
	tests := []struct {
		name             string
		viewer           fcontract.Principal
		wantApp, wantTen string
	}{
		{"tenant viewer", reportsViewer("app-1", "tenant-a"), "app-1", "tenant-a"},
		{"app-wide viewer", reportsViewer("app-1", ""), "app-1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &reportsSpyStore{}
			if _, err := reportsListHandler(Deps{Store: spy})(context.Background(), ReportListInput{}, tt.viewer); err != nil {
				t.Fatalf("reports.list: %v", err)
			}
			if len(spy.listOpts) != 1 {
				t.Fatalf("ListReports called %d times", len(spy.listOpts))
			}
			if o := spy.listOpts[0]; o.AppID != tt.wantApp || o.TenantID != tt.wantTen {
				t.Fatalf("list scope = %q/%q, want %q/%q", o.AppID, o.TenantID, tt.wantApp, tt.wantTen)
			}
		})
	}
}

// One row past the page decides HasMore, and the extra row never reaches the
// caller.
func TestReportListReportsHasMoreFromOneRowPastThePage(t *testing.T) {
	mk := func(n int) []*compliance.Report {
		out := make([]*compliance.Report, n)
		for i := range out {
			out[i] = reportsFixture("app-1", "")
		}
		return out
	}
	tests := []struct {
		name        string
		limit       int
		stored      int
		wantRows    int
		wantHasMore bool
	}{
		{"exactly a page", 3, 3, 3, false},
		{"one more than a page", 3, 4, 3, true},
		{"short page", 3, 1, 1, false},
		{"empty", 3, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy := &reportsSpyStore{list: mk(tt.stored)}
			out, err := reportsListHandler(Deps{Store: spy})(context.Background(),
				ReportListInput{Limit: tt.limit}, reportsViewer("app-1", ""))
			if err != nil {
				t.Fatalf("reports.list: %v", err)
			}
			if len(out.Reports) != tt.wantRows || out.HasMore != tt.wantHasMore {
				t.Fatalf("rows = %d hasMore = %v, want %d / %v", len(out.Reports), out.HasMore, tt.wantRows, tt.wantHasMore)
			}
			if got := spy.listOpts[0].Limit; got != tt.limit+1 {
				t.Errorf("asked the store for %d rows, want limit+1 = %d", got, tt.limit+1)
			}
		})
	}
}

func TestReportListClampsLimitAndRefusesANegativeOffset(t *testing.T) {
	for _, tt := range []struct{ in, want int }{{0, 50}, {-5, 50}, {10, 10}, {1000, 1000}, {5000, 1000}} {
		spy := &reportsSpyStore{}
		_, err := reportsListHandler(Deps{Store: spy})(context.Background(), ReportListInput{Limit: tt.in}, reportsViewer("app-1", ""))
		if err != nil {
			t.Fatalf("limit %d: %v", tt.in, err)
		}
		if got := spy.listOpts[0].Limit; got != tt.want+1 {
			t.Errorf("limit %d: store asked for %d, want %d", tt.in, got, tt.want+1)
		}
	}

	spy := &reportsSpyStore{}
	_, err := reportsListHandler(Deps{Store: spy})(context.Background(), ReportListInput{Offset: -1}, reportsViewer("app-1", ""))
	reportsWantCode(t, err, fcontract.CodeBadRequest, "negative offset")
	if len(spy.listOpts) != 0 {
		t.Error("the store was touched for a negative offset")
	}
}

func TestReportListSummariesCarryNoSectionEvents(t *testing.T) {
	spy := &reportsSpyStore{list: []*compliance.Report{reportsFixture("app-1", "")}}
	out, err := reportsListHandler(Deps{Store: spy})(context.Background(), ReportListInput{}, reportsViewer("app-1", ""))
	if err != nil {
		t.Fatalf("reports.list: %v", err)
	}
	raw, _ := json.Marshal(out)
	for _, banned := range []string{"sections", "events", "login", "matchedEvents"} {
		if bytes.Contains(raw, []byte(banned)) {
			t.Errorf("list response contains %q: %s", banned, raw)
		}
	}
	if out.Reports[0].Stats == nil || out.Reports[0].Stats.TotalEvents != 3 {
		t.Errorf("summary stats = %+v", out.Reports[0].Stats)
	}
}

// A store that answers outside the viewer's scope is a bug to surface, not
// evidence to hand on.
func TestReportListRefusesAStoreRowOutsideTheViewersScope(t *testing.T) {
	spy := &reportsSpyStore{list: []*compliance.Report{reportsFixture("app-2", "")}}
	_, err := reportsListHandler(Deps{Store: spy})(context.Background(), ReportListInput{}, reportsViewer("app-1", ""))
	reportsWantCode(t, err, fcontract.CodeInternal, "out of scope row")
}

// ──────────────────────────────────────────────────
// reports.detail
// ──────────────────────────────────────────────────

func TestReportDetailProjectsSectionsWithTheirEvidence(t *testing.T) {
	r := reportsFixture("app-1", "")
	out, err := reportsDetailHandler(Deps{Store: &reportsSpyStore{report: r}})(
		context.Background(), GetReportInput{ID: r.ID.String()}, reportsViewer("app-1", ""))
	if err != nil {
		t.Fatalf("reports.detail: %v", err)
	}
	if out.ID != r.ID.String() || len(out.Sections) != 1 {
		t.Fatalf("detail = %+v", out)
	}
	sec := out.Sections[0]
	if len(sec.Events) != 1 || sec.Events[0].Action != "login" {
		t.Errorf("events = %+v", sec.Events)
	}
	if sec.MatchedEvents != 5 || !sec.EventsTruncated {
		t.Errorf("matched = %d truncated = %v, want 5 / true: a truncated sample must say so", sec.MatchedEvents, sec.EventsTruncated)
	}
	if sec.Stats == nil || sec.Stats.Total != 5 || len(sec.Stats.Groups) != 1 {
		t.Errorf("section stats = %+v", sec.Stats)
	}
}

// A report with no verification projects to null, and stays null. It is not
// coerced into a passing or an empty verification.
func TestReportDetailLeavesVerificationNullWhenTheReportHasNone(t *testing.T) {
	r := reportsFixture("app-1", "")
	out, err := reportsDetailHandler(Deps{Store: &reportsSpyStore{report: r}})(
		context.Background(), GetReportInput{ID: r.ID.String()}, reportsViewer("app-1", ""))
	if err != nil {
		t.Fatalf("reports.detail: %v", err)
	}
	if out.Verification != nil {
		t.Fatalf("verification = %+v, want nil", out.Verification)
	}
	raw, _ := json.Marshal(out)
	if bytes.Contains(raw, []byte(`"verification"`)) {
		t.Errorf("a null verification crossed the wire: %s", raw)
	}
}

// When a report does carry a verification, it crosses in verify.run's own
// shape, with each checked flag intact, so the page can draw the same three
// states.
func TestReportDetailProjectsAnEmbeddedVerificationThroughTheVerifyProjection(t *testing.T) {
	r := reportsFixture("app-1", "")
	r.Verification = &verify.Report{
		Valid:       true,
		Verified:    7,
		HeadChecked: true,
		Tampered:    []uint64{4},
		Coverage:    []verify.Coverage{{FromSeq: 1, ToSeq: 7, Level: verify.LevelUnkeyed}},
	}
	out, err := reportsDetailHandler(Deps{Store: &reportsSpyStore{report: r}})(
		context.Background(), GetReportInput{ID: r.ID.String()}, reportsViewer("app-1", ""))
	if err != nil {
		t.Fatalf("reports.detail: %v", err)
	}
	if out.Verification == nil {
		t.Fatal("the embedded verification was dropped")
	}
	want := projectReport(r.Verification)
	got, _ := json.Marshal(out.Verification)
	exp, _ := json.Marshal(want)
	if !bytes.Equal(got, exp) {
		t.Errorf("verification = %s, want %s", got, exp)
	}
	if !out.Verification.HeadChecked || out.Verification.CheckpointsChecked || len(out.Verification.Tampered) != 1 {
		t.Errorf("the checked flags or findings did not survive: %+v", out.Verification)
	}
}

// The store is never touched for an ID that does not parse, and the answer
// is the same as for a real miss.
func TestReportDetailAndExportRefuseAnUnparseableIDWithoutTouchingTheStore(t *testing.T) {
	for _, bad := range []string{"", "rpt_1", "not-an-id", id.NewAuditID().String()} {
		spy := &reportsSpyStore{report: reportsFixture("app-1", "")}
		deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}

		_, err := reportsDetailHandler(deps)(context.Background(), GetReportInput{ID: bad}, reportsViewer("app-1", ""))
		reportsWantCode(t, err, fcontract.CodeNotFound, "detail "+bad)
		_, err = reportsExportHandler(deps)(context.Background(), ExportReportInput{ID: bad, Format: "json"}, reportsViewer("app-1", ""))
		reportsWantCode(t, err, fcontract.CodeNotFound, "export "+bad)

		if spy.getCalls != 0 {
			t.Errorf("id %q reached the store", bad)
		}
	}
}

func TestReportDetailAnswersNotFoundForAMissingReport(t *testing.T) {
	spy := &reportsSpyStore{} // GetReport answers ErrReportNotFound
	_, err := reportsDetailHandler(Deps{Store: spy})(context.Background(),
		GetReportInput{ID: id.NewReportID().String()}, reportsViewer("app-1", ""))
	reportsWantCode(t, err, fcontract.CodeNotFound, "missing report")
}

// The viewer's own report is served, for a tenant viewer and an app-wide
// viewer alike. This is the half of the ownership tests that fails when the
// arguments to owns are swapped.
func TestReportDetailAndExportServeTheViewersOwnReport(t *testing.T) {
	tests := []struct {
		name        string
		viewer      fcontract.Principal
		app, tenant string
	}{
		{"tenant viewer, own tenant's report", reportsViewer("app-1", "tenant-a"), "app-1", "tenant-a"},
		{"app-wide viewer, a tenant's report in its app", reportsViewer("app-1", ""), "app-1", "tenant-b"},
		{"app-wide viewer, an app-level report", reportsViewer("app-1", ""), "app-1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := reportsFixture(tt.app, tt.tenant)
			spy := &reportsSpyStore{report: r}
			deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}
			if _, err := reportsDetailHandler(deps)(context.Background(), GetReportInput{ID: r.ID.String()}, tt.viewer); err != nil {
				t.Errorf("detail refused the viewer's own report: %v", err)
			}
			if _, err := reportsExportHandler(deps)(context.Background(), ExportReportInput{ID: r.ID.String(), Format: "csv"}, tt.viewer); err != nil {
				t.Errorf("export refused the viewer's own report: %v", err)
			}
		})
	}
}

// Ownership on detail and export, with real IDs so the check is reached. Each
// case is a report the viewer must not see: another tenant's in the same app,
// another app's, and (for a tenant viewer) the app's own tenantless one.
func TestReportDetailAndExportRefuseAReportTheViewerDoesNotOwn(t *testing.T) {
	tests := []struct {
		name        string
		viewer      fcontract.Principal
		app, tenant string
	}{
		{"same app, other tenant", reportsViewer("app-1", "tenant-a"), "app-1", "tenant-b"},
		{"other app, same tenant name", reportsViewer("app-1", "tenant-a"), "app-2", "tenant-a"},
		{"other app, no tenant", reportsViewer("app-1", ""), "app-2", ""},
		{"other app, app-wide viewer, tenant report", reportsViewer("app-1", ""), "app-2", "tenant-a"},
		{"tenant viewer, app-level report", reportsViewer("app-1", "tenant-a"), "app-1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := reportsFixture(tt.app, tt.tenant)
			spy := &reportsSpyStore{report: r}
			deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}

			detail, err := reportsDetailHandler(deps)(context.Background(), GetReportInput{ID: r.ID.String()}, tt.viewer)
			reportsWantCode(t, err, fcontract.CodeNotFound, "detail")
			if len(detail.Sections) != 0 || detail.ID != "" {
				t.Errorf("a refused detail still returned content: %+v", detail)
			}

			out, err := reportsExportHandler(deps)(context.Background(), ExportReportInput{ID: r.ID.String(), Format: "json"}, tt.viewer)
			reportsWantCode(t, err, fcontract.CodeNotFound, "export")
			if out.Content != "" || out.Filename != "" {
				t.Errorf("a refused export still rendered content: %+v", out)
			}
		})
	}
}

// ──────────────────────────────────────────────────
// reports.export
// ──────────────────────────────────────────────────

func TestReportExportRefusesAnUnknownFormatBeforeFetching(t *testing.T) {
	for _, format := range []string{"pdf", "", "JSON", "Csv", "md", "xml", " json"} {
		spy := &reportsSpyStore{report: reportsFixture("app-1", "")}
		deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}
		_, err := reportsExportHandler(deps)(context.Background(),
			ExportReportInput{ID: id.NewReportID().String(), Format: format}, reportsViewer("app-1", ""))
		reportsWantCode(t, err, fcontract.CodeBadRequest, "format "+format)
		if spy.getCalls != 0 {
			t.Errorf("format %q reached the store", format)
		}
	}
}

func TestReportExportRendersEachFormat(t *testing.T) {
	r := reportsFixture("app-1", "")
	spy := &reportsSpyStore{report: r}
	deps := Deps{Store: spy, Engine: reportsEngineOver(spy)}

	tests := []struct {
		format, ext, contentType, marker string
	}{
		{"json", "json", "application/json", `"title"`},
		{"csv", "csv", "text/csv", "section,timestamp,action"},
		{"markdown", "md", "text/markdown", "# SOC2 Type II Compliance Report"},
		{"html", "html", "text/html", "<!DOCTYPE html>"},
	}
	for _, tt := range tests {
		out, err := reportsExportHandler(deps)(context.Background(),
			ExportReportInput{ID: r.ID.String(), Format: tt.format}, reportsViewer("app-1", ""))
		if err != nil {
			t.Fatalf("export %s: %v", tt.format, err)
		}
		if want := "report-" + r.ID.String() + "." + tt.ext; out.Filename != want {
			t.Errorf("%s filename = %q, want %q", tt.format, out.Filename, want)
		}
		if !strings.HasPrefix(out.ContentType, tt.contentType) {
			t.Errorf("%s content type = %q", tt.format, out.ContentType)
		}
		if !strings.Contains(out.Content, tt.marker) {
			t.Errorf("%s content lacks %q", tt.format, tt.marker)
		}
	}
}

// The filename never comes from the report's title, which a custom report's
// author chooses.
func TestReportExportFilenameIgnoresTheTitle(t *testing.T) {
	r := reportsFixture("app-1", "")
	r.Title = "../../etc/passwd\r\nX-Injected: 1"
	spy := &reportsSpyStore{report: r}
	out, err := reportsExportHandler(Deps{Store: spy, Engine: reportsEngineOver(spy)})(context.Background(),
		ExportReportInput{ID: r.ID.String(), Format: "json"}, reportsViewer("app-1", ""))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if strings.ContainsAny(out.Filename, "/\\\r\n ") || strings.Contains(out.Filename, "passwd") {
		t.Errorf("filename = %q", out.Filename)
	}
}

// The HTML export is html/template output. A title or event field carrying
// markup must arrive escaped.
func TestReportExportHTMLEscapesReportContent(t *testing.T) {
	r := reportsFixture("app-1", "")
	r.Title = `<script>alert("title")</script>`
	r.Sections[0].Events[0].Action = `<img src=x onerror=alert(1)>`
	spy := &reportsSpyStore{report: r}
	out, err := reportsExportHandler(Deps{Store: spy, Engine: reportsEngineOver(spy)})(context.Background(),
		ExportReportInput{ID: r.ID.String(), Format: "html"}, reportsViewer("app-1", ""))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	for _, raw := range []string{`<script>alert(`, `<img src=x`} {
		if strings.Contains(out.Content, raw) {
			t.Errorf("html export carries unescaped %q", raw)
		}
	}
	if !strings.Contains(out.Content, "&lt;script&gt;") {
		t.Error("the escaped title is missing")
	}
}

// ──────────────────────────────────────────────────
// Registration
// ──────────────────────────────────────────────────

func TestReportsRegistrationsDeclareTheFiveIntentsWithTheRightKinds(t *testing.T) {
	want := map[string]intentKind{
		"reports.list":           kindQuery,
		"reports.detail":         kindQuery,
		"reports.generate":       kindCommand,
		"reports.generateCustom": kindCommand,
		"reports.export":         kindQuery,
	}
	got := map[string]intentKind{}
	for _, r := range reportsRegistrations() {
		got[r.name] = r.kind
	}
	if len(got) != len(want) {
		t.Fatalf("registered %v", got)
	}
	for name, kind := range want {
		if got[name] != kind {
			t.Errorf("%s registered as %q, want %q", name, got[name], kind)
		}
	}
}

// ──────────────────────────────────────────────────
// reports.export ordering around ownership
// ──────────────────────────────────────────────────

// reportsUnexportable is a report the JSON export cannot encode: a channel in
// an event's metadata makes json.Encoder fail. Export therefore fails for it
// exactly when it is reached.
func reportsUnexportable(app, tenant string) *compliance.Report {
	r := reportsFixture(app, tenant)
	r.Sections[0].Events[0].Metadata = map[string]any{"unencodable": make(chan int)}
	return r
}

// Ownership is decided before Export runs. A report the viewer does not own
// must never be rendered, and if rendering it fails the caller must still see
// NOT_FOUND: INTERNAL there would tell a prober the ID names a real report in
// another tenant. Export reaches this report only if the check runs late, and
// then it fails, so the two answers tell the orderings apart.
func TestReportExportNeverReachesExportForAReportTheViewerDoesNotOwn(t *testing.T) {
	viewer := reportsViewer("app-1", "tenant-a")

	// Control: the same unencodable report, owned, does reach Export and
	// fails there. Without this the foreign case below could pass because
	// Export was never going to fail.
	own := reportsUnexportable("app-1", "tenant-a")
	ownSpy := &reportsSpyStore{report: own}
	_, err := reportsExportHandler(Deps{Store: ownSpy, Engine: reportsEngineOver(ownSpy)})(
		context.Background(), ExportReportInput{ID: own.ID.String(), Format: "json"}, viewer)
	reportsWantCode(t, err, fcontract.CodeInternal, "owned unencodable report")

	for name, foreign := range map[string]*compliance.Report{
		"other tenant": reportsUnexportable("app-1", "tenant-b"),
		"other app":    reportsUnexportable("app-2", "tenant-a"),
	} {
		spy := &reportsSpyStore{report: foreign}
		out, err := reportsExportHandler(Deps{Store: spy, Engine: reportsEngineOver(spy)})(
			context.Background(), ExportReportInput{ID: foreign.ID.String(), Format: "json"}, viewer)
		reportsWantCode(t, err, fcontract.CodeNotFound, name+": foreign report whose export would fail")
		if out.Content != "" {
			t.Errorf("%s: rendered content for a foreign report", name)
		}
	}
}

// With no engine configured, a foreign report ID must answer exactly as a
// missing one does. UNAVAILABLE for a foreign ID and NOT_FOUND for a missing
// one would let a caller tell them apart.
func TestReportExportAnswersNotFoundBeforeUnavailableForAForeignReport(t *testing.T) {
	viewer := reportsViewer("app-1", "tenant-a")

	// Control: the viewer's own report with no engine is UNAVAILABLE.
	own := reportsFixture("app-1", "tenant-a")
	_, err := reportsExportHandler(Deps{Store: &reportsSpyStore{report: own}})(
		context.Background(), ExportReportInput{ID: own.ID.String(), Format: "json"}, viewer)
	reportsWantCode(t, err, fcontract.CodeUnavailable, "owned report, no engine")

	foreign := reportsFixture("app-2", "tenant-a")
	_, err = reportsExportHandler(Deps{Store: &reportsSpyStore{report: foreign}})(
		context.Background(), ExportReportInput{ID: foreign.ID.String(), Format: "json"}, viewer)
	reportsWantCode(t, err, fcontract.CodeNotFound, "foreign report, no engine")

	// And a report that does not exist at all answers the same.
	_, err = reportsExportHandler(Deps{Store: &reportsSpyStore{}})(
		context.Background(), ExportReportInput{ID: id.NewReportID().String(), Format: "json"}, viewer)
	reportsWantCode(t, err, fcontract.CodeNotFound, "missing report, no engine")
}
