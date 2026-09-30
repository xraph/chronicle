# Moving off the templ dashboard

Chronicle's server-rendered dashboard, the `dashboard/` package, is gone. A React plugin replaced it. This file is the only record of what the templ pages showed and did, written while they could still be opened, so every page, column, action, filter, badge and empty state has a line here.

If you are upgrading, read the next two sections and skip the rest. If you are checking that nothing was lost, the tables are for you.

## What to do when you upgrade

### Mount the React plugin

The plugin lives in the forge-dashboard repo as `@forge-go/dashboard-plugin-chronicle`. Add it to the plugins list in your forge dashboard shell (`apps/shell/src/App.tsx` in forge-dashboard):

```tsx
import chroniclePlugin from "@forge-go/dashboard-plugin-chronicle"

const plugins = [
  corePlugin,
  // ...your other plugins
  chroniclePlugin,
]
```

Order in the array is the order in the nav. The Go side needs nothing from you: forge's dashboard picks up the chronicle extension's contract (29 intents, contributor name `chronicle`) automatically when both extensions are registered. forge v1.11.1 is the version this was built and tested against, not a stated minimum. You do not call anything.

### Three things that changed under you

`dashboard_mutations` no longer does anything. The YAML key still loads and `extension.WithDashboardMutations()` still compiles, so nothing breaks, but both are deprecated no-ops and will be removed in a later release. The old flag existed because templ pages rendered through a route chronicle could not authenticate. The contract path has a signed-in user and scopes, so the flag has nothing left to guard. Delete it from your config when you get a chance.

Writes are governed by scopes on the signed-in user, matched as the bare names `chronicle.write` and `chronicle.admin`:

| Needs | Intents |
|---|---|
| Any signed-in user with a resolvable app | every read: lists, details, verify, preview, export, settings |
| `chronicle.write` or `chronicle.admin` | `checkpoints.take`, `reports.generate`, `reports.generateCustom` |
| `chronicle.admin` | `retention.savePolicy`, `retention.deletePolicy`, `retention.enforce`, `erasures.request` |

Before, one switch covered creating policies, deleting them, enforcing and generating reports. Now the three retention commands (and the erasure request) each need `chronicle.admin` on its own. Nobody is an admin because they hold some other admin role, and a tenant session with no scope sees every page and can change nothing. `erasures.request` also answers "unavailable" unless crypto-erasure is on.

The dashboard's app and tenant come from session claims, and never from the request. `app_id` gives the app. `tenant_id`, or `org_id` if there is no `tenant_id`, gives the tenant. A session with no app is refused, where templ treated no scope at all as "show everything". Two more rules bite people:

- A session whose claims give an app and no tenant is an app-wide view, and needs `chronicle.admin`. Anyone else is refused.
- If your auth provider does not fill claims in yet, a single-app deployment names its app in config instead:

```yaml
chronicle:
  dashboard:
    app_id: my-app          # chronicle.dashboard.app_id
    tenant_id: my-tenant    # optional; chronicle.dashboard.tenant_id
```

The README's Dashboard section has the full rules for when the configured values apply and when a claim wins.

### If you import the package

`github.com/xraph/chronicle/dashboard` (and its `pages`, `components` and `widgets` subpackages) no longer exist. The extension's `DashboardContributor()` went with it. Drop the import. Nothing else in the module depended on it. The package is removed in the first chronicle release after v1.6.4.

### Old links

Templ routes do not carry over, and neither do their query strings (`?severity=critical`, `?category=auth`, `?id=...`). The table under "Route map" lists where each one went. Events filters live in page state and are not in the URL, so a filtered events page cannot be bookmarked.

## How to read the tables

Every templ item has an ID made from its file, so the rows can be checked against the files on the `main` history before this change. Status is one of three phrases:

- Migrated: the React plugin does it. The last column names the page or component and route, and says so when the behaviour changed.
- Dropped: deliberately left out. The last column gives the reason.
- Blocked: it needs Go work first. The last column says what.

Routes below are plugin routes, under the `chronicle` namespace. Intent names (`events.list`) are the contract's.

---

## Pages

### overview.templ (OV)

The landing page at `/`. React has no overview page. Its counts moved to Activity and its two recent lists are the Events page.

| ID | Templ item | Status | Now |
|---|---|---|---|
| OV-1 | Page title "Overview", subtitle "Monitor your immutable audit trail at a glance.", and being the landing page | Dropped | The landing page is Chain (`/`, `/chain`), because this library's job is to prove a record was not altered and that comes first. Nothing replaces the title. |
| OV-2 | Tile "Total Events", "All recorded events" | Migrated | Activity (`/activity`), tile "Total events", from `overview.stats`. |
| OV-3 | Tile "Critical Events", "Last 30 days" | Migrated | Activity, tile "Critical", with an "All time" hint. Changed: it counts every critical event in your scope (all time), not the last 30 days. Volume over time is on the same page. See "Numbers that mean something different". |
| OV-4 | Tile "Failed / Denied", "Last 30 days" | Migrated | Activity, tile "Failed or denied", with a hint that says "All time" and splits the two. Changed: all time (your whole scope), not 30 days. The page adds `failedEvents` (failure only) to `deniedEvents`. |
| OV-5 | Tile "Erasures", "GDPR erasure requests" | Migrated | Activity, tile "Erasures". |
| OV-6 | Card "Recent Events", "The last 10 audit events recorded." | Migrated | Events (`/events`), newest first. Changed: no fixed 10-row card, it is the whole log at 50 a page. |
| OV-7 | Empty state "No events yet" / "Audit events will appear here once they are recorded." | Migrated | Events: "This chain holds no events yet." |
| OV-8 | Card "Recent Critical Events", "The last 10 critical severity events." | Migrated | Events with the Severity filter set to `critical`. |
| OV-9 | Empty state "No critical events" / "Critical events will appear here when they are recorded." | Migrated | Events: "No events match these filters", with the filter echoed and a "Clear filters" button. |
| OV-10 | Clicking a row opens the event | Migrated | The Action cell links to `/events/:id`. The whole row is not clickable. |

### events.templ (EV)

| ID | Templ item | Status | Now |
|---|---|---|---|
| EV-1 | Title "Events", subtitle "Browse and filter the immutable audit trail." | Migrated | Events page header. |
| EV-2 | Badge "N total" | Migrated | Table caption, "50 of 1,204 events". The total is the count matching your filters. |
| EV-3 | Severity filter: buttons All, Info, Warning, Critical | Migrated | Severity select: Any, info, warning, critical. Changed: a select, and it combines with every other filter. |
| EV-4 | Outcome filter: buttons All, Success, Failed, Denied | Migrated | Outcome select: Any, success, failure, denied. Changed: the "Failed" button is `failure`. |
| EV-5 | Category filter, reachable only by typing `?category=` | Migrated | "Categories" text field, comma separated, now a real control. |
| EV-6 | Selected filter button drawn filled, the others outlined | Migrated | The selects show their value. With filters applied, a "Reset filters" button appears. |
| EV-7 | Clicking any filter button dropped the other filters | Migrated | Closed quirk. Filters apply together on "Apply filters". |
| EV-8 | Fixed `Limit: 50`, no way to page | Migrated | Paged 50 at a time, offset paging, page control under the table. |
| EV-9 | Table of events | Migrated | See EVT below. |
| EV-10 | Empty state "No events found" / "Adjust your filters or wait for new audit events to be recorded." | Migrated | "No events match these filters" with the filters listed and "Clear filters", or "This chain holds no events yet." with none applied. A page past the end says "No events on this page." and offers "Back to the first page". |
| EV-11 | A failed query rendered as an empty table with a total of 0 | Migrated | Changed: the error shows, it is not read as "no events". |

### event_detail.templ (ED)

Route `/events/:id`. The page loads lazily, because the JSON viewer is CodeMirror.

| ID | Templ item | Status | Now |
|---|---|---|---|
| ED-1 | Title "Event Detail" and the event ID in a code tag | Migrated | Title "Event", ID in the "Event" row. |
| ED-2 | "Back" button to the list | Migrated | Closed in forge-dashboard 62fbbce. A "Back to events" link sits at the foot of the event page, not the top. It renders outside the page's loading and error boundary, so it shows even when the event can't be read. |
| ED-3 | Card title "{Action} on {Resource}", description "Recorded {time ago}" | Migrated | "Action", "Resource" and "Time" rows. The time is the kit's timestamp component. |
| ED-4 | Fields Action, Resource, Category | Migrated | Same rows. |
| ED-5 | Resource ID, shown only when set | Migrated | Beside Resource. |
| ED-6 | Severity badge | Migrated | See SB. |
| ED-7 | Outcome badge | Migrated | See SB. |
| ED-8 | Reason, shown only when set | Migrated | "Reason" row, "None" when empty. |
| ED-9 | Timestamp as `2006-01-02 15:04:05 UTC` | Migrated | "Time" row, the kit's formatting. |
| ED-10 | Sequence, shown in both the identity card and the hash chain card | Migrated | Once, in the side column, formatted with separators. |
| ED-11 | Scope card "Scope" / "Multi-tenant context for this event.": App ID | Dropped | Not shown. The App ID is always your own app, and `events.detail` does not send it. |
| ED-12 | Scope card: Tenant ID, shown only when set | Blocked | Not shown. An app-wide operator reads events from many tenants and cannot tell which one. Needs `tenantId` added to `EventDetail` (and `EventSummary` for the table) in `extension/contract`, then the plugin's `types.ts`. |
| ED-13 | Scope card: User ID, shown only when set | Migrated | "User" row, now a link to `/users/:userId`. |
| ED-14 | Scope card: IP Address, shown only when set | Migrated | "IP address" row. |
| ED-15 | Hash Chain card "Hash Chain" / "Immutable hash chain linking for tamper detection." and its Stream ID | Migrated | Side column, "Chain" row. |
| ED-16 | Hash, in a select-all code block | Migrated | "Hash" row, monospace, full value. |
| ED-17 | Previous Hash | Migrated | "Previous hash" row. |
| ED-18 | Text "Genesis event (no previous hash)" on the first event | Migrated | Closed in forge-dashboard 62fbbce. Changed: templ said "Genesis event" whenever the previous hash was empty. The plugin says it for sequence 1 only. A later event with no previous hash is flagged instead ("None recorded. Only a chain's first event has no previous hash") and is not called genesis. |
| ED-19 | GDPR Status card, shown when the event has a subject or was erased | Migrated | Changed: the "Subject" row is always there ("None" when empty), and the erasure details sit in the side column when the event is erased. |
| ED-20 | GDPR: Subject ID | Migrated | "Subject" row. |
| ED-21 | GDPR: Encryption Key ID | Blocked | Not shown. Needs `encryptionKeyId` added to `EventDetail`. (The "Key id" row in React is the digest key, a different thing.) |
| ED-22 | GDPR: Status badge, "Erased" or "Active" | Migrated | Changed: the "Erased" badge, Erased At and the erasure link show only when the event is erased and names an erasure. Templ showed them for any erased event. Nothing appears otherwise, and there is no "Active" badge. |
| ED-23 | GDPR: Erased At | Migrated | Side column, under the badge. |
| ED-24 | GDPR: Erasure ID | Migrated | "Erased by" link to `/erasures/:id`. |
| ED-25 | Metadata card "Metadata" / "Custom fields attached to this event.", pretty-printed JSON | Migrated | "Metadata" heading and a folding, searchable JSON viewer. |
| ED-26 | Metadata card hidden when there is none | Migrated | "None" cell. On an erased event with no metadata it says the metadata went with the erased fields. |
| ED-27 | Opening an event by ID checked the viewer owned it; a tenant viewer could open app-level events (fixed on main in d1b8957) | Migrated | `events.detail` answers not-found unless the record is yours. A tenant viewer owns only records carrying its own tenant, and an app-wide viewer owns everything in its app. |

### verify.templ (VF)

The templ page is called Verification and sits at `/verify`. The React page is Chain.

| ID | Templ item | Status | Now |
|---|---|---|---|
| VF-1 | Title "Hash Chain Verification", subtitle "Verify the integrity of the immutable audit trail hash chain." | Migrated | Chain page header: "The hash chain your audit events are recorded in, and whether it has been altered." |
| VF-2 | Form card "Verify Chain Integrity" / "Enter a stream ID and sequence range to verify hash chain integrity." | Migrated | The chain posture block plus a range form. See the rows below. |
| VF-3 | "Stream ID" field (placeholder `stream_01h2x...`) | Migrated | Changed: there is no field, you do not paste an ID. Your chain resolves from your scope (`streams.mine`). An app-wide operator gets a "Chain" picker, from `streams.list`, to choose a tenant's chain. |
| VF-4 | "From Sequence" field | Migrated | "From sequence". |
| VF-5 | "To Sequence" field | Migrated | "To sequence". It refuses a number past the head and says where the head is. |
| VF-6 | "Verify Chain" button, empty range meaning the whole chain | Migrated | Changed: two buttons. "Check this range" runs what is typed, and starts on the latest 10,000 sequences. "Check the whole chain" is explicit and disabled above the 100,000 sequence cap the server enforces. Nothing runs until you press one, unless you followed a deep link. |
| VF-7 | Error "Stream ID is required" | Dropped | There is no stream ID field. |
| VF-8 | Error "Invalid Stream ID format" | Dropped | Same. |
| VF-9 | Errors "Invalid From Sequence number" and "Invalid To Sequence number" | Migrated | The button is disabled until both fields are whole numbers. |
| VF-10 | Error "Stream not found" when the stream was not yours | Migrated | A chain ID that is not yours answers not-found from `verify.run` and shows as "The chain could not be checked". |
| VF-11 | Error "Verification failed: ..." | Migrated | "The chain could not be checked", with the server's code and message. A bad-request answer offers "Check the most recent 10,000 instead". |
| VF-12 | Card "Verification Result", shown only after a run | Migrated | The certificate: verdict, limits, where, what was found, what was examined, coverage. |
| VF-13 | Tile "Status": Valid or Tampered | Migrated | Changed: a verdict sentence, never a bare "Valid". An unkeyed pass reads "No corruption detected in sequences 1 to 12,431" followed by what that method cannot see. |
| VF-14 | Tile "Verified", "events checked" | Migrated | "What was examined": "N events read, sequences a to b." |
| VF-15 | Tile "Range", "sequence range" | Migrated | The verdict names the range, and the "Where" ribbon draws it. |
| VF-16 | Tile "Issues", "gaps + tampered + downgrades" | Dropped | One number hid the kind. The verdict counts each kind ("3 missing, 1 altered") and the "What was found" table lists every break with its position. |
| VF-17 | "Chain Status" badge, Valid or Tampered | Migrated | The verdict, in the failure colour when there are breaks. A failed result outranks everything else on the page. |
| VF-18 | "Sequence Gaps" list | Migrated | "What was found", rows titled "Sequences 40 to 42 missing", consecutive runs merged. |
| VF-19 | "Removed by Retention" list with its explanation | Migrated | "Removed by retention" section, plus a verdict sentence saying the chain links across the range and what the events said is gone. Retained ranges are never counted as breaks. |
| VF-20 | Backfilled range label, "1 (record 7, backfilled from s3://...)" (added on main in e5df302) | Migrated | "recorded at sequence 7 under {policy}, recovered from {archive}", and the verdict says the record was recovered afterwards. |
| VF-21 | "Scheme Downgrades" panel and its advice to investigate who can write the events table | Migrated | Rows titled "Sequence N relabelled", explained as a weaker scheme than the chain required. The advice about who holds write access is on the relabelled break itself. See VF-30. |
| VF-22 | "Truncated Tail" panel, shown when a signed checkpoint reaches past the head | Migrated | A break titled "A signed checkpoint contradicts the head", and the verdict says so. The advice that went with it, about who holds write access, is on that break too. See VF-30. |
| VF-23 | "Tampered Events" list | Migrated | Rows titled "Sequence N altered". |
| VF-24 | "Resolved Tolerantly" panel, with the sequence numbers | Migrated | Closed in forge-dashboard 62fbbce. The verdict sentence still gives the count ("3 events recorded no digest scheme"), and a "Scheme inferred" section on the certificate now lists the tolerant sequences, merged into runs. A run that is also altered is marked. |
| VF-25 | "Coverage" list, `from-to: level` and its note | Migrated | "Coverage" section (level badge, range, note) and the coloured bands on the "Where" ribbon. |
| VF-26 | Checkpoints: a failed checkpoint in a red box, with its note | Migrated | Closed in forge-dashboard 62fbbce. Changed: each checkpoint has Signature, Hash and Continuity rows, and the note sits on the first row that did not hold, in the verifier's order (signature, hash, continuity). On a failed row it sits beside the destructive badge. On a row that was not checked it reads "Not checked." followed by the note. There is no red box. |
| VF-27 | Checkpoints: "not fully checked" in a grey box, with its note | Migrated | The unchecked row is plain muted text, "Not checked", with the note appended. |
| VF-28 | Checkpoints: "signed and intact" | Migrated | Held rows in an outline badge. |
| VF-29 | Nothing rendered until you submitted the form | Migrated | The chain's posture (head, hash, scheme, latest checkpoint, the best level it can reach) shows on load. Nothing is verified until you ask. |
| VF-30 | The advice on the "Truncated Tail" panel ("find out who holds write access to the events and streams tables") and on "Scheme Downgrades" ("treat it as tampering and investigate who has write access to the events table") | Migrated | Closed in forge-dashboard 62fbbce. The relabelled break says "Treat it as tampering, and find out who has write access to the events table". Both head breaks carry the advice too, the head mismatch and "A signed checkpoint contradicts the head", ending "the events and streams tables". |
| VF-31 | Placeholders in the sequence fields, "1" and "100" | Dropped | The From and To fields start filled with the default window, the latest 10,000 sequences, so there is nothing to hint at. |

### reports.templ (RP)

| ID | Templ item | Status | Now |
|---|---|---|---|
| RP-1 | Title "Compliance Reports", subtitle "Generate and manage SOC2, HIPAA, and EU AI Act compliance reports." | Migrated | Reports (`/reports`), "Reports". |
| RP-2 | Badge "N reports" | Migrated | Caption "N reports shown". |
| RP-3 | Button "Generate SOC2" | Migrated | "Generate a report" (`/new-report`), type "SOC 2". Changed: a form. The period is optional and blank means the last 90 days, which is what the button always did. |
| RP-4 | Button "Generate HIPAA" | Migrated | Same form, type "HIPAA". |
| RP-5 | Button "Generate EU AI Act" | Migrated | Same form, type "EU AI Act". |
| RP-6 | Generation fired from a GET link, reported as generated by the literal string "dashboard" | Migrated | A command, `reports.generate`. Changed: `generatedBy` is the signed-in user. |
| RP-7 | Error card "Report generation failed: ..." | Migrated | "Could not generate the report", with code and message. |
| RP-8 | Read-only message when mutations were off | Dropped | The flag is gone. See "What to do when you upgrade". |
| RP-9 | Table of reports | Migrated | See RPT below. |
| RP-10 | Empty state "No reports yet" / "Generate your first compliance report using the buttons above." | Migrated | "No reports have been generated in this scope." |
| RP-11 | First 50 reports, no paging | Migrated | Previous and Next page buttons. |
| RP-12 | Report scoped to the viewer's app and tenant (an earlier templ bug saved reports under an empty scope) | Migrated | Scope comes from the Principal. |

### report_detail.templ (RD)

Route `/reports/:id`.

| ID | Templ item | Status | Now |
|---|---|---|---|
| RD-1 | Title is the report's title; ID in a code tag; "Back" button | Migrated | Title and "Report" row. A "Back to reports" link sits at the foot. |
| RD-2 | Card "Report Details", "Generated {time ago}" | Migrated | "Generated" row. |
| RD-3 | Type badge | Migrated | "Type" row as text: SOC 2, HIPAA, EU AI Act, Custom. |
| RD-4 | Period, `Jan 02, 2006 - Jan 02, 2006` | Migrated | "Period" row. |
| RD-5 | App ID | Dropped | Not shown. It is always your own app. |
| RD-6 | Tenant ID, shown only when set | Blocked | Not shown. Needs `tenantId` added to `ReportSummary` in `extension/contract`, and to the plugin's `types.ts`. |
| RD-7 | Generated By | Migrated | "Generated by" row. |
| RD-8 | Format | Dropped | The stored format no longer matters: you choose a format when you download. |
| RD-9 | Stats tiles: Total Events, Critical, Failed, Denied, only when the report has stats | Migrated | Same four tiles. |
| RD-10 | Card "Chain Verification": Status badge and "Verified Events" | Migrated | Changed: an "Integrity" section that is never omitted. It shows the full certificate, what range the verification covered, and the engine's own notes. A report with no verification says so. |
| RD-11 | Card "Report Sections" / "Detailed breakdown of the compliance report.": title, notes, "N events in this section" | Migrated | Each section is a heading, its notes, and a table of its events with "N of M matching events". When a section was cut short it says "Showing N of M matching events." |
| RD-12 | Card "Export Report" / "Download the report in your preferred format.": JSON, CSV, Markdown, HTML | Migrated | Four "Download ..." buttons. Changed: they used to be links to the REST endpoint `/chronicle/v1/reports/:id/export/:format`, hard-coded to the default base path. Now they go through `reports.export` and save a file from the browser. The REST endpoint is still there. |
| RD-13 | Report opened by ID checked ownership | Migrated | `reports.detail` answers not-found for a record that is not yours. |

### erasures.templ (ER)

| ID | Templ item | Status | Now |
|---|---|---|---|
| ER-1 | Title "GDPR Erasures", subtitle "Crypto-erasure records for GDPR data subject requests." | Migrated | Erasures (`/erasures`), with a description of what an erasure does. |
| ER-2 | Badge "N erasures" | Migrated | Caption "50 of 61 erasures". |
| ER-3 | Table of erasures | Migrated | See ET below. |
| ER-4 | Empty state "No erasure records" / "GDPR erasure requests will appear here when subjects request data deletion." | Migrated | "No erasures have been requested in this scope." |
| ER-5 | First 50, no paging | Migrated | Paged 50 at a time. |

### erasure_detail.templ (ERD)

Route `/erasures/:id`.

| ID | Templ item | Status | Now |
|---|---|---|---|
| ERD-1 | Title "Erasure Detail", ID in a code tag, "Back" button | Migrated | Title is the ID. "Back to erasures" link at the foot. |
| ERD-2 | Card "Subject Erasure Request", "GDPR crypto-erasure for subject {id}" | Migrated | The page description, and the "Subject" row. |
| ERD-3 | Subject ID | Migrated | "Subject" row. |
| ERD-4 | Reason | Migrated | "Reason" row. |
| ERD-5 | Requested By | Migrated | "Requested by", "None" when empty. |
| ERD-6 | Events Affected | Migrated | "Events erased". |
| ERD-7 | Status badge (added on main in e81e2a2) | Migrated | "Status" row. See SB. |
| ERD-8 | Key badge (e81e2a2) | Migrated | "Key" row. See SB. |
| ERD-9 | App ID | Dropped | Not shown. It is always your own app. |
| ERD-10 | Tenant ID, shown only when set | Blocked | Not shown. Needs `tenantId` added to `ErasureSummary` in `extension/contract`, and the plugin's `types.ts`. |
| ERD-11 | Created | Migrated | "Requested" row. |
| ERD-12 | Paragraph for a pending erasure (e81e2a2): did not finish, run it again, the retry gets its own record | Migrated | Same message, slightly shorter. |
| ERD-13 | Paragraph for a retained legacy key (e81e2a2): events are marked erased, but the key was kept | Migrated | Same message, slightly shorter. |
| ERD-14 | Detail opened by ID with no ownership check at all | Migrated | Closed bug. `erasures.detail` checks ownership. |

### retention.templ (RT)

| ID | Templ item | Status | Now |
|---|---|---|---|
| RT-1 | Title "Retention Policies", subtitle "Configure automatic event archival and purge schedules." | Migrated | Retention (`/retention`), "Retention", with "Retention permanently deletes audit events." and a note on what `*` means. |
| RT-2 | Badge "N policies" | Migrated | Caption "3 policies". |
| RT-3 | Error card | Migrated | Command errors show inside the page or dialog that ran them. |
| RT-4 | Read-only message when mutations were off | Dropped | The flag is gone. |
| RT-5 | "Create Policy" card, inline on the list page | Migrated | "New policy" button to `/new-policy`, its own page. |
| RT-6 | Field "Category" (placeholder "auth, data, or * for all") | Migrated | "Category". It is checked before sending: `*`, or 1 to 64 characters with no `:` and no control characters. |
| RT-7 | Field "Duration" (placeholder "720h (30 days)"), any Go duration | Migrated | Changed: "Keep events for", a whole number plus hours or days, greater than zero. Templ accepted `0`. |
| RT-8 | Checkbox "Archive before purge" | Migrated | "Archive events before removing them". |
| RT-9 | Button "Create Policy" | Migrated | "Save policy". Needs `chronicle.admin`. A second policy for the same category in your scope answers "already exists". |
| RT-10 | Errors "Category and duration are required", "Invalid duration: ...", "Failed to save policy: ..." | Migrated | Field-level messages, and "Could not save the policy" for a server refusal. |
| RT-11 | Button "Enforce Now", confirm "Are you sure you want to enforce all retention policies now?" | Migrated | "Run retention now" opens a dialog that counts the eligible events per policy first, and says what verification will show afterwards. Changed: the old confirm said "all" but only ever ran your own policies. Needs `chronicle.admin`. |
| RT-12 | Enforcement outcome was thrown away | Migrated | The dialog shows how many were removed and archived, says "More may remain: close this and run it again" when they do, and shows a run that stopped part-way as a failure. |
| RT-13 | Error "Enforcement failed: ..." | Migrated | "Could not run retention", with code and message. |
| RT-14 | Table of policies | Migrated | See PT below. |
| RT-15 | Empty state "No retention policies" / "Create a policy above to automate event lifecycle management." | Migrated | "No retention policies: nothing is removed from this audit trail automatically." |
| RT-16 | Delete, fired from `?action=delete&id=` on this page | Migrated | Moved to the policy page. See RDT-8. |
| RT-17 | Enforcement confined to the viewer's own policies | Migrated | `retention.enforce` runs the viewer's scope only. |
| RT-18 | The enforce link was a bare query-param GET with no preview | Migrated | Closed bug. See "Closed bugs". |
| RT-19 | "Create Policy" card description, "Define a new retention policy for a category of events." | Migrated | The New policy page's description: "Events in the category are removed once they are older than the duration." |

### retention_detail.templ (RDT)

Route `/retention/:id`.

| ID | Templ item | Status | Now |
|---|---|---|---|
| RDT-1 | Title "Retention Policy", ID in a code tag, "Back" button | Migrated | Title is the ID. "Back to retention" link at the foot. |
| RDT-2 | Card title `Policy for "{category}"`, description "Retention configuration for events in this category." | Migrated | The page description, and the "Category" row. |
| RDT-3 | Category | Migrated | "Category", with `*` spelled "Every category (*)". |
| RDT-4 | Duration | Migrated | "Keeps for", whole hours written as days where they divide. |
| RDT-5 | Action badge, "Archive" or "Purge" | Migrated | "Archive" row: "Archived first" or "Not archived". |
| RDT-6 | App ID | Migrated | "App" row. |
| RDT-7 | Created | Migrated | "Created", plus a new "Updated" row. |
| RDT-8 | Button "Delete Policy", confirm "Are you sure you want to delete this retention policy?" | Migrated | "Delete policy" opens a confirm dialog that says events already removed stay removed. Needs `chronicle.admin`. |
| RDT-9 | Policy opened or deleted by ID, ownership checked (tenant guard, d1b8957) | Migrated | `retention.policyDetail` and `retention.deletePolicy` answer not-found unless the policy is yours. A tenant viewer cannot open or delete an app-level policy. |

### archives.templ (AR)

| ID | Templ item | Status | Now |
|---|---|---|---|
| AR-1 | Title "Archives", subtitle "Events archived by retention policies to cold storage." | Migrated | Archives (`/archives`), "Events a retention run wrote to an archive sink before removing them." |
| AR-2 | Badge "N archives" | Migrated | Caption "N archives shown". |
| AR-3 | Table of archives | Migrated | See AT below. |
| AR-4 | Empty state "No archives yet" / "Archives are created when retention policies archive events before purging." | Migrated | "No retention run has archived anything yet." |
| AR-5 | First 50, no paging | Migrated | Previous and Next page. |

### settings.templ (ST)

Route `/settings`. The same component also rendered as a settings panel (`chronicle-config`), which is a duplicate. See "Dropped".

| ID | Templ item | Status | Now |
|---|---|---|---|
| ST-1 | Title "Settings", subtitle "Chronicle audit trail engine configuration (read-only)." | Migrated | Settings, "Read-only: these come from the extension's configuration." |
| ST-2 | Card "Engine Configuration" / "Core audit trail engine settings." | Migrated | The settings list. |
| ST-3 | Batch Size, "N events" | Migrated | "Batch size". |
| ST-4 | Flush Interval | Migrated | "Flush interval". |
| ST-5 | Retention Interval | Migrated | "Retention runs every". |
| ST-6 | Crypto Erasure, Enabled or Disabled | Migrated | "Crypto-erasure", Enabled or Not enabled. |
| ST-7 | Base Path | Dropped | The shell knows its own base path and the contract does not send chronicle's. |
| ST-8 | Card "Security Features" / "Built-in security and compliance capabilities." | Dropped | A list of fixed strings. The live posture replaced it: digest scheme, keyed or not, checkpoints, backend. |
| ST-9 | "Hash Algorithm: SHA-256" | Dropped | Fixed text. "Digest scheme" shows the scheme in force. |
| ST-10 | "Hash Chain: Immutable linked hash chain per app+tenant stream" | Dropped | Fixed text. The Chain page shows the chain itself. |
| ST-11 | "Encryption: AES-256-GCM (for GDPR crypto-erasure)" | Dropped | Fixed text. |
| ST-12 | "Multi-Tenancy: Automatic scope isolation via context" | Dropped | Fixed text, and no longer true of the mechanism: scope comes from claims. |
| ST-13 | "Compliance Reports: SOC2 Type II, HIPAA, EU AI Act, Custom" | Dropped | Fixed text. The Reports pages offer what exists. |

### helpers.templ (HP)

Shared page helpers. They count as the thirteenth page file.

| ID | Templ item | Status | Now |
|---|---|---|---|
| HP-1 | `fieldRow`, a label and value pair in a definition list | Migrated | The kit's `DescriptionList`. |
| HP-2 | `codeBlock`, preformatted text | Migrated | `JsonView` for structured data, monospace spans for values. |
| HP-3 | `credentialField`, a select-all monospace field | Migrated | Closed in forge-dashboard 62fbbce. A monospace, break-all span that selects all on click. Hash and previous hash get it, as in templ, and so do the event id and the chain id. |
| HP-4 | `formatTimeAgo` ("just now", "5m ago", "3h ago", "2d ago", "1mo ago", "1y ago") | Migrated | The kit's timestamp component. |
| HP-5 | `formatJSON`, pretty-printed JSON | Migrated | `prettyJSON` in `components/json-view.tsx`. |
| HP-6 | `truncateString`, shorten with "..." | Dropped | The plugin shows full IDs. |

---

## Widgets

The React shell has no home for a chronicle widget. `overview.widgets` is a slot the authsome overview page hosts for its own sub-plugins, and chronicle has none.

### stats.templ (WS)

| ID | Templ item | Status | Now |
|---|---|---|---|
| WS-1 | Widget "Audit Stats" ("Audit trail overview metrics", medium, refresh 30s), a 2 by 2 grid | Dropped | No widget host. The same four numbers are on Activity. |
| WS-2 | Tile "Events" | Migrated | Activity, "Total events". |
| WS-3 | Tile "Critical" | Migrated | Activity, "Critical". All time, see OV-3. |
| WS-4 | Tile "Failed" | Migrated | Activity, "Failed or denied". |
| WS-5 | Tile "Erasures" | Migrated | Activity, "Erasures". |

### recent_events.templ (WR)

| ID | Templ item | Status | Now |
|---|---|---|---|
| WR-1 | Widget "Recent Events" ("Latest audit trail events", large, refresh 15s), the last 5 events | Dropped | No widget host. Events, newest first, is the replacement. There is no auto refresh. |
| WR-2 | Empty state "No events yet" (no description) | Dropped | Goes with the widget. |

---

## Components

### archive_table.templ (AT)

| ID | Templ item | Status | Now |
|---|---|---|---|
| AT-1 | Column "ID" (shortened to 16 characters) | Migrated | "Archive", full ID. |
| AT-2 | Column "Category" | Migrated | "Category". |
| AT-3 | Column "Events" | Migrated | "Events", right aligned. |
| AT-4 | Column "From" (`Jan 02, 2006`) | Migrated | "From", the kit's timestamp. |
| AT-5 | Column "To" | Migrated | "To". |
| AT-6 | Column "Sink" | Migrated | "Sink". |
| AT-7 | Column "Reference" (shortened to 30 characters) | Migrated | "Sink ref", full value, "None" when empty. |

### empty_state.templ (ES)

| ID | Templ item | Status | Now |
|---|---|---|---|
| ES-1 | Centered placeholder: large muted icon, title, optional description | Migrated | `ResourceTable`'s empty message, one line each. The per-page wording is in the page tables above. The icons and the second line of copy are not carried over. |

### erasure_table.templ (ET)

| ID | Templ item | Status | Now |
|---|---|---|---|
| ET-1 | Column "ID" (shortened) | Migrated | "Erasure", full ID, a link to the detail page. |
| ET-2 | Column "Subject ID" | Migrated | "Subject". |
| ET-3 | Column "Reason" (shortened to 40) | Migrated | "Reason", clamped to two lines. |
| ET-4 | Column "Requested By" | Migrated | "Requested by", "None" when empty. |
| ET-5 | Column "Events Affected" | Migrated | "Events". |
| ET-6 | Column "Status" | Migrated | "Status". See SB. |
| ET-7 | Column "Key" | Migrated | "Key". See SB. |
| ET-8 | Row click opens `erasures/detail?id=` | Migrated | The ID is a link to `/erasures/:id`. The row is not clickable. |

### event_table.templ (EVT)

| ID | Templ item | Status | Now |
|---|---|---|---|
| EVT-1 | Column "ID" (shortened to 16) | Dropped | The ID is on the event's own page. The Action cell is the link. |
| EVT-2 | Column "Timestamp" (`Jan 02, 15:04`) | Migrated | "Time". |
| EVT-3 | Column "Action" | Migrated | "Action", a link to `/events/:id`. |
| EVT-4 | Column "Resource" | Migrated | "Resource", with the resource ID beside it. |
| EVT-5 | Column "Category" | Migrated | "Category". |
| EVT-6 | Column "Severity" | Migrated | "Severity". See SB. |
| EVT-7 | Column "Outcome" | Migrated | "Outcome". See SB. Outcome now comes before Severity. |
| EVT-8 | Row click opens `events/detail?id=` | Migrated | Via the Action link. |
| EVT-9 | `truncateStr` helper | Dropped | Nothing is shortened. |

### policy_table.templ (PT)

| ID | Templ item | Status | Now |
|---|---|---|---|
| PT-1 | Column "ID" (shortened) | Dropped | The policy's ID is on its page. The Category cell is the link. |
| PT-2 | Column "Category" | Migrated | "Category", a link to `/retention/:id` when you can edit the policy. `*` reads "Every category (*)". |
| PT-3 | Column "Duration" | Migrated | "Keeps for". |
| PT-4 | Column "Action" (Archive or Purge badge) | Migrated | "Archive": "Archived first" or "Not archived". |
| PT-5 | Column "App ID" (shortened to 20) | Migrated | Replaced by "Scope": "Tenant {id}" or "App level, every tenant". The app is always yours. |
| PT-6 | Row click opens `retention/detail?id=` | Migrated | Via the Category link, and only for a policy you can edit. |

### report_table.templ (RPT)

| ID | Templ item | Status | Now |
|---|---|---|---|
| RPT-1 | Column "ID" (shortened) | Migrated | "ID", full. |
| RPT-2 | Column "Title" | Migrated | "Report", a link to `/reports/:id`. |
| RPT-3 | Column "Type" (badge) | Migrated | "Type", plain text. |
| RPT-4 | Column "Period" (`Jan 02 - Jan 02`) | Migrated | "Period", start to end. |
| RPT-5 | Column "Generated By" | Migrated | "Generated by". |
| RPT-6 | Column "Created" | Migrated | "Generated". |
| RPT-7 | Row click opens `reports/detail?id=` | Migrated | Via the title link. |

### stat_card.templ (SC)

| ID | Templ item | Status | Now |
|---|---|---|---|
| SC-1 | `StatCard`: icon, label, big value, optional subtitle | Migrated | The kit's `StatGrid` (label, value, optional hint). Icons are not carried over. |
| SC-2 | `resolveIcon`, a name to icon map of 30 icons, falling back to an info icon | Dropped | The kit and plugin import icons directly. |

### status_badge.templ (SB)

Colour is `default` (filled), `secondary`, `outline` or `destructive`. React chooses variants in one place, `src/badges.tsx`, and the reasons are written there. The short version: what is nearly every row recedes, and red means something needs looking at.

| ID | Templ item | Status | Now |
|---|---|---|---|
| SB-1 | Outcome badge. Success (filled), Failed (destructive), Denied (destructive), anything else as its own text (secondary) | Migrated | Changed: it shows the raw value (`success`, `failure`, `denied`). `failure` and `denied` are destructive, everything else is outline. |
| SB-2 | Severity badge. Critical (destructive), Warning (secondary), everything else "Info" (outline) | Migrated | Shows the raw value. Critical destructive, warning secondary, everything else outline. Changed: an unknown severity used to be labelled "Info". It now shows its own text. |
| SB-3 | Erased badge. "Erased" (destructive) or "Active" (filled) | Migrated | "Erased" in `secondary`, shown only when the event is erased and names an erasure (templ showed it for any erased event). An erasure is a lawful action, not a fault. There is no "Active". |
| SB-4 | Verification badge. "Valid" (filled) or "Tampered" (destructive) | Migrated | There is no badge. The verdict sentence says it, and a chain break is never a badge. Individual checks use "held" (outline), "failed" (destructive), or plain muted "Not checked" text. |
| SB-5 | Report type badge. SOC2, HIPAA, EU AI Act (filled), anything else "Custom" (secondary) | Migrated | Plain text: SOC 2, HIPAA, EU AI Act, Custom. A type the plugin does not know is shown as sent. |
| SB-6 | Erasure status badge. "Pending" (filled), "Completed" (secondary) | Migrated | "Pending" is `destructive` and "Completed" is `outline`. A record with no status reads as completed. |
| SB-7 | Erasure key badge. "Not Confirmed" (outline), "Key Destroyed" (destructive), "Legacy Key Retained" (outline), "Key Intact" (secondary) | Migrated | "Not confirmed" `secondary`, "Key destroyed" `outline`, "Legacy key retained" `secondary`, "Key intact" `secondary`. Never destructive: the Status column carries the failure. |
| SB-8 | Archive badge. "Archive" (filled), "Purge" (secondary) | Migrated | Text, "Archived first" or "Not archived". |

---

## Dashboard glue

### manifest.go (MF)

| ID | Templ item | Status | Now |
|---|---|---|---|
| MF-1 | Name `chronicle`, display name "Chronicle", icon `scroll-text`, version 1.0.0 | Migrated | `extension: "chronicle"`, `namespace: "chronicle"`, label "Chronicle" in the plugin. The contract's contributor name is `chronicle`. |
| MF-2 | Layout `extension`, sidebar shown | Migrated | The shell's layout. |
| MF-3 | Topbar title "Chronicle" and logo icon | Dropped | The shell owns the top bar. |
| MF-4 | Accent colour `#8b5cf6` | Dropped | The shell owns the theme. |
| MF-5 | Topbar search box and the `searchable` capability | Dropped | The plugin API has no top bar or search hook. Searching is the Events page's filters, which run on the server. |
| MF-6 | Topbar action "API Docs" linking to `/docs` | Dropped | The plugin API has no top bar hook. |
| MF-7 | Nav "Overview" (`/`, group Overview) | Dropped | No overview page. See OV-1. |
| MF-8 | Nav "Events" (`/events`, group Audit Trail) | Migrated | "Events", group Log. |
| MF-9 | Nav "Verification" (`/verify`, group Audit Trail) | Migrated | "Chain", group Integrity, `/chain`. |
| MF-10 | Nav "Reports" (`/reports`, group Compliance) | Migrated | "Reports", group Compliance. |
| MF-11 | Nav "Erasures" (`/erasures`, group Compliance) | Migrated | "Erasures", group Compliance. |
| MF-12 | Nav "Retention" (`/retention`, group Data Lifecycle) | Migrated | "Policies", group Retention, `/retention`. |
| MF-13 | Nav "Archives" (`/retention/archives`, group Data Lifecycle) | Migrated | "Archives", group Retention, `/archives`. |
| MF-14 | Nav "Settings" (`/settings`, group Configuration) | Migrated | "Settings", group Settings. |
| MF-15 | Widget descriptors `chronicle-stats` and `chronicle-recent-events` | Dropped | See Widgets. |
| MF-16 | Settings descriptor `chronicle-config` | Dropped | A duplicate of the Settings page. See "Dropped". |
| MF-17 | The settings descriptor's title "Chronicle Configuration", description "Audit trail engine settings", group "Chronicle" and icon `scroll-text` | Dropped | They named the duplicate panel. The Settings page has its own title and description. |
| MF-18 | Nav icon names: `layout-dashboard` (Overview), `activity` (Events), `shield-check` (Verification), `file-check` (Reports), `eraser` (Erasures), `clock` (Retention), `archive` (Archives), `settings` (Settings) | Migrated | The plugin picks its own icons: shield (Chain), milestone (Checkpoints), scroll text (Events), column chart (Activity), file text (Reports), eraser (Erasures), timer reset (Policies), archive (Archives), settings (Settings). The Overview icon goes with the Overview page. No icon carries a check mark, because that would be a pass shown permanently. |

### contributor.go (CT)

| ID | Templ item | Status | Now |
|---|---|---|---|
| CT-1 | `Config.AllowMutations` | Dropped | See "Dropped". |
| CT-2 | `Config` fields BatchSize, FlushInterval, RetentionInterval, EnableCryptoErasure, BasePath | Migrated | `settings.detail`. BasePath is not carried, see ST-7. |
| CT-3 | `Config.HashChain`, the chain verify recomputes digests under | Migrated | `contract.Deps.HashChain`. Leaving it out reports every event of an HMAC deployment as tampered. |
| CT-4 | `Config.CheckpointStore` and `CheckpointSigner` | Migrated | `contract.Deps`, set as a set. Without both, verification reports no checkpoints. |
| CT-5 | Route `/` | Migrated | `/` and `/chain`. |
| CT-6 | Route `/events` | Migrated | `/events`. |
| CT-7 | Route `/events/detail` (`?id=`) | Migrated | `/events/:id`. |
| CT-8 | Route `/verify` | Migrated | `/chain`, `/chain/:streamId`, `/chain/:streamId/:fromSeq/:toSeq`. |
| CT-9 | Route `/reports` | Migrated | `/reports`. |
| CT-10 | Route `/reports/detail` | Migrated | `/reports/:id`. |
| CT-11 | Route `/erasures` | Migrated | `/erasures`. |
| CT-12 | Route `/erasures/detail` | Migrated | `/erasures/:id`. |
| CT-13 | Route `/retention` | Migrated | `/retention`. |
| CT-14 | Route `/retention/detail` | Migrated | `/retention/:id`. |
| CT-15 | Route `/retention/archives` | Migrated | `/archives`. |
| CT-16 | Route `/settings` | Migrated | `/settings`. |
| CT-17 | Settings panel `chronicle-config`, identical to `/settings` | Dropped | See "Dropped". |
| CT-18 | Widget renderers `chronicle-stats` and `chronicle-recent-events` | Dropped | See Widgets. |
| CT-19 | Query and form parameters: `category`, `severity`, `outcome`, `id`, `stream_id`, `from_seq`, `to_seq`, `action` | Dropped | Pages take route params and page state. Old bookmarks do not work. |
| CT-20 | Create-policy stamped the viewer's app and tenant on the policy | Migrated | `retention.savePolicy` takes scope from the Principal. No request field carries an app or tenant. |
| CT-21 | Enforcement ran only the viewer's own scope (`EnforceScope`) | Migrated | `retention.enforce`. |
| CT-22 | Detail pages and delete checked ownership with `inScope` | Migrated | See DT-3. |
| CT-23 | Every fetch error swallowed into an empty list | Migrated | Closed quirk. Pages show the error. |
| CT-24 | Report generation window fixed at 90 days, generated by "dashboard" | Migrated | See RP-3 and RP-6. |
| CT-25 | Verification checked the stream belonged to the viewer, then verified with the stream's pin, head sequence and head hash | Migrated | `verify.run`, which also selects the chain by ownership and caps the span at 100,000. |
| CT-26 | Delete errors "Policy not found" (not found, or not yours) and "Failed to delete policy: ..." | Migrated | `retention.deletePolicy` answers not-found for a policy that is not yours. The confirm dialog shows "Could not delete the policy" with the code and message. |

### data.go (DT)

| ID | Templ item | Status | Now |
|---|---|---|---|
| DT-1 | `readOnlyMessage`, "This dashboard is read-only. Set the chronicle extension's dashboard_mutations option..." | Dropped | The flag is gone. |
| DT-2 | `resolveScope`: forge scope, then chronicle scope, off the request context. An empty scope showed every app | Dropped | Replaced by claims or `chronicle.dashboard.*`. A missing app is refused. |
| DT-3 | `inScope`: a viewer with no tenant owns all of its app's records, a tenant viewer only its own (d1b8957) | Migrated | The same rule, applied by every detail handler, and answering not-found. |
| DT-4 | The four overview counts loaded in parallel | Migrated | `overview.stats`, three aggregations plus an erasure count. |
| DT-5 | Critical count over the last 30 days | Migrated | Changed: all time. |
| DT-6 | Failed count over the last 30 days, `failure` and `denied` together | Migrated | Changed: all time, and split into `failedEvents` and `deniedEvents`. |
| DT-7 | A failing count read as 0 | Migrated | Closed bug. See "Closed bugs". |
| DT-8 | Recent events (10 on the page, 5 in the widget) and recent critical events (10) | Migrated | Events page. See OV-6 and OV-8. |
| DT-9 | List fetch sizes: events 50, erasures 50, reports 50, archives 50 | Migrated | Each list pages 50 at a time. |

---

## Route map

Route names are plugin routes. Anything not listed here has no equivalent.

| Templ route | React route |
|---|---|
| `/` | `/` or `/chain` (Chain); counts on `/activity` |
| `/events` | `/events` |
| `/events/detail?id=` | `/events/:id` |
| `/verify` | `/chain`, `/chain/:streamId`, `/chain/:streamId/:fromSeq/:toSeq` |
| `/reports` | `/reports` |
| `/reports/detail?id=` | `/reports/:id` |
| `/erasures` | `/erasures` |
| `/erasures/detail?id=` | `/erasures/:id` |
| `/retention` | `/retention` |
| `/retention/detail?id=` | `/retention/:id` |
| `/retention/archives` | `/archives` |
| `/settings` | `/settings` |

---

## Dropped

Everything the tables mark Dropped was left out on purpose. Each item gives its reason:

- `Config.AllowMutations`, now `DashboardMutations` in the extension config and `WithDashboardMutations()`. Both stay as deprecated no-ops for one release, so existing config loads and code compiles, and go in a later release. The flag existed because templ pages rendered through a route chronicle cannot authenticate. The contract has a Principal and scope checks, so the flag goes when templ does.
- The settings panel. `RenderSettings("chronicle-config")` and `RenderPage("/settings")` returned the identical component, so one of them was never a feature.
- `UpdateStreamScheme`. It has no intent. A stream's digest pin moves by itself when an event is written (`reconcileStreamPin`). Offering it as an operator action would let somebody move a pin without writing an event, which is the shape of the downgrade attack verification exists to catch.
- `compliance.ReportStore.DeleteReport`. Neither the REST API nor the templ dashboard ever offered it. Deleting compliance evidence should not be one click in a dashboard, so this is a choice and not an oversight.
- The "read-only" message, the fixed "Security Features" strings on Settings, and the single "Issues" count on the verify page. Each is replaced by something that says more (scopes, live posture, the per-kind verdict).
- Widgets, the top bar's title, accent, search and "API Docs" link, and the Overview page as a landing page. The shell owns or has no place for them.
- Everything the templ pages cut off: the 16, 20, 30 and 40 character shortening, the fixed 50-row lists, and the `?severity=` style query strings.

## Blocked

Needs Go work before it can exist.

- A before and after diff view for events. `audit.Event` has no such representation and `Metadata` is freeform, so building one means inventing a metadata convention the library does not have. The templ dashboard never had one.
- External anchoring. `LevelAnchored` is in the coverage enum and nothing emits it. The coverage ladder shows it as a level not reached, and the verdict says nothing anchors the chain outside the deployment.
- Tenant ID on event, erasure and report detail (ED-12, ERD-10, RD-6). The contract's `EventDetail`, `ErasureSummary` and `ReportSummary` do not carry `tenantId`. An app-wide operator who reads several tenants' records cannot tell them apart. Add the field to those three types in `extension/contract`, then to the plugin's `types.ts` and the detail pages.
- Encryption Key ID on an event (ED-21). Add `encryptionKeyId` to `EventDetail`.

## New, not migrated

Nothing in the templ dashboard did any of this.

- Checkpoints as a surface: a list, a detail page, and "Take a checkpoint".
- The coverage ceiling: the best assurance level a chain can report, shown before you run anything.
- Both destructive-action previews: what retention would remove, and how many events an erasure would touch.
- Report export through the dashboard, and custom reports. One correction to the design notes: the templ report page did link to the REST export endpoint, but with a hard-coded `/chronicle/v1` prefix that broke on any other base path, so only default-path installs could use it.
- Per-event verification ("Check this event's digest", on the event page).
- Aggregation and the Activity charts: breakdowns by category, severity and outcome, and event volume by day or hour, with empty periods written out as a finding.
- Events by user, at `/users/:userId`.
- The stream selector, for an app-wide operator with one chain per tenant.
- `erasures.request`: requesting an erasure from the dashboard. The templ dashboard only listed them.
- The three `Report` fields the templ verify page dropped: `HeadMatch` and `HeadChecked` (truncation evidence), `Partial` (a bounded check does not speak for the rest of the chain), and `CheckpointsChecked` (the difference between "this chain has no checkpoints" and "nothing looked").

Also new, smaller: every events filter the store supports (actions, resources, user, session, request, before, after), edit a policy's duration and archive flag, archive rows with their policy, tenant and creation time, and event rows with an erased marker. An `[ERASED]` value on an event with no erasure recorded in your scope is flagged as unexplained and is never presented as an erasure.

## Closed bugs

The templ dashboard had these. They are fixed by the move, so nobody should read their absence as a lost feature.

- `renderErasureDetail` did no scope check, unlike every other detail renderer. `erasures.detail` checks ownership.
- Detail pages let a tenant viewer open app-level records by ID that the viewer's own lists hid (events, reports, erasures and policies, by ID). d1b8957 tightened this on main for the templ code. The contract applies the same strict rule from the start, and answers not-found so nobody can probe which IDs exist.
- The retention page fired enforcement from a bare query-param link with no preview, and accepted any duration including zero. Enforcement now opens a dialog that counts what is eligible first, policy by policy, and a duration must be greater than zero.
- On every sqlite deployment the overview's critical and failed counts read 0, because a filter error was swallowed as a zero count. Activity reads them off an aggregation, and an error is shown as an error.
- Also fixed: every list page turned a store error into an empty table, events filter buttons dropped each other's filters, the report export links ignored a non-default base path, and report generation ran from a plain GET link.

## Numbers that mean something different now

- Templ counted critical events, and failed or denied events, over the last 30 days. The Activity page counts them across the whole scope (all time), says so in a hint on each tile, and shows volume over time, by day or hour. The "Last 30 days" labels are gone.
- "Failed" on the old overview meant failure plus denied. The contract's `failedEvents` is failure only, and `deniedEvents` is separate. Activity adds them for its "Failed or denied" tile and shows both parts beside it.
- Verifying with no range used to check the whole chain. The page now defaults to the latest 10,000 sequences and says plainly that the result does not speak for the rest.
- A result is never "Valid". It is a sentence that names the range, the method and what that method cannot see.
