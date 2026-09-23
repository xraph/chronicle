package contract

import (
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle/audit"
)

// viewScope is the app and tenant every handler confines itself to.
//
// It is derived from the principal's claims and never from the request body.
// A request that could name its own scope is a request that can read another
// customer's audit log.
type viewScope struct {
	AppID    string
	TenantID string
}

// scopeFromPrincipal resolves the viewer's scope, refusing a principal that
// carries no usable app.
//
// The refusal is the important half. Chronicle's stores treat an empty AppID
// as matching every app: audit.Query with no AppID returns every tenant's
// events, and retention.PurgeQuery with no AppID deletes them. The
// characterization test in store/scope_behaviour_test.go records that
// against all four backends. So a missing claim cannot default to "the
// current app", because there is no such thing here. It has to be an error.
//
// Claims is the contract path's scoping surface, the same one authsome's
// AppIDFromPrincipal documents, keyed "app_id". The templ dashboard's
// forge.ScopeFrom(ctx) is NOT available on this path: nothing in the
// dispatcher, server or transport puts a forge scope into the handler's
// context, so porting its resolveScope here would silently return empty.
//
// Every handler calls this before it touches the store.
func scopeFromPrincipal(p fcontract.Principal) (viewScope, error) {
	appID, ok := p.Claims["app_id"].(string)
	if !ok || appID == "" {
		return viewScope{}, &fcontract.Error{
			Code:    fcontract.CodePermissionDenied,
			Message: "no app scope on this session",
		}
	}

	tenantID, err := tenantFromClaims(p)
	if err != nil {
		return viewScope{}, err
	}

	return viewScope{AppID: appID, TenantID: tenantID}, nil
}

// tenantFromClaims resolves the tenant dimension, distinguishing a claim that
// is ABSENT from one that is PRESENT AND UNUSABLE.
//
// Those two look identical through a bare `v, _ := claims[k].(string)` and
// they mean opposite things. Absent is a legitimate app-wide operator, and
// widening to app-wide is correct for them. Present but unusable is a session
// that was scoped to a tenant by something upstream, whose scoping this
// handler then failed to read: widening THAT to app-wide hands one tenant's
// operator every other tenant's audit events inside the same app.
//
// So an absent claim falls back and an unusable one is refused. "tenant_id"
// is read first and "org_id", authsome's spelling of the same dimension,
// second. An unusable tenant_id is refused even when org_id is readable,
// because treating org_id as a stand-in for a claim we could not parse is a
// guess about what the upstream meant.
func tenantFromClaims(p fcontract.Principal) (string, error) {
	for _, key := range []string{"tenant_id", "org_id"} {
		raw, present := p.Claims[key]
		if !present || raw == nil {
			continue // absent: try the next spelling, then app-wide
		}
		s, ok := raw.(string)
		if !ok {
			return "", &fcontract.Error{
				Code:    fcontract.CodePermissionDenied,
				Message: "tenant scope on this session is unreadable",
			}
		}
		if s == "" {
			continue // explicitly empty reads as app-wide, same as absent
		}
		return s, nil
	}
	return "", nil
}

// owns reports whether a record fetched by ID belongs to this viewer.
//
// Every detail handler calls it after fetching and before returning. A detail
// intent resolves a record by ID, which bypasses every list filter, so without
// this check any caller could read another tenant's event by guessing an ID.
//
// An empty TenantID on the VIEWER means an app-wide operator, who owns every
// tenant inside their own app. An empty TenantID on the RECORD means a record
// held at app level, which an app operator also owns. Neither ever reaches
// past AppID, which is compared first and unconditionally.
//
// A viewer with no AppID owns nothing. scopeFromPrincipal never builds one,
// but a zero viewScope that leaked through would otherwise match every record
// whose AppID is also empty.
func (v viewScope) owns(appID, tenantID string) bool {
	if v.AppID == "" || appID != v.AppID {
		return false
	}
	if v.TenantID != "" && tenantID != "" && tenantID != v.TenantID {
		return false
	}
	return true
}

// applyQuery stamps the viewer's scope onto an event query, overwriting
// whatever scope the query already carried. It sets TenantID even when the
// viewer's is empty, so an app-wide viewer's query is app-wide and never
// keeps a tenant some earlier step put there.
func (v viewScope) applyQuery(q *audit.Query) *audit.Query {
	q.AppID = v.AppID
	q.TenantID = v.TenantID
	return q
}
