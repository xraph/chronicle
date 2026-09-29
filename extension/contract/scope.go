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
// is ABSENT from one that is PRESENT.
//
// The rule is exactly this. A tenant key ("tenant_id", or "org_id", which is
// authsome's spelling of the same dimension) that is missing from the claims
// map means the upstream never scoped this session to a tenant: that is a
// legitimate app-wide operator, and the result is "" (app-wide). A tenant key
// that IS in the map with any value other than a non-empty string (an empty
// string, nil, a number, a list) means the upstream wrote a tenant and its
// value was lost on the way here. That is a tenant-scoped session whose
// scoping failed, and widening it to app-wide would hand one tenant's
// operator every other tenant's audit events inside the same app, so it is
// refused with PERMISSION_DENIED.
//
// Both keys are checked, and a bad value in either refuses the session even
// when the other is good: treating one spelling as a stand-in for a claim we
// could not read is a guess about what the upstream meant. When both are
// present and readable they must be equal. Two different tenants on one
// session means some layer wrote a tenant the upstream did not, and picking
// either one is a guess about which layer to trust, so it is refused with the
// same code as an unreadable claim.
func tenantFromClaims(p fcontract.Principal) (string, error) {
	var tenant string
	for _, key := range []string{"tenant_id", "org_id"} {
		raw, present := p.Claims[key]
		if !present {
			continue // absent: the upstream never scoped a tenant
		}
		s, ok := raw.(string)
		if !ok || s == "" {
			return "", &fcontract.Error{
				Code:    fcontract.CodePermissionDenied,
				Message: "tenant scope on this session is unreadable",
			}
		}
		if tenant != "" && tenant != s {
			return "", &fcontract.Error{
				Code:    fcontract.CodePermissionDenied,
				Message: "tenant scope on this session is ambiguous",
			}
		}
		tenant = s
	}
	return tenant, nil
}

// owns reports whether a record fetched by ID belongs to this viewer.
//
// Every detail handler calls it after fetching and before returning. A detail
// intent resolves a record by ID, which bypasses every list filter, so without
// this check any caller could read another tenant's event by guessing an ID.
//
// AppID is compared first and unconditionally, and a viewer with no AppID
// owns nothing. Past that:
//
//   - An app-wide viewer (TenantID "") owns every record in its app, including
//     records held at app level with no tenant.
//   - A tenant viewer owns a record only when the record's TenantID equals its
//     own exactly. It does NOT own app-level records. applyQuery pins list
//     queries to the viewer's tenant exactly, so lists already hide those
//     records, and the contract must not show by ID what its lists hide.
func (v viewScope) owns(appID, tenantID string) bool {
	if v.AppID == "" || appID != v.AppID {
		return false
	}
	if v.TenantID == "" {
		return true
	}
	return tenantID == v.TenantID
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
