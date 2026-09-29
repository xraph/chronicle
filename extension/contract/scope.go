package contract

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

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

// scopeFromPrincipal resolves the viewer's scope, refusing a session that
// carries no usable app.
//
// The refusal is the important half. Chronicle's stores treat an empty AppID
// as matching every app: audit.Query with no AppID returns every tenant's
// events, and retention.PurgeQuery with no AppID deletes them. The
// characterization test in store/scope_behaviour_test.go records that
// against all four backends. So a session with no app cannot default to "the
// current app" on its own, because there is no such thing here. The only
// app it may take is one an operator named in the deployment's config
// (Deps.DefaultAppID), and otherwise it is an error.
//
// Claims is the contract path's scoping surface, the same one authsome's
// AppIDFromPrincipal documents, keyed "app_id". The templ dashboard's
// forge.ScopeFrom(ctx) is NOT available on this path: nothing in the
// dispatcher, server or transport puts a forge scope into the handler's
// context, so porting its resolveScope here would silently return empty.
//
// A session with no signed-in user is refused first, as UNAUTHENTICATED,
// before any claim or default is read. A subject that is empty or only
// whitespace is no user: it names nobody, and would otherwise pass for one.
//
// Then each dimension resolves on its own, in this order:
//
//  1. A claim that is present and usable wins.
//  2. A claim that is present and unusable refuses. It never falls back to
//     the configured value: an upstream that wrote a scope and lost its
//     value has failed to resolve one, and letting a legitimate default
//     cover for that failure is how a session ends up in a scope nobody
//     assigned it.
//  3. A claim that is absent takes the configured default.
//  4. An app still unresolved is refused, and the message names the setting
//     to add. A tenant still unresolved is an app-wide view.
//
// A tenant claim with no app claim beside it is refused whatever the config
// says. The tenant was written by an upstream that also owned the app, and it
// lost the app on the way here. Pairing that tenant with the configured app
// would guess which app the tenant was ever meant for.
//
// Every handler calls this before it touches the store.
func scopeFromPrincipal(p fcontract.Principal, deps Deps) (viewScope, error) {
	if p.User == nil || strings.TrimSpace(p.User.Subject) == "" {
		return viewScope{}, &fcontract.Error{
			Code:    fcontract.CodeUnauthenticated,
			Message: "no signed-in user on this session",
		}
	}

	appID, appFromClaim, err := appFromClaims(p, deps)
	if err != nil {
		return viewScope{}, err
	}
	if !appFromClaim && (hasClaim(p, "tenant_id") || hasClaim(p, "org_id")) {
		return viewScope{}, &fcontract.Error{
			Code:    fcontract.CodePermissionDenied,
			Message: "session names a tenant but no app: refusing rather than pairing it with the configured app",
		}
	}

	tenantID, err := tenantFromClaims(p, deps, appID)
	if err != nil {
		return viewScope{}, err
	}

	return viewScope{AppID: appID, TenantID: tenantID}, nil
}

// hasClaim reports whether key is in the claims map at all, whatever its value.
func hasClaim(p fcontract.Principal, key string) bool {
	_, present := p.Claims[key]
	return present
}

// ValidateDefaultScope checks the configured default app and tenant, the values
// of chronicle.dashboard.app_id and chronicle.dashboard.tenant_id.
//
// Nothing is trimmed. A value with a leading or trailing space, or with a
// control character in it, would be stored and compared exactly as written,
// so it would name a scope that looks like the real one on every page and
// matches none of its data. It is refused rather than quietly repaired, the
// same rule a policy category follows.
//
// A tenant with no app is refused because the default tenant only ever
// applies inside the default app, so on its own it would do nothing while
// looking like it narrowed every session.
func ValidateDefaultScope(appID, tenantID string) error {
	if err := checkConfiguredID("chronicle.dashboard.app_id", appID); err != nil {
		return err
	}
	if err := checkConfiguredID("chronicle.dashboard.tenant_id", tenantID); err != nil {
		return err
	}
	if tenantID != "" && appID == "" {
		return errors.New("chronicle: chronicle.dashboard.tenant_id is set but chronicle.dashboard.app_id is not; " +
			"the default tenant belongs to the default app, so set both or neither")
	}
	return nil
}

// checkConfiguredID refuses an identifier with invalid UTF-8, a control
// character, or edge whitespace. Empty is allowed: it means "not configured".
func checkConfiguredID(key, v string) error {
	if v == "" {
		return nil
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("chronicle: %s is not valid UTF-8", key)
	}
	for _, r := range v {
		if unicode.Is(unicode.Cc, r) {
			return fmt.Errorf("chronicle: %s contains a control character; it is not trimmed or repaired, so remove it", key)
		}
	}
	first, _ := utf8.DecodeRuneInString(v)
	last, _ := utf8.DecodeLastRuneInString(v)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return fmt.Errorf("chronicle: %s has leading or trailing whitespace; it is not trimmed, so remove it", key)
	}
	return nil
}

// appFromClaims resolves the app dimension. See scopeFromPrincipal for the
// order; the distinction that matters here is between an "app_id" key that is
// missing and one that is in the map with a value that cannot be used.
func appFromClaims(p fcontract.Principal, deps Deps) (appID string, fromClaim bool, err error) {
	if raw, present := p.Claims["app_id"]; present {
		s, ok := raw.(string)
		if !ok || s == "" {
			return "", false, &fcontract.Error{
				Code:    fcontract.CodePermissionDenied,
				Message: "app scope on this session is unreadable",
			}
		}
		return s, true, nil
	}

	if deps.DefaultAppID != "" {
		return deps.DefaultAppID, false, nil
	}

	return "", false, &fcontract.Error{
		Code: fcontract.CodePermissionDenied,
		Message: "no app scope on this session: chronicle cannot tell which app this request is for. " +
			"Set chronicle.dashboard.app_id for a single-app deployment.",
	}
}

// tenantFromClaims resolves the tenant dimension, distinguishing a claim that
// is ABSENT from one that is PRESENT.
//
// The rule is exactly this. A tenant key ("tenant_id", or "org_id", which is
// authsome's spelling of the same dimension) that is missing from the claims
// map means the upstream never scoped this session to a tenant. A tenant key
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
//
// The tenant is absent only when BOTH keys are absent. Then, if the resolved
// app is the configured default app and a default tenant is configured, the
// session takes that tenant. The default tenant belongs to the default app:
// a session whose claims put it in some other app must not be narrowed to a
// tenant id that was chosen for a different one, since the same id can name
// an unrelated tenant there. With no default, an absent tenant is a
// legitimate app-wide operator and the result is "" (app-wide).
func tenantFromClaims(p fcontract.Principal, deps Deps, appID string) (string, error) {
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
	if tenant != "" {
		return tenant, nil
	}

	if deps.DefaultTenantID != "" && deps.DefaultAppID != "" && appID == deps.DefaultAppID {
		return deps.DefaultTenantID, nil
	}
	return "", nil
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

// governedBy reports whether a record is an app-level policy of the viewer's
// app that purges a tenant viewer's chain without being the viewer's own: same
// app, no tenant, and a viewer that has one. An app-wide viewer is governed by
// nothing, because every app-level record in its app is already its own.
func (v viewScope) governedBy(appID, tenantID string) bool {
	return v.AppID != "" && v.TenantID != "" && appID == v.AppID && tenantID == ""
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
