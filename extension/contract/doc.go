// Package contract wires chronicle into the Forge dashboard's contract path.
// It registers the `chronicle` contributor, declares the intents the React
// dashboard reads, and answers them from chronicle's own domain packages.
//
// scope.go is the security boundary. Every handler resolves the viewer's
// scope from the principal's claims before it touches the store, and every
// detail handler re-checks ownership after it fetches.
package contract
