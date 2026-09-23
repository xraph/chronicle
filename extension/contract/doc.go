// Package contract wires chronicle into the Forge dashboard's contract path.
// It registers the `chronicle` contributor, declares the intents the React
// dashboard reads, and answers them from chronicle's own domain packages.
//
// The templ dashboard in chronicle/dashboard/ continues to run alongside this
// package until it is retired. Both read the same store.
package contract

import (
	_ "github.com/xraph/forge/extensions/dashboard/contract"
	_ "github.com/xraph/forge/extensions/dashboard/contract/dispatcher"
	_ "github.com/xraph/forge/extensions/dashboard/contract/loader"
)
