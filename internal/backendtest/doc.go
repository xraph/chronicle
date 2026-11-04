// Package backendtest holds tests that run Chronicle against every store
// backend. It is never imported.
//
// The tests live in their own module so the root module, Chronicle's core,
// never depends on a database driver, not even to run its own tests.
package backendtest
