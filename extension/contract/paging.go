package contract

import (
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// pageBounds is the one paging rule every list intent in this contract uses.
//
// A negative limit or offset is a caller mistake and is refused with
// CodeBadRequest. A limit of zero means the list's default. A limit above the
// list's own maximum is capped to it, not refused, so a client that asks for
// more than it can have still gets a page. An offset of zero is the first
// page.
//
// The default and the maximum are parameters because they differ by list:
// streams and checkpoints cap at 200, the rest at 1000. What is the same
// everywhere is how a bad number is treated.
func pageBounds(limit, offset, defaultLimit, maxLimit int) (int, int, error) {
	if limit < 0 || offset < 0 {
		return 0, 0, &fcontract.Error{Code: fcontract.CodeBadRequest, Message: "limit and offset cannot be negative"}
	}
	if limit == 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	return limit, offset, nil
}
