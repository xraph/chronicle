package handler

import (
	"errors"

	"github.com/xraph/forge"

	"github.com/xraph/chronicle"
)

// mapStoreError converts chronicle sentinel errors to forge HTTP errors.
func mapStoreError(err error) error {
	if err == nil {
		return nil
	}

	if isNotFound(err) {
		return forge.NotFound(err.Error())
	}
	if errors.Is(err, chronicle.ErrInvalidQuery) {
		return forge.BadRequest(err.Error())
	}
	if errors.Is(err, chronicle.ErrUnauthorized) {
		return forge.NewHTTPError(401, err.Error())
	}

	return err
}

// isNotFound returns true if the error is a "not found" sentinel.
func isNotFound(err error) bool {
	return errors.Is(err, chronicle.ErrEventNotFound) ||
		errors.Is(err, chronicle.ErrStreamNotFound) ||
		errors.Is(err, chronicle.ErrPolicyNotFound) ||
		errors.Is(err, chronicle.ErrReportNotFound) ||
		errors.Is(err, chronicle.ErrErasureNotFound) ||
		errors.Is(err, chronicle.ErrSubjectNotFound)
}
