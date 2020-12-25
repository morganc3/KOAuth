package oauth

import (
	"errors"
	"fmt"
)

const (
	CONTEXT_TIMEOUT_ERROR   = "context deadline exceeded"
	CONTEXT_CANCELLED_ERROR = "context canceled"
	NOT_REDIRECTED          = "Browser was never redirected to the provided redirect_uri"
)

func (i *FlowInstance) GetURLError() error {
	if i.RedirectedToURL == nil {
		return errors.New(NOT_REDIRECTED)
	}

	errorType := GetFragmentParameterFirst(i.RedirectedToURL, "error")
	errorDescription := GetFragmentParameterFirst(i.RedirectedToURL, "error_description")

	if len(errorType) > 0 || len(errorDescription) > 0 {
		return errors.New(fmt.Sprintf("%s: %s", errorType, errorDescription))
	}
	return nil
}
