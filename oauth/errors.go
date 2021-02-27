package oauth

import (
	"errors"
	"fmt"
)

// error constants
const (
	ContextTimeoutError   = "context deadline exceeded"
	ContextCancelledError = "context canceled"
	NotRedirectedError    = "Browser was never redirected to the provided redirect_uri"
)

// GetURLError - gets error from URL parameter as defined in the OAuth 2.0 specification
func (i *FlowInstance) GetURLError() error {
	if i.RedirectedToURL == nil {
		return errors.New(NotRedirectedError)
	}

	errorType := GetFragmentParameterFirst(i.RedirectedToURL, "error")
	errorDescription := GetFragmentParameterFirst(i.RedirectedToURL, "error_description")

	if len(errorType) > 0 || len(errorDescription) > 0 {
		return fmt.Errorf("%s: %s", errorType, errorDescription)
	}
	return nil
}
