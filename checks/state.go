package checks

import (
	"github.com/morganc3/KOAuth/oauth"
)

// checks if state is supported
func StateSupported(fi *oauth.FlowInstance) (State, error) {
	// we send state by default
	err := fi.DoAuthorizationRequest()
	if err != nil {
		return WARN, err
	}
	redirectedTo := fi.RedirectedToURL
	stateSent := oauth.GetQueryParameterFirst(fi.AuthorizationURL, oauth.STATE)
	stateReturned := oauth.GetQueryParameterFirst(redirectedTo, oauth.STATE)

	if stateSent == stateReturned {
		return PASS, nil
	}
	return FAIL, err
}
