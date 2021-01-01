package checks

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"

	"github.com/morganc3/KOAuth/oauth"
)

const (
	OUTCOME_FAIL    = "FAIL"
	OUTCOME_SUCCEED = "SUCCEED"
)

type Step struct {
	FlowType string `json:"flowType"`

	// Extra parameters to be added to Auth URL
	AuthURLParams map[string][]string `json:"authUrlParams,omitempty"`

	// Default parameters that should be deleted prior to browsing to Auth URL
	DeleteAuthURLParams []string `json:"deleteUrlParams,omitempty"`

	// Not taken as input, default params required for the code exchange
	TokenExchangeParams url.Values `json:"-"`

	// Extra parameters to be added to the code exchange
	TokenExchangeExtraParams map[string][]string `json:"tokenExchangeExtraParams,omitempty"`

	// Default parameters that should be deleted prior to code exchange
	DeleteTokenExchangeParams []string `json:"deleteExchangeParams,omitempty"`

	// URL to wait to be redirected to
	WaitForRedirectTo string `json:"waitForRedirectTo,omitempty"`

	// URL Parameters that must be in URL we are redirected to
	RedirectMustContainUrl map[string][]string `json:"redirectMustContainUrl,omitempty"`

	// Fragment Parameters that must be in URL we are redirected to
	RedirectMustContainFragment map[string][]string `json:"redirectMustContainFragment,omitempty"`

	FailMessage  string `json:"failMessage,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`

	RequiredOutcome string `json:"requiredOutcome"`

	// State contains result of the step
	State `json:"state"`

	FlowInstance *oauth.FlowInstance `json:"-"`
}

func (s *Step) runStep() (State, error) {
	fi := s.FlowInstance
	authzUrl := fi.AuthorizationURL

	// first delete any "required" auth URL parameters that we have specfically
	// defined in the check to be deleted
	deleteRequiredParams(authzUrl, s.DeleteAuthURLParams)

	// now, add additional URL parameters defined in the check
	addAuthURLParams(authzUrl, s.AuthURLParams)

	// set the redirect_uri value we will wait to be redirected to
	// if none was provided, this will default to the value in the redirect_uri URL parameter
	s.setExpectedRedirectUri()

	var err error
	switch s.FlowType {
	case "authorization-code":
		s.AddDefaultExchangeParams()
		deleteRequiredExchangeParams(s.TokenExchangeParams, s.DeleteTokenExchangeParams)
		addTokenExchangeParams(s.TokenExchangeParams, s.TokenExchangeExtraParams)
		err = fi.DoAuthorizationRequest()
		if err != nil {
			s.ErrorMessage = err.Error()
			return WARN, err
		}

		// if we were not redirected
		if fi.RedirectedToURL.String() == "" {
			s.FailMessage = "Was not redirected during authorization code flow"
			return FAIL, nil
		}

		redirectedTo := fi.RedirectedToURL
		ok, err := s.requiredRedirectParamsPresent(redirectedTo)
		if !ok || err != nil {
			s.ErrorMessage = err.Error()
			return WARN, err
		}

		authorizationCode := oauth.GetQueryParameterFirst(redirectedTo, oauth.AUTHORIZATION_CODE)

		// set authorization code from redirect uri
		s.TokenExchangeParams[oauth.AUTHORIZATION_CODE] = []string{authorizationCode}
		// perform exchange
		tok, err := fi.Exchange(context.TODO(), s.TokenExchangeParams)

		if err != nil {
			s.ErrorMessage = err.Error()
			return WARN, err
		}
		if err == nil && len(tok.AccessToken) > 0 {
			return PASS, nil
		}

		return FAIL, nil

	case "implicit":
		err = fi.DoAuthorizationRequest()
		// this will only be set with a value
		// if we were redirected to the provided redirect_uri
		// therefore, if this is not empty, we were redirected
		// to the malicious URI
		if err != nil {
			s.ErrorMessage = err.Error()
			return WARN, err
		}

		redirectedTo := fi.RedirectedToURL
		// if we were not redirected
		if redirectedTo.String() == "" {
			s.FailMessage = "Was not redirected during implicit flow"
			return FAIL, nil
		}

		ok, err := s.requiredRedirectParamsPresent(redirectedTo)
		if !ok || err != nil {
			s.ErrorMessage = err.Error()
			return WARN, err
		}

		return PASS, nil
	}

	// should never get here
	s.ErrorMessage = "Something went wrong"
	return WARN, errors.New("Something went wrong")
}

// Chrome checks if implicit flow tests pass by if we are redirected
// to the expected redirect URI without an error. This sets
// which redirect URI we should be waiting to be redirected to.
func (s *Step) setExpectedRedirectUri() {
	if len(s.WaitForRedirectTo) > 0 {
		// if we have specifically set the parameter in checks.json
		// to have a URL we are waiting to be redirected to
		// this is useful for cases where, for example, we provide
		// two redirect_uri parameters (one valid and one invalid) as part of a test.
		maliciousRedirectURI, err := url.Parse(s.WaitForRedirectTo)
		if err != nil {
			log.Fatalf("Bad WaitForRedirectTo value\n")
		}
		s.FlowInstance.ProvidedRedirectURL = maliciousRedirectURI
	} else {
		ur := s.FlowInstance.AuthorizationURL
		// addAuthURLPArams() is called before this, so we can search for the
		// redirect_uri parameter in the URL in the normal case
		redirectUriStr := oauth.GetQueryParameterFirst(ur, oauth.REDIRECT_URI)
		redirectUri, err := url.Parse(redirectUriStr)
		if err != nil {
			log.Fatalf("Bad redirect_uri param\n")
		}
		s.FlowInstance.ProvidedRedirectURL = redirectUri
	}
}

// Add URL parameter to authorization URL. If the parameter already
// exists in the URL, this will add an additional.
func addAuthURLParams(authzUrl *url.URL, pm map[string][]string) {
	for key, values := range pm {
		for _, v := range values {
			oauth.AddQueryParameter(authzUrl, key, v)
		}
	}
}

// Delete required parameters that are
// specified to be manually deleted. Parameters should always
// be deleted before new ones are added.
// The following parameters are required and would need
// to be deleted if desired: state, redirect_uri, client_id, scope, response_type
func deleteRequiredParams(authzUrl *url.URL, p []string) {
	for _, d := range p {
		oauth.DelQueryParameter(authzUrl, d)
	}
}

func (s *Step) AddDefaultExchangeParams() {
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"redirect_uri": {s.FlowInstance.ProvidedRedirectURL.String()},
	}
	s.TokenExchangeParams = v

}

func addTokenExchangeParams(v url.Values, pm map[string][]string) {
	for key, values := range pm {
		if len(v[key]) == 0 {
			v[key] = values
		} else {
			v[key] = append(v[key], values...)
		}
	}
}

func deleteRequiredExchangeParams(v url.Values, p []string) {
	for _, d := range p {
		delete(v, d)
	}
}

// Checks if the URL we were redirected to contains the
// parameters defined in the step that it must contain
// Checks RedirectMustContainFragment for implicit flow and
// RedirectMustContainUrl for authorization code flow
func (s *Step) requiredRedirectParamsPresent(redirectedTo *url.URL) (bool, error) {
	var getParamFunc func(*url.URL, string) []string
	var requiredParams map[string][]string
	switch s.FlowType {
	case "authorization-code":
		// If authz code flow, look at query params
		getParamFunc = oauth.GetQueryParameterAll
		requiredParams = s.RedirectMustContainUrl
	case "implicit":
		// If implicit flow, look at fragment params (parameters after "#")
		getParamFunc = oauth.GetFragmentParameterAll
		requiredParams = s.RedirectMustContainFragment
	case "default":
		return false, errors.New("Bad flow type")
	}

	for key, values := range requiredParams {
		redirectUrlVals := getParamFunc(redirectedTo, key)
		for _, v := range values {
			if !sliceContains(redirectUrlVals, v) {
				return false, errors.New(fmt.Sprintf("Missing value %s for key %s.\n", v, key))
			}
		}
	}
	return true, nil
}

// checks if slice of strings contains given string
func sliceContains(list []string, element string) bool {
	for _, item := range list {
		if item == element {
			return true
		}
	}
	return false
}
