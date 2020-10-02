package main

import (
	"crypto/sha256"
	"log"
	"net/url"

	"golang.org/x/oauth2"
)

type CheckFunction func(*FlowInstance) bool

type Check struct {
	CheckName       string
	RiskRating      string
	ConfidenceLevel string
	FlowInstance    *FlowInstance
	CheckFunc       CheckFunction
	Pass            bool
}

func NewCheck(name, risk, confidence string, flowType FlowType, checkFunction CheckFunction) *Check {
	check := &Check{
		CheckName:       name,
		RiskRating:      risk,
		ConfidenceLevel: confidence,
		CheckFunc:       checkFunction,
	}
	check.FlowInstance = NewInstance(flowType)
	return check
}

// TODO - check error in context here
// Perform check, check returns bool for if it was passed
func (c *Check) DoCheck() {
	c.Pass = c.CheckFunc(c.FlowInstance)
}

func DoChecks(checkList []*Check) {
	for _, c := range checkList {
		c.DoCheck()
	}
}

// add new redirect URI param
// change redirect URI entirely
// change redirect URI subdomain
// change redirect URI path

// iframes allowed at consent url

// state not supported

// pkce not supported
// pkce downgrade sha256 -> plain
// pkce downgrade (stop using pkce at all)

// Changes redirect URI, checks if we are still redirected
func redirectURITotalChange(fi *FlowInstance) bool {
	newRedirectURI, _ := url.Parse("http://fakedomain123321.com/callback")

	SetQueryParameter(fi.AuthorizationURL, REDIRECT_URI, newRedirectURI.String())
	fi.DoAuthorizationRequest()

	resp := fi.AuthorizationRequest.Response
	redirectedTo, err := url.Parse(getLocationHeader(resp))
	if err != nil {
		// If we're not redirected at all, check definitely passes
		return true
	}

	// if we are redirected to our malicious redirectURI,
	// then the check failed
	return redirectedTo.Host != newRedirectURI.Host
}

// TODO - These checks need to have an error response value as well.
// checks if state is supported
// ones like these should probably run for bth imlpicit and authz code ?
func stateSupported(fi *FlowInstance) bool {
	// we send state by default
	fi.DoAuthorizationRequest()
	resp := fi.AuthorizationRequest.Response
	redirectedTo, err := url.Parse(getLocationHeader(resp))
	if err != nil {
		// this would really be an error rather than a pass/fail TODO
		log.Println(err)
		return false
	}
	stateSent := GetQueryParameterFirst(fi.AuthorizationRequest.Request.URL, STATE)
	stateReturned := GetQueryParameterFirst(redirectedTo, STATE)

	return stateSent == stateReturned
}

// checks if state is supported
func pkceSupported(fi *FlowInstance) bool {
	// TODO probably add helper function here to add pkce params
	data := []byte("random-code-verifier-value!")
	hash := sha256.Sum256(data)
	pkceCodeChallenge := string(hash[:])
	SetQueryParameter(fi.AuthorizationURL, CODE_CHALLENGE, pkceCodeChallenge)
	SetQueryParameter(fi.AuthorizationURL, CODE_CHALLENGE_METHOD, pkceCodeChallenge)

	fi.DoAuthorizationRequest()
	resp := fi.AuthorizationRequest.Response
	redirectedTo, err := url.Parse(getLocationHeader(resp))
	if err != nil {
		// this would really be an error rather than a pass/fail TODO
		log.Println(err)
		return false
	}
	authorizationCode := GetQueryParameterFirst(redirectedTo, AUTHORIZATION_CODE)
	opt := oauth2.SetAuthURLParam(CODE_CHALLENGE, pkceCodeChallenge)
	tok, err := config.OAuthConfig.Exchange(fi.Ctx, authorizationCode, opt)

	if err != nil || !(len(tok.AccessToken) > 0) {
		return true
	}
	return false
}
