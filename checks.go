package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/url"

	"golang.org/x/oauth2"
)

type CheckFunction func(*FlowInstance) (bool, error)

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

// Perform check, check returns bool for if it was passed
func (c *Check) DoCheck() {
	pass, err := c.CheckFunc(c.FlowInstance)
	c.Pass = pass
	if err != nil {
		switch err.Error() {
		case CONTEXT_TIMEOUT_ERROR:
			log.Printf("%s - Check timed out\n", c.CheckName)
		default:
			log.Printf("%s - %s\n", c.CheckName, err.Error())
		}
	}
}

func DoChecks(checkList []*Check) {
	for _, c := range checkList {
		c.DoCheck()
	}
}

// TODO checks:

// add new redirect URI param
// change redirect uri protocol to http from https
// change redirect URI entirely
// change redirect URI subdomain
// change redirect URI path
// check if redirect URI allows http at all, to begin with

// iframes allowed at consent url
// state not supported

// pkce not supported
// pkce downgrade sha256 -> plain
// pkce downgrade (stop using pkce at all)

// Changes redirect URI, checks if we are still redirected
func redirectURICheck(fi *FlowInstance, redirectUri string) (bool, error) {
	maliciousRedirectURI, _ := url.Parse(redirectUri)
	SetQueryParameter(fi.AuthorizationURL, REDIRECT_URI, maliciousRedirectURI.String())
	err := fi.DoAuthorizationRequest()

	redirectedTo := fi.RedirectedToURL
	// if we are redirected to our malicious redirectURI,
	// then the check failed
	pass := redirectedTo.Host != maliciousRedirectURI.Host
	return pass, err
}

// totally change redirect URI
func redirectURITotalChange(fi *FlowInstance) (bool, error) {
	return redirectURICheck(fi, "http://fakedomain123321.com/callback")
}

func redirectURISchemeDowngrade(fi *FlowInstance) (bool, error) {
	uri, _ := url.Parse(config.OAuthConfig.RedirectURL)
	if uri.Scheme == "https" {
		uri.Scheme = "http"
	} else {
		return true, nil
	}
	uriStr := uri.String()

	return redirectURICheck(fi, uriStr)
}

// checks if state is supported
// ones like these should probably run for bth imlpicit and authz code ?
func stateSupported(fi *FlowInstance) (bool, error) {
	// we send state by default
	err := fi.DoAuthorizationRequest()
	redirectedTo := fi.RedirectedToURL

	stateSent := GetQueryParameterFirst(fi.AuthorizationURL, STATE)
	stateReturned := GetQueryParameterFirst(redirectedTo, STATE)

	pass := stateSent == stateReturned
	return pass, err
}

// checks if pkce is supported
func pkceSupported(fi *FlowInstance) (bool, error) {
	// TODO probably add helper function here to add pkce params
	data := []byte("random-code-verifier-value-asdasdasdasd")
	hash := sha256.Sum256(data)

	pkceCodeChallenge := hex.EncodeToString(hash[:])
	SetQueryParameter(fi.AuthorizationURL, PKCE_CODE_CHALLENGE, pkceCodeChallenge)
	SetQueryParameter(fi.AuthorizationURL, PKCE_CODE_CHALLENGE_METHOD, PKCE_S256)

	err := fi.DoAuthorizationRequest()
	if err != nil {
		return false, err
	}
	redirectedTo := fi.RedirectedToURL

	authorizationCode := GetQueryParameterFirst(redirectedTo, AUTHORIZATION_CODE)
	opt := oauth2.SetAuthURLParam(PKCE_CODE_VERIFIER, string(data))
	opt2 := oauth2.SetAuthURLParam(PKCE_CODE_CHALLENGE_METHOD, PKCE_S256)
	tok, err := config.OAuthConfig.Exchange(context.TODO(), authorizationCode, opt, opt2)
	pass := false
	if err != nil {
		return pass, err
	}
	if err == nil && len(tok.AccessToken) > 0 {
		pass = true
	}

	return pass, err
}
