package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/url"

	"github.com/morganc3/KOAuth/config"
	"github.com/morganc3/KOAuth/oauth"
	"golang.org/x/oauth2"
)

type CheckFunction func(*oauth.FlowInstance) (State, error)

type State string

const (
	PASS State = "PASS" // Test passed
	FAIL State = "FAIL" // Test failed
	WARN State = "WARN" // Warning, likely some issue with the test
	INFO State = "INFO" // Informational
	SKIP State = "SKIP" // Skipped for some reason
)

type Check struct {
	CheckName       string
	RiskRating      string
	ConfidenceLevel string
	FlowInstance    *oauth.FlowInstance
	CheckFunc       CheckFunction
	State
}

func NewCheck(name, risk, confidence string, flowType oauth.FlowType, checkFunction CheckFunction) *Check {
	check := &Check{
		CheckName:       name,
		RiskRating:      risk,
		ConfidenceLevel: confidence,
		CheckFunc:       checkFunction,
	}
	check.FlowInstance = oauth.NewInstance(flowType)
	return check
}

// Perform check, check returns bool for if it was passed
func (c *Check) DoCheck() {
	state, err := c.CheckFunc(c.FlowInstance)
	c.State = state
	if err != nil {
		switch err.Error() {
		case oauth.CONTEXT_TIMEOUT_ERROR:
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
func RedirectURICheck(fi *oauth.FlowInstance, redirectUri string) (State, error) {
	maliciousRedirectURI, _ := url.Parse(redirectUri)
	oauth.SetQueryParameter(fi.AuthorizationURL, oauth.REDIRECT_URI, maliciousRedirectURI.String())
	err := fi.DoAuthorizationRequest()
	if err != nil {
		return WARN, err
	}

	redirectedTo := fi.RedirectedToURL
	// if we are redirected to our malicious redirectURI,
	// then the check failed
	if redirectedTo.Host != maliciousRedirectURI.Host {
		return PASS, nil
	}
	return FAIL, err
}

// totally change redirect URI
func RedirectURITotalChange(fi *oauth.FlowInstance) (State, error) {
	return RedirectURICheck(fi, "http://fakedomain123321.com/callback")
}

func RedirectURISchemeDowngrade(fi *oauth.FlowInstance) (State, error) {
	uri, _ := url.Parse(config.Config.OAuthConfig.RedirectURL)
	if uri.Scheme == "https" {
		uri.Scheme = "http"
	} else {
		return INFO, nil
	}
	uriStr := uri.String()

	return RedirectURICheck(fi, uriStr)
}

// checks if state is supported
// ones like these should probably run for bth imlpicit and authz code ?
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

// checks if pkce is supported
func PkceSupported(fi *oauth.FlowInstance) (State, error) {
	// TODO probably add helper function here to add pkce params
	data := []byte("random-code-verifier-value-asdasdasdasd")
	hash := sha256.Sum256(data)

	pkceCodeChallenge := hex.EncodeToString(hash[:])
	oauth.SetQueryParameter(fi.AuthorizationURL, oauth.PKCE_CODE_CHALLENGE, pkceCodeChallenge)
	oauth.SetQueryParameter(fi.AuthorizationURL, oauth.PKCE_CODE_CHALLENGE_METHOD, oauth.PKCE_S256)

	err := fi.DoAuthorizationRequest()
	if err != nil {
		return WARN, err
	}
	redirectedTo := fi.RedirectedToURL

	authorizationCode := oauth.GetQueryParameterFirst(redirectedTo, oauth.AUTHORIZATION_CODE)
	opt := oauth2.SetAuthURLParam(oauth.PKCE_CODE_VERIFIER, string(data))
	opt2 := oauth2.SetAuthURLParam(oauth.PKCE_CODE_CHALLENGE_METHOD, oauth.PKCE_S256)
	tok, err := config.Config.OAuthConfig.Exchange(context.TODO(), authorizationCode, opt, opt2)
	if err != nil {
		return WARN, err
	}
	if err == nil && len(tok.AccessToken) > 0 {
		return PASS, nil
	}

	return FAIL, err
}
