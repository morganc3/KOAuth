package main

import (
	"log"
	"net/url"
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

// state not supported

// pkce not supported
// pkce downgrade

// Changes redirect URI, checks if we are still redirected
func redirectURITotalChange(fi *FlowInstance) bool {
	newRedirectURI, _ := url.Parse("http://fakedomain123321.com/callback")

	SetQueryParameter(fi.AuthorizationURL, REDIRECT_URI, newRedirectURI.String())
	fi.DoAuthorizationRequest()

	resp := fi.AuthorizationRequest.Response
	redirectedTo, err := url.Parse(GetLocationHeader(resp))
	if err != nil {
		// If we're not redirected at all, check definitely passes
		return true
	}

	// if we are redirected to our malicious redirectURI,
	// then the check failed
	return redirectedTo.Host != newRedirectURI.Host
}

// TODO - These checks need to have an error parameter as well.
// checks if state is supported
// ones like these should probably run for bth imlpicit and authz code ?
func stateSupported(fi *FlowInstance) bool {
	// we send state by default
	fi.DoAuthorizationRequest()
	resp := fi.AuthorizationRequest.Response
	redirectedTo, err := url.Parse(GetLocationHeader(resp))
	if err != nil {
		// this would really be an error rather than a pass/fail TODO
		log.Println(err)
		return false
	}
	stateSent := GetQueryParameterFirst(fi.AuthorizationRequest.Request.URL, STATE)
	stateReturned := GetQueryParameterFirst(redirectedTo, STATE)

	return stateSent == stateReturned
}
