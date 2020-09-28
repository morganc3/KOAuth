package main

import "net/url"

// Check names
const (
	RedirectURIChange = ""
)

type CheckFunction func(*FlowInstance)

type Check struct {
	CheckName       string
	RiskRating      string
	ConfidenceLevel string
	FlowInstance    *FlowInstance
	CheckFunc       CheckFunction
}

func NewCheck(name, risk, confidence string, checkFunction CheckFunction) *Check {
	check := &Check{
		CheckName:       name,
		RiskRating:      risk,
		ConfidenceLevel: confidence,
		CheckFunc:       checkFunction,
	}
	return check
}

func (c *Check) DoCheck() {
	c.CheckFunc(c.FlowInstance)
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

func redirectURITotalChange(fi *FlowInstance) {
	newRedirectURI := url.QueryEscape("http://example2.com")
	fi.SetQueryParameter(REDIRECT_URI, newRedirectURI)
	fi.DoAuthorizationRequest()
}
