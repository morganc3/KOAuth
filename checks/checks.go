package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"

	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/config"
	"github.com/morganc3/KOAuth/oauth"
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

var ChecksList []*Check

type ChecksIn struct {
	Checks []Check `json:"checks"`
}

type Check struct {
	CheckName   string `json:"name"`
	RiskRating  string `json:"risk"`
	Description string `json:"description"`
	SkipReason  string `json:"skipReason,omitempty"`
	FlowType    string `json:"flowType"`
	References  string `json:"references,omitempty"`

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

	// URL to wait to be redirected to. If redirected here, the check "fails"
	WaitForRedirectTo string              `json:"waitForRedirectTo,omitempty"`
	FlowInstance      *oauth.FlowInstance `json:"-"`
	CheckFunc         CheckFunction       `json:"-"`

	// Output message giving information about why the check failed
	FailMessage string `json:"-"`

	// Output message giving information about an error that occurred during
	// the check
	ErrorMessage string `json:"errorMessage,omitempty"`

	// State contains result of the check
	State `json:"-"`
}

func Init(checkJSONFile string, ctx context.Context, cancel context.CancelFunc, promptFlag string) {
	Mappings = getMappings()
	jsonBytes := config.GenerateChecksInput(checkJSONFile)
	if len(jsonBytes) <= 0 {
		log.Fatalf("Error opening or parsing JSON file")
	}
	var checks []Check
	err := json.Unmarshal(jsonBytes, &checks)
	if err != nil {
		log.Fatalf("Error unmarshalling check JSON file:\n%s\n", err.Error())
	}

	currCtx := ctx
	for i, c := range checks {
		checks[i].CheckFunc = getMapping(c.CheckName)
		var responseType oauth.FlowType
		switch c.FlowType {
		case "authorization-code":
			responseType = oauth.AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE
		case "implicit":
			responseType = oauth.IMPLICIT_FLOW_RESPONSE_TYPE
		default:
			log.Fatalf("Invalid flow type given for check %s", c.CheckName)
		}

		// make a new context child for each tabs
		// update ctx to the current context of the new instance
		newCtx, newCancel := chromedp.NewContext(currCtx)
		checks[i].FlowInstance = oauth.NewInstance(newCtx, newCancel, responseType, promptFlag)
		currCtx = newCtx

		// append pointer to the check to our list
		ChecksList = append(ChecksList, &checks[i])
	}

}

// Perform check, check returns bool for if it was passed
func (c *Check) DoCheck() {
	var state State
	var err error
	if c.CheckFunc != nil {
		state, err = c.CheckFunc(c.FlowInstance)
	} else {
		state, err = c.RunCheck()
	}
	c.State = state
	if err != nil {
		c.ErrorMessage = err.Error()
	}
}

func DoChecks() {
	for _, c := range ChecksList {
		c.DoCheck()
	}
}

// Write Check results in JSON format to file
func WriteResults(outfile string) {

	type CheckOut struct {
		CheckName    string `json:"name"`
		RiskRating   string `json:"risk"`
		Description  string `json:"description"`
		SkipReason   string `json:"skipReason,omitempty"`
		References   string `json:"references,omitempty"`
		FailMessage  string `json:"failMessage,omitempty"`
		ErrorMessage string `json:"errorMessage,omitempty"`
		State        `json:"state"`
	}

	var outList []CheckOut
	for _, c := range ChecksList {
		// only want to output some fields, so
		// marhsal Check struct to bytes, then unmarshal it back to tmp struct
		// then marshal to bytes and write to file

		var outCheck CheckOut
		if c.State != SKIP {
			c.SkipReason = ""
		}

		bslice, err := json.Marshal(c)
		if err != nil {
			log.Fatalf("Could not Marshal to JSON for Check %s\n", c.CheckName)
		}

		err = json.Unmarshal(bslice, &outCheck)
		if err != nil {
			log.Fatalf("Could not Unmarshal to JSON to output format for  %s\n", c.CheckName)
		}
		outCheck.State = c.State
		outList = append(outList, outCheck)
	}

	bslice, err := json.Marshal(outList)
	err = ioutil.WriteFile(outfile, bslice, 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Output has been saved to %s\n", outfile)
}

// print Check results to console
func PrintResults() {
	for _, c := range ChecksList {
		fmt.Println(c.CheckName, c.State)
		if c.State == WARN {
			fmt.Println("\t", c.ErrorMessage)
		}
		fmt.Println("")
	}
}

// TODO checks:

// iframes allowed at consent url
// state not supported

// pkce only supported for implicit
// pkce downgrade sha256 -> plain
// pkce downgrade (stop using pkce at all)

// client secret not required

// Changes redirect URI, checks if we are still redirected

// TODO: There should be error checking here for
// different errors, such as if we get an "error" URL parameter
// returned in redirect URI, or if there is an internal error
func (c *Check) RunCheck() (State, error) {
	// TODO check if should skip the check
	// documentation should be added to say if a check in some cases should be
	// skipped, we should add a skipMessage in checks.json and a skipfunction
	// to detect if it should be skipped
	fi := c.FlowInstance
	authzUrl := fi.AuthorizationURL

	// first delete any "required" auth URL parameters that we have specfically
	// defined in the check to be deleted
	deleteRequiredParams(authzUrl, c.DeleteAuthURLParams)

	// now, add additional URL parameters defined in the check
	addAuthURLParams(authzUrl, c.AuthURLParams)

	// set the redirect_uri value we will wait to be redirected to
	// if none was provided, this will default to the value in the redirect_uri URL parameter
	c.setExpectedRedirectUri()

	var err error
	switch c.FlowType {
	case "authorization-code":
		c.AddDefaultExchangeParams()
		deleteRequiredExchangeParams(c.TokenExchangeParams, c.DeleteTokenExchangeParams)
		addTokenExchangeParams(c.TokenExchangeParams, c.TokenExchangeExtraParams)
		err = fi.DoAuthorizationRequest()
		if err != nil {
			return WARN, err
		}

		// if we were not redirected
		if fi.RedirectedToURL.String() == "" {
			return WARN, errors.New("Was not redirected during authorization code flow check")
		}

		redirectedTo := fi.RedirectedToURL
		authorizationCode := oauth.GetQueryParameterFirst(redirectedTo, oauth.AUTHORIZATION_CODE)
		// set authorization code from redirect uri
		c.TokenExchangeParams[oauth.AUTHORIZATION_CODE] = []string{authorizationCode}

		// perform exchange
		tok, err := fi.Exchange(context.TODO(), c.TokenExchangeParams)

		if err != nil {
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
			return WARN, err
		}

		// if we were redirected
		if fi.RedirectedToURL.String() != "" {
			return FAIL, nil
		}

		return PASS, nil
	}

	// should never get here
	return WARN, errors.New("Something went wrong")
}

// Chrome checks if implicit flow tests pass by if we are redirected
// to the expected redirect URI without an error. This sets
// which redirect URI we should be waiting to be redirected to.
func (c *Check) setExpectedRedirectUri() {
	if len(c.WaitForRedirectTo) > 0 {
		// if we have specifically set the parameter in checks.json
		// to have a URL we are waiting to be redirected to
		// this is useful for cases where, for example, we provide
		// two redirect_uri parameters (one valid and one invalid) as part of a test.
		maliciousRedirectURI, err := url.Parse(c.WaitForRedirectTo)
		if err != nil {
			log.Fatalf("Bad WaitForRedirectTo value\n")
		}
		c.FlowInstance.ProvidedRedirectURL = maliciousRedirectURI
	} else {
		ur := c.FlowInstance.AuthorizationURL
		// addAuthURLPArams() is called before this, so we can search for the
		// redirect_uri parameter in the URL in the normal case
		redirectUriStr := oauth.GetQueryParameterFirst(ur, oauth.REDIRECT_URI)
		redirectUri, err := url.Parse(redirectUriStr)
		if err != nil {
			log.Fatalf("Bad redirect_uri param\n")
		}
		c.FlowInstance.ProvidedRedirectURL = redirectUri
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

func (c *Check) AddDefaultExchangeParams() {
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"redirect_uri": {c.FlowInstance.ProvidedRedirectURL.String()},
	}
	c.TokenExchangeParams = v

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
