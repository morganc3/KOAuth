package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

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
	SupportChecks []Check `json:"supportChecks"`
	Checks        []Check `json:"checks"`
}

type Check struct {
	CheckName   string `json:"name"`
	RiskRating  string `json:"risk"`
	Description string `json:"description"`
	SkipReason  string `json:"skipReason,omitempty"`
	References  string `json:"references,omitempty"`

	// "Support" checks that must have succeeded
	// For example, checks involving PKCE won't run unless
	// the PKCE support check succeeds
	RequiresSupport []string `json:"requiresSupport,omitempty"`

	// Output message giving information about why the check failed
	FailMessage string `json:"-"`

	// Output message giving information about an error that occurred during
	// the check
	ErrorMessage string `json:"errorMessage,omitempty"`

	// Custom defined check function
	CheckFunc CheckFunction `json:"-"`

	Steps []Step `json:"steps,omitempty"`

	// State contains result of the check
	State `json:"-"`
}

func Init(checkJSONFile string, ctx context.Context, promptFlag string) {
	Mappings = getMappings()
	ChecksList = readChecks(ctx, checkJSONFile, promptFlag)
}

// Perform check, check returns bool for if it was passed
func (c *Check) DoCheck() {
	var state State
	var err error
	if c.CheckFunc != nil {
		// TODO: fix now that we're using steps
		// state, err = c.CheckFunc(c.FlowInstance)
	} else {
		state = c.RunCheck()
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
		Steps        []Step `json:"steps,omitempty"`
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

// TODO: checks for things like redirect should be able to use either implicit or authz.

// TODO checks:
// iframes allowed at consent url

// pkce only supported for implicit
// pkce downgrade sha256 -> plain
// pkce downgrade (stop using pkce at all)

// client secret not required

// Changes redirect URI, checks if we are still redirected

// TODO: There should be error checking here for
// different errors, such as if we get an "error" URL parameter
// returned in redirect URI, or if there is an internal error
func (c *Check) RunCheck() State {
	// TODO check if should skip the check
	// documentation should be added to say if a check in some cases should be
	// skipped, we should add a skipMessage in checks.json and a skipfunction
	// to detect if it should be skipped

	if !c.checkSupported() {
		c.SkipReason = "Check skipped due to missing support for checks defined in requiresSupport"
		return SKIP
	}

	for i, step := range c.Steps {
		state, _ := step.runStep()
		c.Steps[i].State = state
		if state == PASS && step.RequiredOutcome == OUTCOME_SUCCEED {
			continue
		}
		if state != PASS && step.RequiredOutcome == OUTCOME_FAIL {
			continue
		}

		// Check failed
		return FAIL
	}
	return PASS
}

// Checks if required support checks passed
func (c *Check) checkSupported() bool {
	requires := c.RequiresSupport

	// does not require any other checks to be supported
	if len(requires) == 0 {
		return true
	}

	for _, r := range requires {
		if !supportExists(r) {
			return false
		}
	}

	return true
}

// Checks if required support check passed
func supportExists(name string) bool {
	for _, c := range ChecksList {
		if name == c.CheckName && c.State == PASS {
			return true
		}
	}
	return false
}

func readChecks(ctx context.Context, checkFile, promptFlag string) []*Check {
	jsonBytes := config.GenerateChecksInput(checkFile)
	if len(jsonBytes) <= 0 {
		log.Fatalf("Error opening or parsing JSON file")
	}

	var checksIn ChecksIn

	var ret []*Check
	err := json.Unmarshal(jsonBytes, &checksIn)
	if err != nil {
		log.Fatalf("Error unmarshalling check JSON file:\n%s\n", err.Error())
	}

	supportChecks, ctx := processChecks(ctx, checksIn.SupportChecks, promptFlag)
	checks, ctx := processChecks(ctx, checksIn.Checks, promptFlag)

	ret = append(ret, supportChecks...)
	ret = append(ret, checks...)
	return ret
}

func processChecks(ctx context.Context, checks []Check, promptFlag string) ([]*Check, context.Context) {
	var ret []*Check
	currCtx := ctx
	for i, c := range checks {
		for j, s := range c.Steps {
			var responseType oauth.FlowType
			switch s.FlowType {
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
			checks[i].Steps[j].FlowInstance = oauth.NewInstance(newCtx, newCancel, responseType, promptFlag)
			currCtx = newCtx
		}
		checks[i].CheckFunc = getMapping(c.CheckName)

		// append pointer to the check to our list
		ret = append(ret, &checks[i])
	}
	return ret, currCtx
}
