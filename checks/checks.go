package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/config"
	"github.com/morganc3/KOAuth/oauth"
)

type state string

const (
	pass state = "PASS" // Test passed
	fail state = "FAIL" // Test failed
	warn state = "WARN" // Warning, likely some issue with the test
	info state = "INFO" // Informational
	skip state = "SKIP" // Skipped for some reason
)

type checkType string

const (
	support checkType = "support" // Check to see if something is supported
	normal  checkType = "normal"  // Normal check defined by provided JSON check file
	custom  checkType = "custom"  // Custom check that is mapped to a Go function
)

var checksList []*check        // List of normal or custom checks
var supportChecksList []*check // List of "support" checks

type check struct {
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
	failMessage string `json:"-"`

	// Output message giving information about an error that occurred during
	// the check
	errorMessage string `json:"-"`

	// Custom defined check function
	custom *customCheck `json:"-"`

	Steps []step `json:"steps"`

	// State contains result of the check
	state `json:"-"`

	CheckType checkType `json:"type,omitempty"`
}

type customCheckFunction func(*check, *context.Context) (state, error)
type customCheckContext *context.Context
type customCheck struct {
	checkFunction customCheckFunction
	checkContext  customCheckContext
}

// Init - initializes checks by reading checks from files, identifying
// custom definitions for checks, setting up support checks
func Init(ctx context.Context, checkJSONFile string, promptFlag string) {
	mappings = getMappings()
	checksList = readChecks(ctx, checkJSONFile, promptFlag)

	// Remove checks of type "support" and add them to SupportChecksList
	// TODO: do this during reading checks so we don't have to remove later
	for i, c := range checksList {
		if c.CheckType == support {
			checksList = append(checksList[:i], checksList[i+1:]...) // remove
			supportChecksList = append(supportChecksList, c)
		}
	}
}

// identifies if a check is supported, if so, runs the check
func (c *check) doCheck() {
	var state state
	var err error
	if !c.checkSupported() {
		c.SkipReason = "Check skipped due to missing support for checks defined in requiresSupport"
		c.state = skip
		return
	}

	if c.custom != nil {
		state, err = c.custom.checkFunction(c, c.custom.checkContext)
	} else {
		state = c.runCheck()
	}
	c.state = state
	if err != nil {
		c.errorMessage = err.Error()
	}
}

// DoChecks - completes each support check, followed by other checks
func DoChecks() {
	for _, c := range supportChecksList { // Do support checks first to determine support
		c.doCheck()
	}
	for _, c := range checksList { // Do the rest of checks
		c.doCheck()
	}
}

// PrintResults - print basic Check results to console
func PrintResults() {
	allChecks := append(supportChecksList, checksList...)
	for _, c := range allChecks {
		fmt.Println(c.CheckName, c.state)
		if c.state == warn {
			fmt.Println("\t", c.errorMessage)
		}
		fmt.Println("")
	}
}

// TODO checks:
// scopes reflected at consent url
// client secret not required

// TODO: There should be error checking here for
// different errors, such as if we get an "error" URL parameter
// returned in redirect URI, or if there is an internal error

// runCheck - runs each step of a check, returning the
// state of the check, indicating its outcome
func (c *check) runCheck() state {
	// TODO check if check should be skipped
	// documentation should be added to say if a check in some cases should be
	// skipped, we should add a skipMessage in checks.json and a skipfunction
	// to detect if it should be skipped
	for i, step := range c.Steps {
		state, _ := step.runStep()
		step.state = state
		c.Steps[i] = step
		if state == pass && step.RequiredOutcome == outcomeSucceed {
			continue
		}
		if state != pass && step.RequiredOutcome == outcomeFail {
			continue
		}

		// Check failed
		return fail
	}
	return pass
}

// Checks if required support checks passed
func (c *check) checkSupported() bool {
	// if this is a support check, return true
	if c.CheckType == support {
		return true
	}
	requires := c.RequiresSupport

	// Checks if "supportCheck" passed for
	// whatever checks are required
	for _, r := range requires {
		if !supportExists(r) {
			return false
		}
	}

	// Anonymous function so that this isn't used anywhere else,
	// as it shouldn't be used unless all support checks have already been run
	getSupportedFlows := func() []string {
		supported := []string{}
		for _, check := range supportChecksList {
			switch check.CheckName {
			case "implicit-flow-supported":
				if check.state == pass {
					supported = append(supported, oauth.FlowImplicit)
				}
			case "authorization-code-flow-supported":
				if check.state == pass {
					supported = append(supported, oauth.FlowAuthorizationCode)
				}
			}
		}
		return supported
	}
	supportedFlows := getSupportedFlows()

	// no flow types are supported
	if len(supportedFlows) == 0 {
		return false
	}

	// Check if any flow type is available to support the steps of
	// this check
	for i, s := range c.Steps {
		switch s.FlowType {
		case oauth.FlowImplicit:
			if !sliceContains(supportedFlows, oauth.FlowImplicit) {
				return false
			}
		case oauth.FlowAuthorizationCode:
			if !sliceContains(supportedFlows, oauth.FlowAuthorizationCode) {
				return false
			}
		default:
			// This is the case where a flowtype for a step was not set,
			// so just update it to whatever flowtype is supported
			c.Steps[i].FlowType = supportedFlows[0]
			flowInstance := c.Steps[i].FlowInstance
			flowInstance.UpdateFlowType(supportedFlows[0])

			return true
		}
	}

	return true
}

// Checks if required support check passed
func supportExists(name string) bool {
	for _, c := range supportChecksList {
		if name == c.CheckName && c.state == pass {
			return true
		}
	}
	return false
}

func readChecks(ctx context.Context, checkFile, promptFlag string) []*check {
	jsonBytes := config.GenerateChecksInput(checkFile)
	if len(jsonBytes) <= 0 {
		log.Fatalf("Error opening or parsing JSON file")
	}

	var ret []*check
	err := json.Unmarshal(jsonBytes, &ret)
	if err != nil {
		log.Fatalf("Error unmarshalling check JSON file:\n%s\n", err.Error())
	}

	ret, ctx = processChecks(ctx, ret, promptFlag)

	return ret
}

func processChecks(ctx context.Context, checks []*check, promptFlag string) ([]*check, context.Context) {
	var ret []*check
	currCtx := ctx
	for i, c := range checks {
		if c.CheckType == "" {
			c.CheckType = normal
		}

		switch c.CheckType {
		case custom:
			funcMapping := getMapping(c.CheckName)
			if funcMapping == nil {
				log.Fatal("No function mapping found for check of type CUSTOM")
			}
			newCtx, _ := chromedp.NewContext(currCtx)
			cust := customCheck{
				checkFunction: getMapping(c.CheckName),
				checkContext:  &newCtx,
			}
			c.custom = &cust
		default: // normal or support checks
			for j, s := range c.Steps {
				var responseType oauth.FlowType
				switch s.FlowType {
				case oauth.FlowAuthorizationCode:
					responseType = oauth.AuthorizationCodeFlowResponseType
				case oauth.FlowImplicit:
					responseType = oauth.ImplicitFlowResponseType
				default:
					// if malformed or empty, leave this empty.
					// support will be determined later, and
					// this will be updated in the Step.runStep() method
					responseType = ""
				}
				// make a new context child for each tabs
				// update ctx to the current context of the new instance
				newCtx, newCancel := chromedp.NewContext(currCtx)
				checks[i].Steps[j].FlowInstance = oauth.NewInstance(newCtx, newCancel, responseType, promptFlag)
				currCtx = newCtx
			}
		}

		// append pointer to the check to our list
		ret = append(ret, checks[i])
	}
	return ret, currCtx
}
