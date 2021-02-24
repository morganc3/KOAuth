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

type State string

const (
	PASS State = "PASS" // Test passed
	FAIL State = "FAIL" // Test failed
	WARN State = "WARN" // Warning, likely some issue with the test
	INFO State = "INFO" // Informational
	SKIP State = "SKIP" // Skipped for some reason
)

type CheckType string

const (
	SUPPORT CheckType = "support" // Check to see if something is supported
	NORMAL  CheckType = "normal"  // Normal check defined by provided JSON check file
	CUSTOM  CheckType = "custom"  // Custom check that is mapped to a Go function
)

var ChecksList []*Check        // List of normal or custom checks
var SupportChecksList []*Check // List of "support" checks

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
	Custom *CustomCheck `json:"-"`

	Steps []Step `json:"steps"`

	// State contains result of the check
	State `json:"-"`

	CheckType CheckType `json:"type,omitempty"`
}

type CustomCheckFunction func(*Check, *context.Context) (State, error)
type CustomCheckContext *context.Context
type CustomCheck struct {
	CheckFunction CustomCheckFunction
	CheckContext  CustomCheckContext
}

func Init(checkJSONFile string, ctx context.Context, promptFlag string) {
	Mappings = getMappings()
	ChecksList = readChecks(ctx, checkJSONFile, promptFlag)

	// Remove checks of type "support" and add them to SupportChecksList
	for i, c := range ChecksList {
		if c.CheckType == SUPPORT {
			ChecksList = append(ChecksList[:i], ChecksList[i+1:]...) // remove
			SupportChecksList = append(SupportChecksList, c)
		}
	}
}

// Perform check, check returns bool for if it was passed
func (c *Check) DoCheck() {
	var state State
	var err error
	if !c.checkSupported() {
		c.SkipReason = "Check skipped due to missing support for checks defined in requiresSupport"
		c.State = SKIP
		return
	}

	if c.Custom != nil {
		state, err = c.Custom.CheckFunction(c, c.Custom.CheckContext)
	} else {
		state = c.RunCheck()
	}
	c.State = state
	if err != nil {
		c.ErrorMessage = err.Error()
	}
}

func DoChecks() {
	for _, c := range SupportChecksList { // Do support checks first to determine support
		c.DoCheck()
	}
	for _, c := range ChecksList { // Do the rest of checks
		c.DoCheck()
	}
}

// print basic Check results to console
func PrintResults() {
	allChecks := append(SupportChecksList, ChecksList...)
	for _, c := range allChecks {
		fmt.Println(c.CheckName, c.State)
		if c.State == WARN {
			fmt.Println("\t", c.ErrorMessage)
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
func (c *Check) RunCheck() State {
	// TODO check if check should be skipped
	// documentation should be added to say if a check in some cases should be
	// skipped, we should add a skipMessage in checks.json and a skipfunction
	// to detect if it should be skipped
	for i, step := range c.Steps {
		state, _ := step.runStep()
		step.State = state
		c.Steps[i] = step
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
	// if this is a support check, return true
	if c.CheckType == SUPPORT {
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
		for _, check := range SupportChecksList {
			switch check.CheckName {
			case "implicit-flow-supported":
				if check.State == PASS {
					supported = append(supported, oauth.FLOW_IMPLICIT)
				}
			case "authorization-code-flow-supported":
				if check.State == PASS {
					supported = append(supported, oauth.FLOW_AUTHORIZATION_CODE)
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
		case oauth.FLOW_IMPLICIT:
			if !sliceContains(supportedFlows, oauth.FLOW_IMPLICIT) {
				return false
			}
		case oauth.FLOW_AUTHORIZATION_CODE:
			if !sliceContains(supportedFlows, oauth.FLOW_AUTHORIZATION_CODE) {
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
	for _, c := range SupportChecksList {
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

	var ret []*Check
	err := json.Unmarshal(jsonBytes, &ret)
	if err != nil {
		log.Fatalf("Error unmarshalling check JSON file:\n%s\n", err.Error())
	}

	ret, ctx = processChecks(ctx, ret, promptFlag)

	return ret
}

func processChecks(ctx context.Context, checks []*Check, promptFlag string) ([]*Check, context.Context) {
	var ret []*Check
	currCtx := ctx
	for i, c := range checks {
		if c.CheckType == "" {
			c.CheckType = NORMAL
		}

		switch c.CheckType {
		case CUSTOM:
			funcMapping := getMapping(c.CheckName)
			if funcMapping == nil {
				log.Fatal("No function mapping found for check of type CUSTOM")
			}
			newCtx, _ := chromedp.NewContext(currCtx)
			cust := CustomCheck{
				CheckFunction: getMapping(c.CheckName),
				CheckContext:  &newCtx,
			}
			c.Custom = &cust
		default: // normal or support checks
			for j, s := range c.Steps {
				var responseType oauth.FlowType
				switch s.FlowType {
				case oauth.FLOW_AUTHORIZATION_CODE:
					responseType = oauth.AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE
				case oauth.FLOW_IMPLICIT:
					responseType = oauth.IMPLICIT_FLOW_RESPONSE_TYPE
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
