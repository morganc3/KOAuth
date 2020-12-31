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
	Checks []Check `json:"checks"`
}

type Check struct {
	CheckName   string `json:"name"`
	RiskRating  string `json:"risk"`
	Description string `json:"description"`
	SkipReason  string `json:"skipReason,omitempty"`
	References  string `json:"references,omitempty"`

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
		ChecksList = append(ChecksList, &checks[i])
	}

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
func (c *Check) RunCheck() State {
	// TODO check if should skip the check
	// documentation should be added to say if a check in some cases should be
	// skipped, we should add a skipMessage in checks.json and a skipfunction
	// to detect if it should be skipped

	for i, step := range c.Steps {
		state, _ := step.runStep()
		c.Steps[i].State = state
		if step.State == PASS && step.RequiredOutcome == OUTCOME_SUCCEED {
			continue
		}
		if step.State != PASS && step.RequiredOutcome == OUTCOME_FAIL {
			continue
		}

		// Check failed
		return FAIL
	}
	return PASS
}
