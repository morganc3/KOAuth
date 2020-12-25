package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/chromedp/chromedp"
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
	CheckName    string              `json:"name"`
	RiskRating   string              `json:"risk"`
	Description  string              `json:"description"`
	SkipReason   string              `json:"skipReason,omitempty"`
	FlowType     string              `json:"flowType"`
	References   string              `json:"references,omitempty"`
	FlowInstance *oauth.FlowInstance `json:"-"`
	CheckFunc    CheckFunction       `json:"-"`

	// Output message giving information about why the check failed
	FailMessage string `json:"-"`

	// Output message giving information about an error that occurred during
	// the check
	ErrorMessage string `json:"-"`

	// State contains result of the check
	State `json:"-"`
}

func Init(checkJSONFile string, ctx context.Context, cancel context.CancelFunc) {
	Mappings = getMappings()
	// read checkJSONfile and marshal
	jsonFile, err := os.Open(checkJSONFile)
	if err != nil {
		log.Fatal("Error opening checks JSON file")
	}
	defer jsonFile.Close()
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatal("Error reading checks JSON file")
	}
	var checks ChecksIn
	err = json.Unmarshal(byteValue, &checks)
	if err != nil {
		log.Fatal("Error unmarshalling check JSON file")
	}

	currCtx := ctx
	for i, c := range checks.Checks {
		checks.Checks[i].CheckFunc = getMapping(c.CheckName)
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
		checks.Checks[i].FlowInstance = oauth.NewInstance(newCtx, newCancel, responseType)
		currCtx = newCtx

		// append pointer to the check to our list
		ChecksList = append(ChecksList, &checks.Checks[i])
	}

}

// Perform check, check returns bool for if it was passed
func (c *Check) DoCheck() {
	state, err := c.CheckFunc(c.FlowInstance)
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

// print Check results nicely to console
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

// add new redirect URI param
// change redirect uri protocol to http from https
// change redirect URI entirely
// change redirect URI subdomain
// change redirect URI path
// check if redirect URI allows http at all, to begin with
// multiple redirect uri's

// iframes allowed at consent url
// state not supported

// pkce only supported for implicit
// pkce downgrade sha256 -> plain
// pkce downgrade (stop using pkce at all)

// client secret not required

// Changes redirect URI, checks if we are still redirected
