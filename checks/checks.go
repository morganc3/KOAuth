package checks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

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

func Init(checkJSONFile string) {
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
		checks.Checks[i].FlowInstance = oauth.NewInstance(responseType)

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

func GetResults() {
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

// pkce downgrade sha256 -> plain
// pkce downgrade (stop using pkce at all)

// client secret not required

// Changes redirect URI, checks if we are still redirected
