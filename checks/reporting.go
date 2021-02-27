package checks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"text/template"

	"github.com/morganc3/KOAuth/oauth"
)

// structs for output format

type stepOut struct {
	//fields taken from Step.FlowInstance
	AuthorizationURL string `json:"authorizationURL"`
	RedirectedToURL  string `json:"redirectedToURL"`

	FailMessage  string `json:"failMessage,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`

	RequiredOutcome string `json:"requiredOutcome"`

	FlowType     string              `json:"flowType,omitempty"`
	FlowInstance *oauth.FlowInstance `json:"flow,omitempty"`

	// State contains result of the step
	State string `json:"state"`
}

type checkOut struct {
	CheckName    string    `json:"name"`
	RiskRating   string    `json:"risk"`
	Description  string    `json:"description"`
	SkipReason   string    `json:"skipReason,omitempty"`
	References   string    `json:"references,omitempty"`
	FailMessage  string    `json:"failMessage,omitempty"`
	ErrorMessage string    `json:"errorMessage,omitempty"`
	Steps        []stepOut `json:"steps,omitempty"`
	State        string    `json:"state"`
}

// convert Step to StepOut
func (s *step) export() stepOut {
	return stepOut{
		AuthorizationURL: s.FlowInstance.AuthorizationURL.String(),
		RedirectedToURL:  s.FlowInstance.RedirectedToURL.String(),
		FailMessage:      s.failMessage,
		ErrorMessage:     s.errorMessage,
		RequiredOutcome:  s.RequiredOutcome,
		State:            string(s.state),
		FlowType:         s.FlowType,
		FlowInstance:     s.FlowInstance,
	}
}

// WriteResults - Write Check results in JSON format to file
// and generate HTML report
func WriteResults(outDir string, htmlReportTemplate string) {
	outDir = removeTrailingSlash(outDir) // remove trailing slash from provided dir
	err := makeDirectory(outDir)         // create output directory if it doesn't exist

	var outList []checkOut
	allChecks := append(supportChecksList, checksList...)
	for _, c := range allChecks {
		// only want to output some fields, so
		// marhsal Check struct to bytes, then unmarshal it back to tmp struct
		// then marshal to bytes and write to file

		var outCheck checkOut
		if c.state != skip {
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

		steps := c.Steps
		// Export steps to format for outputting
		outCheck.Steps = []stepOut{}
		for _, s := range steps {
			outCheck.Steps = append(outCheck.Steps, s.export())
		}

		outCheck.State = string(c.state)
		outList = append(outList, outCheck)
	}

	bslice, err := json.Marshal(outList)
	outFile := filepath.Join(outDir, "output.json")

	err = ioutil.WriteFile(outFile, bslice, 0644)
	if err != nil {
		log.Fatal(err)
	}

	htmlReportPath := filepath.Join(outDir, "report.html")
	renderTemplate(outList, htmlReportTemplate, htmlReportPath)

	fmt.Printf("HTML Report has been saved to %s\n", htmlReportPath)
	fmt.Printf("Raw JSON output has been saved to %s\n", outFile)
}

// remove trailing slash from output directory if present
func removeTrailingSlash(outdir string) string {
	if string(outdir[len(outdir)-1]) == string(os.PathSeparator) { // remove trailing slash
		outdir = outdir[0 : len(outdir)-1]
	}
	return outdir
}

// create output directory if it doesn't exist
func makeDirectory(outDir string) error {
	_, err := os.Stat(outDir)
	if err == nil { // directory exists
		return nil
	}
	if os.IsNotExist(err) { // directory does't exist, create it
		return os.MkdirAll(outDir, 0755)
	}
	return nil
}

// render html report template
func renderTemplate(co []checkOut, htmlReportTemplate, htmlReportPath string) {
	t := template.New("HTML Report").Delims("[%[", "]%]")

	htmlFile, err := os.Open(htmlReportTemplate)
	if err != nil {
		log.Printf("Couldn't open file at %s\n", htmlReportTemplate)
		log.Fatal(err)
	}

	// read report html file
	tpl, err := ioutil.ReadAll(htmlFile)
	if err != nil {
		log.Fatal(err)
	}

	t, err = t.Parse(string(tpl))
	if err != nil {
		log.Println("Error parsing template")
		log.Fatal(err)
	}

	f, err := os.Create(htmlReportPath)
	if err != nil {
		log.Fatal(err)
	}

	bslice, err := json.Marshal(co)
	t.Execute(f, string(bslice))
}
