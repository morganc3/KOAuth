package config

import (
	"log"
	"os"
	"strconv"

	flag "github.com/ogier/pflag"
)

type cliFlag struct {
	name         string
	hint         string
	defaultValue string
	value        *string
}

type cliFlagsMap map[string]*cliFlag

// CliFlags - map of cliFlags with their names and values
var CliFlags cliFlagsMap

// CLI Flag constant values
const (
	FlagConfig            = "config"
	FlagChecks            = "checks"
	FlagOut               = "out"
	FlagAuthenticationURL = "authentication-url"
	FlagProxy             = "proxy"
	FlagUserAgent         = "user-agent"
	FlagTimeout           = "timeout"
	FlagPrompt            = "prompt"
	FlagClientAuth        = "client-auth"
	FlagReportTemplate    = "report-template"
)

// InitCliFlags - Initialize CliFlagsMap and parse CLI flags
func (c *cliFlagsMap) InitCliFlags() {
	*c = make(cliFlagsMap)

	c.newFlag(FlagConfig, "input oauth configuration file", "config.json")
	c.newFlag(FlagChecks, "file containing checks to run", "./checks/rules/checks.json")
	c.newFlag(FlagOut, "directory for output to be stored", "output/")
	c.newFlag(FlagAuthenticationURL,
		`Url to originally authenticate at to establish an authenticated session in the browser. 
		If left blank, authentication will occur through an OAuth flow.`,
		"")
	c.newFlag(FlagProxy, "HTTP Proxy <ip>:<port>", "")
	c.newFlag(FlagUserAgent, "User-Agent Header for Chrome", `Chrome`)
	c.newFlag(FlagTimeout, "Timeout for waiting for OAuth redirects to redirect_uri", "4")
	c.newFlag(FlagPrompt, `Value of "prompt" parameter in authorization request. If the authorization 
		server does not support prompt=none, it should be set to "login" or "select_account". If the 
		pressence of the prompt parameter breaks the flow, set to this flag to the string "DONT_SEND" 
		and it will not be sent.`, "none")
	c.newFlag(FlagClientAuth, `Client Authentication Method: "BASIC", "BODY", or "auto", to indicate if 
		client ID and client secret should be sent in an HTTP Basic authentication header or in the POST body, 
		or should be auto detected.`, "auto")
	c.newFlag(FlagReportTemplate, "HTML report template to consume JSON output", "./checks/assets/report.html")

	c.parseCliFlags() // parse CLI flags
	filePathsExist()  // ensure file paths provided by CLI flags exist
}

func (c cliFlagsMap) newFlag(name, hint string, defaultValue string) {
	f := cliFlag{
		name:         name,
		hint:         hint,
		defaultValue: defaultValue,
	}
	c[name] = &f
}

// parse cli flags, storing in CliFlagsMap
func (c cliFlagsMap) parseCliFlags() {
	for _, v := range c {
		c.parseFlag(v)
	}
	flag.Parse()

}

func (c cliFlagsMap) parseFlag(cf *cliFlag) {
	val := flag.String(cf.name, cf.defaultValue, cf.hint)
	c[cf.name].value = val
}

// GetOpt - get cli option value
func GetOpt(name string) string {
	return *CliFlags[name].value
}

// GetOptAsInt - get cli option as int
func GetOptAsInt(name string) int {
	v, err := strconv.Atoi(*CliFlags[name].value)
	if err != nil {
		log.Fatalf("Bad option value - could not be converted to int\n")
	}
	return v
}

// Must only be called after flags have been parsed
func filePathsExist() {
	// ensure input check JSON file exists
	checkFile := GetOpt(FlagChecks)
	if !fileExists(checkFile) {
		log.Printf("Check file at %s does not exist\n", checkFile)
		log.Fatal("The default check file is in the repository at KOAuth/checks/rules/checks.json")
	}

	// ensure OAuth config file exists
	oauthConfig := GetOpt(FlagConfig)
	if !fileExists(oauthConfig) {
		log.Fatalf("OAuth configuration file at %s does not exist\n", oauthConfig)
	}

	// ensure HTML report template file exists
	reportTemplate := GetOpt(FlagReportTemplate)
	if !fileExists(reportTemplate) {
		log.Printf("HTML Report template file at %s does not exist\n", reportTemplate)
		log.Fatal("The default report template file is in the repository at KOAuth/checks/assets/report.html")
	}
}

func fileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// file doesn't exist
		return false
	}
	return true
}
