package config

import (
	"log"
	"os"
	"strconv"

	flag "github.com/ogier/pflag"
)

type CliFlag struct {
	Name    string
	Hint    string
	Default string
	Value   *string
}

type CliFlagsMap map[string]*CliFlag

var CliFlags CliFlagsMap

const (
	FLAG_CONFIG             = "config"
	FLAG_CHECKS             = "checks"
	FLAG_OUT                = "out"
	FLAG_AUTHENTICATION_URL = "authentication-url"
	FLAG_PROXY              = "proxy"
	FLAG_USER_AGENT         = "user-agent"
	FLAG_TIMEOUT            = "timeout"
	FLAG_PROMPT             = "prompt"
	FLAG_CLIENT_AUTH        = "client-auth"
	FLAG_REPORT_TEMPLATE    = "report-template"
)

func (c *CliFlagsMap) InitCliFlags() {
	*c = make(CliFlagsMap)

	c.newFlag(FLAG_CONFIG, "input oauth configuration file", "config.json")
	c.newFlag(FLAG_CHECKS, "file containing checks to run", "./checks/rules/checks.json")
	c.newFlag(FLAG_OUT, "directory for output to be stored", "output/")
	c.newFlag(FLAG_AUTHENTICATION_URL,
		`Url to originally authenticate at to establish an authenticated session in the browser. 
		If left blank, authentication will occur through an OAuth flow.`,
		"")
	c.newFlag(FLAG_PROXY, "HTTP Proxy <ip>:<port>", "")
	c.newFlag(FLAG_USER_AGENT, "User-Agent Header for Chrome", `Chrome`)
	c.newFlag(FLAG_TIMEOUT, "Timeout for waiting for OAuth redirects to redirect_uri", "4")
	c.newFlag(FLAG_PROMPT, `Value of "prompt" parameter in authorization request. If the authorization 
		server does not support prompt=none, it should be set to "login" or "select_account". If the 
		pressence of the prompt parameter breaks the flow, set to this flag to the string "DONT_SEND" 
		and it will not be sent.`, "none")
	c.newFlag(FLAG_CLIENT_AUTH, `Client Authentication Method: "BASIC", "BODY", or "auto", to indicate if 
		client ID and client secret should be sent in an HTTP Basic authentication header or in the POST body, 
		or should be auto detected.`, "auto")
	c.newFlag(FLAG_REPORT_TEMPLATE, "HTML report template to consume JSON output", "./checks/assets/report.html")

	c.ParseCliFlags() // parse CLI flags
	filePathsExist()  // ensure file paths provided by CLI flags exist
}

func (c CliFlagsMap) newFlag(name, hint string, defaultValue string) {
	f := CliFlag{
		Name:    name,
		Hint:    hint,
		Default: defaultValue,
	}
	c[name] = &f
}

func (c CliFlagsMap) ParseCliFlags() {
	for _, v := range c {
		c.parseFlag(v)
	}
	flag.Parse()

}

func (c CliFlagsMap) parseFlag(cf *CliFlag) {
	val := flag.String(cf.Name, cf.Default, cf.Hint)
	c[cf.Name].Value = val
}

func GetOpt(name string) string {
	return *CliFlags[name].Value
}

func GetOptAsInt(name string) int {
	v, err := strconv.Atoi(*CliFlags[name].Value)
	if err != nil {
		log.Fatalf("Bad option value - could not be converted to int\n")
	}
	return v
}

// Must only be called after flags have been parsed
func filePathsExist() {
	// ensure input check JSON file exists
	checkFile := GetOpt(FLAG_CHECKS)
	if !fileExists(checkFile) {
		log.Printf("Check file at %s does not exist\n", checkFile)
		log.Fatal("The default check file is in the repository at KOAuth/checks/rules/checks.json")
	}

	// ensure OAuth config file exists
	oauthConfig := GetOpt(FLAG_CONFIG)
	if !fileExists(oauthConfig) {
		log.Fatalf("OAuth configuration file at %s does not exist\n", oauthConfig)
	}

	// ensure HTML report template file exists
	reportTemplate := GetOpt(FLAG_REPORT_TEMPLATE)
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
