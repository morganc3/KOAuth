package cmd

import (
	"context"
	"os"

	"github.com/morganc3/KOAuth/browser"
	"github.com/morganc3/KOAuth/checks"
	"github.com/morganc3/KOAuth/config"
)

func Execute() {
	config.CliFlags.InitCliFlags() // Initialize and Parse CLI Flags

	cancel := browser.InitChromeSession() // Initialize Chrome browser configuration
	defer cancel()

	config.OAuthConfig.Init() // Parse OAuth configuration file provided

	// first tab's context and CancelFunc
	// this will be the first window, which
	// sets up authentication to the authorization server
	fctx, fctxCancel := initSession(config.GetOpt(config.FLAG_AUTHENTICATION_URL))
	defer fctxCancel()

	checkFile := config.GetOpt(config.FLAG_CHECKS)
	promptFlag := config.GetOpt(config.FLAG_PROMPT)
	outDir := config.GetOpt(config.FLAG_OUT)
	reportTemplate := config.GetOpt(config.FLAG_REPORT_TEMPLATE)
	performChecks(fctx, checkFile, promptFlag, outDir, reportTemplate)
}

func performChecks(ctx context.Context, checkFile, promptFlag, outDir, htmlReportTemplate string) {
	checks.Init(checkFile, ctx, promptFlag)
	checks.DoChecks()
	checks.PrintResults()
	checks.WriteResults(outDir, htmlReportTemplate)
}

func fileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// file doesn't exist
		return false
	}
	return true
}
