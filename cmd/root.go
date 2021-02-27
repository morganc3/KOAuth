package cmd

import (
	"context"
	"os"

	"github.com/morganc3/KOAuth/browser"
	"github.com/morganc3/KOAuth/checks"
	"github.com/morganc3/KOAuth/config"
)

// Execute - Parse CLI flags, OAuth configuration file,
// initialize browser session, and begin performing checks
func Execute() {
	config.CliFlags.InitCliFlags() // Initialize and Parse CLI Flags

	cancel := browser.InitChromeSession() // Initialize Chrome browser configuration
	defer cancel()

	config.OAuthConfig.Init() // Parse OAuth configuration file provided

	// first tab's context and CancelFunc
	// this will be the first window, which
	// sets up authentication to the authorization server
	fctx, fctxCancel := initSession(config.GetOpt(config.FlagAuthenticationURL))
	defer fctxCancel()

	checkFile := config.GetOpt(config.FlagChecks)
	promptFlag := config.GetOpt(config.FlagPrompt)
	outDir := config.GetOpt(config.FlagOut)
	reportTemplate := config.GetOpt(config.FlagReportTemplate)
	performChecks(fctx, checkFile, promptFlag, outDir, reportTemplate)
}

func performChecks(ctx context.Context, checkFile, promptFlag, outDir, htmlReportTemplate string) {
	checks.Init(ctx, checkFile, promptFlag)
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
