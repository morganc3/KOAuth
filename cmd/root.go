package cmd

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/checks"
	"github.com/morganc3/KOAuth/config"
	"github.com/morganc3/KOAuth/oauth"
	flag "github.com/ogier/pflag"
)

// TODO: add support for setting "prompt" param for checks
func Execute() {
	configFile := flag.String("config", "config.json", "config file name")
	checkFile := flag.String("checks", "./checks/resources/checks.json", "checks file name")
	outFile := flag.String("outfile", "output.json", "results output file")
	proxy := flag.String("proxy", "", "HTTP Proxy <ip>:<port>")
	userAgent := flag.String("user-agent", `Chrome`, "User-Agent Header for Chrome")
	timeout := flag.Int("timeout", 4, "Timeout for waiting for OAuth redirects to redirect_uri")
	PromptFlag := flag.String("prompt", "none", "Value of \"prompt\" parameter in authorization request. If the authorization server does\n\t\t not support prompt=none, it should be set to \"login\" or \"select_account\". If the pressence of the prompt parameter\n\t\t breaks the flow, set to this flag to the string \"DONT_SEND\" and it will not be sent.")
	ClientAuth := flag.String("client-auth", "auto", "Client Authentication Method: \"BASIC\", \"BODY\", or \"auto\", to indicate if client ID and client secret\n\t\t should be sent in an HTTP Basic authentication header or in the POST body, or should be auto detected.")
	flag.Parse()

	oauth.FLOW_TIMEOUT_SECONDS = time.Duration(*timeout)

	var chromeOpts []chromedp.ExecAllocatorOption

	headlessFlag := chromedp.Flag("headless", false)
	userAgentFlag := chromedp.UserAgent(*userAgent)
	chromeOpts = append(chromedp.DefaultExecAllocatorOptions[:], headlessFlag, userAgentFlag)

	if *proxy != "" {
		// Be sure you trust your proxy server if you choose this option
		ignoreCerts := chromedp.Flag("ignore-certificate-errors", true)
		chromeOpts = append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ProxyServer(*proxy),
			ignoreCerts,
		)
	}

	cx, cancel := chromedp.NewExecAllocator(context.Background(), chromeOpts...)

	oauth.ChromeExecContext = cx
	oauth.ChromeExecContextCancel = cancel
	defer cancel()

	config.Config = config.NewConfig(*configFile, *ClientAuth)

	// first tab's context and CancelFunc
	// this will be the first window, which
	// sets up authentication to the authorization server
	fctx, fctxCancel := initSession()
	defer fctxCancel()

	checks.Init(*checkFile, fctx, *PromptFlag)
	checks.DoChecks()
	checks.PrintResults()
	checks.WriteResults(*outFile)
}
