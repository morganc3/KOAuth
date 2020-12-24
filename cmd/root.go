package cmd

import (
	"context"
	"flag"
	"log"
	"net/url"
	"os"

	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/checks"
	"github.com/morganc3/KOAuth/config"
	"github.com/morganc3/KOAuth/oauth"
)

func Execute() {
	configFile := flag.String("config", "config.json", "config file name")
	sessionFile := flag.String("session", "session.json", "session file name")
	checkFile := flag.String("checks", "./resources/checks.json", "checks file name")
	outFile := flag.String("outfile", "output.json", "results output file")
	proxy := flag.String("proxy", "", "HTTP Proxy <ip>:<port>")
	flag.Parse()

	var chromeOpts []chromedp.ExecAllocatorOption

	headless := chromedp.Flag("headless", true)
	chromeOpts = append(chromedp.DefaultExecAllocatorOptions[:], headless)

	if *proxy != "" {
		// Be sure you trust your proxy server if you choose this option
		ignoreCerts := chromedp.Flag("ignore-certificate-errors", true)
		chromeOpts = append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ProxyServer(*proxy),
			ignoreCerts,
		)
	}

	cx, cancel := chromedp.NewExecAllocator(context.Background(), chromeOpts...)
	oauth.ChromeContext = cx
	defer cancel()

	config.Config = config.NewConfig(*configFile)

	u, err := url.Parse(config.Config.OAuthConfig.Endpoint.AuthURL)
	if err != nil {
		log.Fatal(err)
	}
	oauth.Session = oauth.NewSession(*sessionFile, u)

	// Perform normal implicit flow token exchange to validate session has been properly setup
	if instance, ok := oauth.Session.ValidateSession(); !ok {
		exitWithAuthInfo(instance)
	}

	checks.Init(*checkFile)
	checks.DoChecks()
	checks.PrintResults()
	checks.WriteResults(*outFile)
}

func exitWithAuthInfo(fi *oauth.FlowInstance) {
	log.Printf("Could not perform normal implicit flow, cancelling scan")
	url := fi.GenerateAuthorizationURL(oauth.IMPLICIT_FLOW_RESPONSE_TYPE, "stateval")

	// if it's our first time consenting, remove prompt=none
	oauth.DelQueryParameter(url, "prompt")
	log.Printf("You likely need to reauthenticate here: %s", url.String())
	os.Exit(1)
}
