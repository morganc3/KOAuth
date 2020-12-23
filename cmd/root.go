package cmd

import (
	"context"
	"flag"
	"fmt"
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

	chk := checks.NewCheck("redirect-uri-change", "high", "certain", oauth.IMPLICIT_FLOW_RESPONSE_TYPE, checks.RedirectURITotalChange)
	chk.DoCheck()
	fmt.Println(chk.State)

	chk = checks.NewCheck("redirect-uri-scheme-downgrade", "high", "certain", oauth.IMPLICIT_FLOW_RESPONSE_TYPE, checks.RedirectURISchemeDowngrade)
	chk.DoCheck()
	fmt.Println(chk.State)

	chk = checks.NewCheck("state-supported", "medium", "certain", oauth.AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE, checks.StateSupported)
	chk.DoCheck()
	fmt.Println(chk.State)

	chk = checks.NewCheck("pkce-supported", "medium", "certain", oauth.AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE, checks.PkceSupported)
	chk.DoCheck()
	fmt.Println(chk.State)
}

func exitWithAuthInfo(fi *oauth.FlowInstance) {
	log.Printf("Could not perform normal implicit flow, cancelling scan")
	url := fi.GenerateAuthorizationURL(oauth.IMPLICIT_FLOW_RESPONSE_TYPE, "stateval")

	// if it's our first time consenting, remove prompt=none
	oauth.DelQueryParameter(url, "prompt")
	log.Printf("You likely need to reauthenticate here: %s", url.String())
	os.Exit(1)
}
