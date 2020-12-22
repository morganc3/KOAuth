package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/chromedp/chromedp"
)

var config KOAuthConfig
var session KOAuthSession
var chromeContext context.Context

func main() {
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
	chromeContext = cx
	defer cancel()

	config = NewConfig(*configFile)

	u, err := url.Parse(config.OAuthConfig.Endpoint.AuthURL)
	if err != nil {
		log.Fatal(err)
	}
	session = NewSession(*sessionFile, u)

	// Perform normal implicit flow token exchange to validate session has been properly setup
	if instance, ok := session.validateSession(); !ok {
		exitWithAuthInfo(instance)
	}

	chk := NewCheck("redirect-uri-change", "high", "certain", IMPLICIT_FLOW_RESPONSE_TYPE, redirectURITotalChange)
	chk.DoCheck()
	fmt.Println(chk.Pass)

	chk = NewCheck("redirect-uri-scheme-downgrade", "high", "certain", IMPLICIT_FLOW_RESPONSE_TYPE, redirectURISchemeDowngrade)
	chk.DoCheck()
	fmt.Println(chk.Pass)

	chk = NewCheck("state-supported", "medium", "certain", AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE, stateSupported)
	chk.DoCheck()
	fmt.Println(chk.Pass)

	chk = NewCheck("pkce-supported", "medium", "certain", AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE, pkceSupported)
	chk.DoCheck()
	fmt.Println(chk.Pass)
}

func exitWithAuthInfo(fi *FlowInstance) {
	log.Printf("Could not perform normal implicit flow, cancelling scan")
	url := fi.GenerateAuthorizationURL(IMPLICIT_FLOW_RESPONSE_TYPE, "stateval")

	// if it's our first time consenting, remove prompt=none
	DelQueryParameter(url, "prompt")
	log.Printf("You likely need to reauthenticate here: %s", url.String())
	os.Exit(1)
}
