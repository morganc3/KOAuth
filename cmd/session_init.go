package cmd

import (
	"context"
	"log"

	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/oauth"
)

// Initialize session by navigating to the Authorization URL and logging in
// This will wait until we are redirected to the correct redirect_uri
// or the context times out. The purpose of this initialization is to
// setup cookies, localstorage, indexdb, etc. in the browser.

func initSession() (context.Context, context.CancelFunc) {
	ctx, cancel := chromedp.NewContext(oauth.ChromeExecContext)
	// We should be prompted for auth as this is our first request

	// TODO: some servers might not support implicit flow
	// for initializing/authenticating, we should probably at minimum
	// allow the option to do authorization code flow here in case
	// implicit flow will cause an immediate error. Otherwise, can simply
	// provide a url to authenticate to
	i := oauth.NewInstance(ctx, cancel, oauth.IMPLICIT_FLOW_RESPONSE_TYPE, "DONT_SEND")

	urlString := i.AuthorizationURL.String()

	// adds listener listening for a redirect to our redirect_uri
	ch := oauth.WaitRedirect(ctx, i.ProvidedRedirectURL.Host, i.ProvidedRedirectURL.Path)

	err := chromedp.Run(ctx, chromedp.Navigate(urlString))
	if err != nil {
		log.Fatal(err)
	}

	select {
	case <-ctx.Done():
		// TODO: this should not be fatal
		log.Fatal("Context was cancelled")
	case urlstr := <-ch:
		i.RedirectedToURL = urlstr
		err = i.GetURLError() // get error as defined in rfc6749
		if err != nil {
			// TODO: this should not be fatal
			log.Fatal(err)
		}
		log.Println("Successfully authenticated")
	}
	return ctx, cancel
}
