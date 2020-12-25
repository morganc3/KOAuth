package cmd

import (
	"context"
	"fmt"
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
	i := oauth.NewInstance(ctx, cancel, oauth.IMPLICIT_FLOW_RESPONSE_TYPE)

	// We should be prompted for auth as this is our first request
	oauth.DelQueryParameter(i.AuthorizationURL, "prompt")
	urlString := i.AuthorizationURL.String()

	// adds listener listening for a redirect to our redirect_uri
	ch := oauth.WaitRedirect(ctx, i.ProvidedRedirectURL.Host, i.ProvidedRedirectURL.Path)
	// extra long timeout since we'll be manually logging in here

	err := chromedp.Run(ctx, chromedp.Navigate(urlString))
	if err != nil {
		log.Fatal(err)
	}

	select {
	case <-ctx.Done():
		fmt.Println("this one?")
		log.Fatal("Context was cancelled")
	case urlstr := <-ch:
		i.RedirectedToURL = urlstr
		err = i.GetURLError() // get error as defined in rfc6749
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Successfully authenticated")
	}
	return ctx, cancel
}
