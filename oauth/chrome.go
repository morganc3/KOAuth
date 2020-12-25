package oauth

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Wait until we get a redirect to a URL that contains our redirect URI's host
// There is no easy way to do this with the chromedp API's, so we literally
// watch events until we get one that is a EventRequestWillBeSent type with
// a URL of our redirectURI
func WaitRedirect(ctx context.Context, host, path string) <-chan *url.URL {
	ch := make(chan *url.URL, 1)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		redirect, ok := ev.(*network.EventRequestWillBeSent)
		if ok {
			redirectURL, err := url.Parse(redirect.Request.URL)
			if len(redirect.Request.URLFragment) > 0 {
				redirectURL.Fragment = redirect.Request.URLFragment[1:] // remove '#'
			}
			if err != nil {
				log.Fatal("Got bad redirectURL from EventRequestWillBeSent object")
			}

			// if we are being redirected to the provided redirectURL
			if redirectURL.Host == host && redirectURL.Path == path {
				fmt.Println("HERE WHERE WE HAVE " + redirectURL.String())
				select {
				case <-ctx.Done():
					return
				case ch <- redirectURL:
					close(ch)
					return
				}
			}
		}
	})
	return ch
}

func RunWithTimeOut(ctx *context.Context, timeout time.Duration, actions []chromedp.Action) (context.Context, error) {
	timeoutContext, _ := context.WithTimeout(*ctx, timeout*time.Second)
	return timeoutContext, chromedp.Run(timeoutContext, actions...)
}
