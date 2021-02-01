package browser

import (
	"context"
	"log"
	"net/url"

	"github.com/chromedp/cdproto/dom"
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

type ResponseHeaders *map[string]interface{}
type ResponseBody *string

// TODO: fix issue around getting response body
// note: body works for google.com and not example.com
//       and headers works for example.com and not google.com
func Load(url string) (ResponseHeaders, ResponseBody) {
	chromeContext, cancelContext := chromedp.NewContext(context.Background())
	defer cancelContext()

	var response string
	var statusCode int64
	var responseHeaders map[string]interface{}

	runError := chromedp.Run(
		chromeContext,
		getFullResponse(
			chromeContext, url,
			map[string]interface{}{"User-Agent": "Mozilla/5.0"},
			&response, &statusCode, &responseHeaders))

	if runError != nil {
		// TODO: Currently giving errors around retrieving document body
		// log.Println(runError)
	}
	return &responseHeaders, &response
}

// gets full response including headers / status code
func getFullResponse(chromeContext context.Context, url string, requestHeaders map[string]interface{}, response *string, statusCode *int64, responseHeaders *map[string]interface{}) chromedp.Tasks {
	chromedp.ListenTarget(chromeContext, func(event interface{}) {
		switch responseReceivedEvent := event.(type) {
		case *network.EventResponseReceived:
			response := responseReceivedEvent.Response
			if response.URL == url {
				*statusCode = response.Status
				*responseHeaders = response.Headers
			}
		}
	})

	return chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(requestHeaders)),
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) error {
			node, err := dom.GetDocument().Do(ctx)
			if err != nil {
				return err
			}
			*response, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)

			return err
		})}
}
