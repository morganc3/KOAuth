package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Wait until we get a redirect to a URL that contains our redirect URI's host
// There is no easy way to do this with the chromedp API's, so we literally
// watch events until we get one that is a EventRequestWillBeSent type with
// a URL of our redirectURI
func waitRedirectToHost(ctx context.Context, cancel context.CancelFunc, host string) <-chan *url.URL {
	ch := make(chan *url.URL, 1)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		redirect, ok := ev.(*network.EventRequestWillBeSent)
		if ok {
			redirectURL, err := url.Parse(redirect.Request.URL)
			redirectURL.Fragment = redirect.Request.URLFragment
			if err != nil {
				log.Fatal("Got bad redirectURL from EventRequestWillBeSent object")
			}
			if redirectURL.Host == host {
				select {
				case <-ctx.Done():
				case ch <- redirectURL:
				}
				close(ch)
				cancel()
			}
		}
	})
	return ch
}

func setChromeCookie(name, value, domain string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Check if cookie needs to be secure (chromedp will error otherwise)
		secure := strings.HasPrefix(name, "__Secure-")
		success, err := network.SetCookie(name, value).
			WithDomain(domain).
			WithPath("/").
			WithSecure(secure).
			Do(ctx)
		if err != nil {
			return err
		}
		if !success {
			return fmt.Errorf("could not set cookie %s", name)
		}
		return nil
	})
}

func setInitialChromeCookies() []chromedp.Action {
	actions := make([]chromedp.Action, len(session.InitialCookies))

	host := config.getConfigHost()
	cnt := 0
	for name, val := range session.InitialCookies {
		actions[cnt] = setChromeCookie(name, val, host)
		cnt++
	}

	return actions
}

func setChromeHeaders(headers map[string]interface{}) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		return network.SetExtraHTTPHeaders(network.Headers(headers)).Do(ctx)
	})
}

func setInitialChromeHeaders() chromedp.Action {
	headers := make(map[string]interface{}, len(session.InitialHeaders))
	for name, val := range session.InitialHeaders {
		headers[name] = val
	}
	return setChromeHeaders(headers)
}

func getHeaderAndCookieActions() []chromedp.Action {
	var actions []chromedp.Action
	actions = append(actions, setInitialChromeHeaders())

	cookieActions := setInitialChromeCookies()
	for _, c := range cookieActions {
		actions = append(actions, c)
	}
	return actions
}
