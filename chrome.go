package main

import (
	"context"
	"fmt"
	"log"
	"net/url"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
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

func setChromeCookie(host string, c SessionCookie) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		domain := host
		if c.Domain != "" {
			domain = c.Domain
		}
		path := "/"
		if c.Path != "" {
			path = c.Path
		}

		success, err := network.SetCookie(c.Name, c.Value).
			WithDomain(domain).
			WithPath(path).
			WithSecure(c.Secure).
			WithHTTPOnly(c.HttpOnly).
			Do(ctx)
		if err != nil {
			return err
		}
		if !success {
			return fmt.Errorf("could not set cookie %s", c.Name)
		}
		return nil
	})
}

func setInitialChromeCookies() []chromedp.Action {
	actions := make([]chromedp.Action, len(session.Cookies))

	host := config.getConfigHost()
	cnt := 0
	for _, c := range session.Cookies {
		actions[cnt] = setChromeCookie(host, c)
		cnt++
	}

	return actions
}

func setLocalStorageValues() []chromedp.Action {
	var actions []chromedp.Action
	for _, item := range session.LocalStorage {
		action := chromedp.ActionFunc(func(ctx context.Context) error {
			javaScriptString := fmt.Sprintf("window.localStorage.setItem('%s', '%s')", item.Name, item.Value)
			_, exp, err := runtime.Evaluate(javaScriptString).Do(ctx)
			if err != nil {
				return err
			}
			if exp != nil {
				return exp
			}
			return nil
		})
		actions = append(actions, action)
	}
	return actions
}

func getSessionActions() []chromedp.Action {
	var actions []chromedp.Action

	// change this to set localstorage
	// actions = append(actions, setInitialChromeHeaders())

	cookieActions := setInitialChromeCookies()
	localStorageActions := setLocalStorageValues()

	for _, c := range cookieActions {
		actions = append(actions, c)
	}

	for _, ls := range localStorageActions {
		actions = append(actions, ls)
	}

	return actions
}
