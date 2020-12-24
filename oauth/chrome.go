package oauth

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/config"
)

// Wait until we get a redirect to a URL that contains our redirect URI's host
// There is no easy way to do this with the chromedp API's, so we literally
// watch events until we get one that is a EventRequestWillBeSent type with
// a URL of our redirectURI
func waitRedirect(ctx context.Context, cancel context.CancelFunc, host, path string) <-chan *url.URL {
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
				case ch <- redirectURL:
				}
				close(ch)
				cancel()
			}
		}
	})
	return ch
}

func RunWithTimeOut(ctx *context.Context, timeout time.Duration, actions []chromedp.Action) error {
	timeoutContext, cancel := context.WithTimeout(*ctx, timeout*time.Second)
	defer cancel()
	return chromedp.Run(timeoutContext, actions...)
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
	actions := make([]chromedp.Action, len(Session.Cookies))

	host := config.Config.GetConfigHost()
	cnt := 0
	for _, c := range Session.Cookies {
		actions[cnt] = setChromeCookie(host, c)
		cnt++
	}

	return actions
}

func setLocalStorageValues() []chromedp.Action {
	var actions []chromedp.Action
	for _, item := range Session.LocalStorage {
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

// Returns actions that include setting local storage, cookie
// values, etc.
func getSessionActions() []chromedp.Action {
	var actions []chromedp.Action

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
