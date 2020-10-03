package main

import (
	"context"
	"fmt"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

func setChromeCookie(name, value, domain string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		success, err := network.SetCookie(name, value).
			WithDomain(domain).
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
	for name, val := range session.InitialCookies {
		actions = append(actions, setChromeCookie(name, val, host))
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
