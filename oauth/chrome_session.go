package oauth

import (
	"context"
	"fmt"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/config"
)

var ChromeExecContext context.Context
var ChromeExecContextCancel context.CancelFunc

// Electron Cookie format
type SessionCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HttpOnly bool   `json:"httpOnly,omitempty"`
}

type LocalStorageItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
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
func GetSessionActions() []chromedp.Action {
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
