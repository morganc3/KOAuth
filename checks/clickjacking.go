package checks

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/browser"
	"github.com/morganc3/KOAuth/config"
	"github.com/morganc3/KOAuth/oauth"
)

// Custom check definition for clickjacking
// this check cannot be easily implemented
// via our checks JSON format

func ClickjackingCheck(c *Check, ctx *context.Context) (State, error) {
	// listen network event
	authzCodeUrl := oauth.GenerateAuthorizationURL(oauth.AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE, "random-state", config.GetOpt(config.FLAG_PROMPT))

	allHeaders := make(map[string][]string)
	domain := authzCodeUrl.Host
	listenForNetworkEvent(*ctx, domain, allHeaders)

	actions := []chromedp.Action{network.Enable(),
		chromedp.Navigate(authzCodeUrl.String()),
		chromedp.WaitVisible(`body`, chromedp.BySearch)}

	browser.RunWithTimeOut(ctx, time.Duration(config.GetOptAsInt(config.FLAG_TIMEOUT)), actions)

	if allowsIframes(allHeaders) {
		return FAIL, nil
	} else {
		return PASS, nil
	}
}

func allowsIframes(allHeaders map[string][]string) bool {
	if vals, ok := allHeaders["x-frame-options"]; ok {
		for _, v := range vals {
			if v == "sameorigin" || v == "deny" {
				return false
			}
		}
	}

	if vals, ok := allHeaders["content-security-policy"]; ok {
		for _, v := range vals {
			if strings.Contains(v, "frame-ancestors") {
				return false
			}
		}
	}

	return true
}

func listenForNetworkEvent(ctx context.Context, domain string, allHeaders map[string][]string) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {

		case *network.EventResponseReceived:
			resp := ev.Response
			respURL, _ := url.Parse(resp.URL)
			respDomain := respURL.Host
			// get headers set by our current domain that is being loaded
			// this isn't ideal, but it accounts for most edge cases
			// such as an iframe being responded to with a 302 (for example to a www. subdomain)
			// We can't simply check the headers of the first HTTP response because
			// of this reason
			domainContainsOther := (strings.Contains(respDomain, domain) || strings.Contains(domain, respDomain))
			if len(resp.Headers) != 0 && domainContainsOther {
				for k, v := range resp.Headers {
					key := strings.ToLower(k) // headers are not case sensitive
					val := strings.ToLower(v.(string))
					if _, ok := allHeaders[key]; ok {
						allHeaders[key] = append(allHeaders[key], val)
					} else {
						allHeaders[key] = []string{val}
					}
				}
			}
			return
		}
	})

}
