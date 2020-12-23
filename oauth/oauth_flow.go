package oauth

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/config"
	"golang.org/x/oauth2"
)

type FlowType string

const (
	IMPLICIT_FLOW_RESPONSE_TYPE           = "token"
	AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE = "code"
)

type FlowInstance struct {
	Ctx                context.Context
	Cancel             context.CancelFunc
	FlowType           FlowType
	FlowTimeoutSeconds time.Duration
	AuthorizationURL   *url.URL
	RedirectedToURL    *url.URL
	ExchangeRequest    *ExchangeRequest
}

type ExchangeRequest struct {
	Request  *http.Request
	Response *http.Response
}

const FLOW_TIMEOUT_SECONDS = 5

// TODO: There are likely to be applications where
// either:
//   A. Session information is updated on each request
//		and the previous value is invalidated
//	 B. Session information is cleared when an
// 		error / authz issue occurs.
// Support should be added to support both of these cases

func NewInstance(ft FlowType) *FlowInstance {
	ctx, cancel := chromedp.NewContext(ChromeContext)
	flowInstance := FlowInstance{
		FlowType:           ft,
		Ctx:                ctx,
		Cancel:             cancel,
		FlowTimeoutSeconds: FLOW_TIMEOUT_SECONDS,
		RedirectedToURL:    new(url.URL),
		ExchangeRequest:    new(ExchangeRequest),
	}
	flowInstance.AuthorizationURL = flowInstance.GenerateAuthorizationURL(ft, "random_state_value")
	return &flowInstance
}

func (i *FlowInstance) DoAuthorizationRequest() error {
	defer i.Cancel()
	var actions []chromedp.Action
	actions = getSessionActions()

	urlString := i.AuthorizationURL.String()

	actions = append(actions, chromedp.Navigate(urlString))

	// adds listener which will cancel the context
	// if a redirect to redirect_uri occurs
	ch := waitRedirectToHost(i.Ctx, i.Cancel, config.Config.GetRedirectURIHost())
	err := RunWithTimeOut(&i.Ctx, i.FlowTimeoutSeconds, actions)

	// Error caused by context being cancelled when
	// we hit our redirect URL
	if err != nil && err.Error() == CONTEXT_CANCELLED_ERROR {
		urlstr := <-ch
		i.RedirectedToURL = urlstr
		return nil
	}
	return err

}

func (i *FlowInstance) GenerateAuthorizationURL(flowType FlowType, state string) *url.URL {
	var option oauth2.AuthCodeOption = oauth2.SetAuthURLParam(RESPONSE_TYPE, string(flowType))
	URLString := config.Config.OAuthConfig.AuthCodeURL(state, option)
	URL, err := url.Parse(URLString)
	if err != nil {
		log.Fatal(err)
	}
	// If supported, this will ensure that the authorization consent prompt only shows once
	SetQueryParameter(URL, "prompt", "none")
	return URL
}

func GetImplicitAccessTokenFromURL(urlString string) string {
	u, err := url.Parse(urlString)
	if err != nil {
		log.Fatal(err)
	}

	values, _ := url.ParseQuery(u.Fragment)
	tokenString := values.Get(ACCESS_TOKEN)
	return tokenString
}
