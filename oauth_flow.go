package main

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"github.com/chromedp/chromedp"
	"golang.org/x/oauth2"
)

type FlowType string

const (
	IMPLICIT_FLOW_RESPONSE_TYPE           = "token"
	AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE = "code"
)

const FLOW_ERROR = "ERROR"

type FlowInstance struct {
	Ctx              context.Context
	Cancel           context.CancelFunc
	FlowType         FlowType
	AuthorizationURL *url.URL
	RedirectedToURL  *url.URL
	ExchangeRequest  *ExchangeRequest
}

type ExchangeRequest struct {
	Request  *http.Request
	Response *http.Response
}

func NewInstance(ft FlowType) *FlowInstance {
	ctx, cancel := chromedp.NewContext(chromeContext)
	flowInstance := FlowInstance{
		FlowType:        ft,
		Ctx:             ctx,
		Cancel:          cancel,
		RedirectedToURL: new(url.URL),
		ExchangeRequest: new(ExchangeRequest),
	}
	flowInstance.AuthorizationURL = flowInstance.GenerateAuthorizationURL(ft, "random_state_value")
	return &flowInstance
}

func (i *FlowInstance) DoAuthorizationRequest() error {
	defer i.Cancel()
	var actions []chromedp.Action
	actions = getHeaderAndCookieActions()

	urlString := i.AuthorizationURL.String()

	actions = append(actions, chromedp.Navigate(urlString))

	ch := waitRedirectToHost(i.Ctx, i.Cancel, config.getRedirectURIHost())
	err := chromedp.Run(i.Ctx, actions...)
	// TODO - fix hacky error check
	if err.Error() == "context canceled" {
		urlstr := <-ch
		i.RedirectedToURL = urlstr
		return nil
	}
	return err

}

func (i *FlowInstance) GenerateAuthorizationURL(flowType FlowType, state string) *url.URL {
	var option oauth2.AuthCodeOption = oauth2.SetAuthURLParam(RESPONSE_TYPE, string(flowType))
	URLString := config.OAuthConfig.AuthCodeURL(state, option)
	URL, err := url.Parse(URLString)
	if err != nil {
		log.Fatal(err)
	}
	// If supported, this will ensure that the authorization consent prompt only shows once
	SetQueryParameter(URL, "prompt", "none")
	return URL
}

func getImplicitAccessTokenFromURL(urlString string) string {
	u, err := url.Parse(urlString)
	if err != nil {
		log.Fatal(err)
	}

	values, _ := url.ParseQuery(u.Fragment)
	tokenString := values.Get(ACCESS_TOKEN)
	return tokenString
}
