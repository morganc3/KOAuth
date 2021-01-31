package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/morganc3/KOAuth/browser"
	"github.com/morganc3/KOAuth/config"
	"golang.org/x/oauth2"
)

// TODO: FlowType should really be "ResponseType" to be more accurate,
// this will also clear up confusion between FlowType in Check struct
type FlowType string

const (
	IMPLICIT_FLOW_RESPONSE_TYPE           = "token"
	AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE = "code"
)

type FlowInstance struct {
	FlowType            FlowType           `json:"-"`
	FlowTimeoutSeconds  time.Duration      `json:"-"`
	Ctx                 context.Context    `json:"-"`
	Cancel              context.CancelFunc `json:"-"`
	AuthorizationURL    *url.URL           `json:"-"`
	ProvidedRedirectURL *url.URL           `json:"-"`
	RedirectedToURL     *url.URL           `json:"-"`
	ExchangeRequest     *ExchangeRequest   `json:"exchangeRequest,omitempty"`
}

type ExchangeRequest struct {
	RequestString  string         `json:"request,omitempty"`
	ResponseString string         `json:"response,omitempty"`
	Request        *http.Request  `json:"-"`
	Response       *http.Response `json:"-"`
}

// TODO: There are likely to be applications where
// either:
//   A. Session information is updated on each request
//		and the previous value is invalidated
//	 B. Session information is cleared when an
// 		error / authz issue occurs.
// Support should be added to support both of these cases

// Scenario A is accounted for currently, as we use the same
// chrome context for each check.

func NewInstance(cx context.Context, cancel context.CancelFunc, ft FlowType, promptFlag string) *FlowInstance {
	redirectUri, err := url.Parse(config.OAuthConfig.OAuth2Config.RedirectURL)
	if err != nil {
		log.Fatalf("Failed to parse provided redirect_uri in config file")
	}
	flowInstance := FlowInstance{
		FlowType:            ft,
		FlowTimeoutSeconds:  time.Duration(config.GetOptAsInt(config.FLAG_TIMEOUT)),
		ProvidedRedirectURL: redirectUri,
		RedirectedToURL:     new(url.URL),
		Ctx:                 cx,
		Cancel:              cancel,
	}
	flowInstance.AuthorizationURL = GenerateAuthorizationURL(ft, "random_state_value", promptFlag)

	return &flowInstance
}

func (i *FlowInstance) DoAuthorizationRequest() error {
	var actions []chromedp.Action

	urlString := i.AuthorizationURL.String()

	actions = append(actions, chromedp.Navigate(urlString))
	// adds listener which will cancel the context
	// if a redirect to redirect_uri occurs
	ch := browser.WaitRedirect(i.Ctx, i.ProvidedRedirectURL.Host, i.ProvidedRedirectURL.Path)
	c, err := browser.RunWithTimeOut(&i.Ctx, time.Duration(config.GetOptAsInt(config.FLAG_TIMEOUT)), actions)
	if err != nil {
		return err
	}

	select {
	case <-c.Done():
		return err
	case urlstr := <-ch:
		i.RedirectedToURL = urlstr
		err = i.GetURLError() // get error as defined in rfc6749
		if err != nil {
			return err
		}
	}

	return err

}

// Same as Exchange() from https://github.com/golang/oauth2 but
// takes arbitrary url values and gives access to HTTP request and response
func (i *FlowInstance) Exchange(ctx context.Context, v url.Values) (*oauth2.Token, error) {
	req, resp, tkn, err := oauth2.RetrieveToken(ctx, &config.OAuthConfig.OAuth2Config, v)
	var reqString, respString string
	if req != nil {
		reqBytes, err := httputil.DumpRequest(req, true)
		reqString = string(reqBytes)
		if err != nil {
			log.Println(err)
		}
	}
	if resp != nil {
		respBytes, err := httputil.DumpResponse(resp, true)
		respString = string(respBytes)
		if err != nil {
			log.Println(err)
		}
	}

	i.ExchangeRequest = &ExchangeRequest{
		Request:        req,
		Response:       resp,
		RequestString:  reqString,
		ResponseString: respString,
	}
	return tkn, err

}

func GenerateAuthorizationURL(flowType FlowType, state, promptFlag string) *url.URL {
	var option oauth2.AuthCodeOption = oauth2.SetAuthURLParam(RESPONSE_TYPE, string(flowType))
	URLString := config.OAuthConfig.OAuth2Config.AuthCodeURL(state, option)
	URL, err := url.Parse(URLString)
	if err != nil {
		log.Fatal(err)
	}

	switch promptFlag {
	case "DONT_SEND":
	default:
		SetQueryParameter(URL, "prompt", promptFlag)
	}

	// some authz servers (such as Okta) require a Nonce
	// despite it not being part of the RFC
	SetQueryParameter(URL, "nonce", randStr(32))
	return URL
}

// update FlowType value and update Authorization URL
func (i *FlowInstance) UpdateFlowType(ft string) {
	var responeType string
	switch ft {
	case "implicit":
		responeType = "token"
	case "authorization-code":
		responeType = "code"
	}

	i.FlowType = FlowType(responeType)
	SetQueryParameter(i.AuthorizationURL, RESPONSE_TYPE, responeType)
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

func randStr(len int) string {
	buff := make([]byte, len)
	rand.Read(buff)
	str := base64.URLEncoding.EncodeToString(buff)
	// Base 64 can be longer than len
	return str[:len]
}
