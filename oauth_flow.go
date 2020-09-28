package main

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

type FlowType string

const (
	IMPLICIT_FLOW_RESPONSE_TYPE           = "token"
	AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE = "code"
)

const FLOW_ERROR = "ERROR"

type FlowInstance struct {
	Ctx                  context.Context
	FlowType             FlowType
	AuthorizationURL     *url.URL
	AuthorizationRequest *AuthorizationRequest
	ExchangeRequest      *ExchangeRequest
}

type AuthorizationRequest struct {
	Request  *http.Request
	Response *http.Response
}

type ExchangeRequest struct {
	Request  *http.Request
	Response *http.Response
}

func NewInstance(ft FlowType) *FlowInstance {
	ctx := context.Background()
	flowInstance := FlowInstance{
		Ctx:                  ctx,
		FlowType:             ft,
		AuthorizationRequest: new(AuthorizationRequest),
		ExchangeRequest:      new(ExchangeRequest),
	}
	flowInstance.AuthorizationURL = flowInstance.GenerateAuthorizationURL(ft, "random_state_value")
	return &flowInstance
}

func (i *FlowInstance) DoAuthorizationRequest() {
	urlStr := i.AuthorizationURL.String()
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		i.Ctx = context.WithValue(i.Ctx, FLOW_ERROR, err)
		return
	}

	resp, err := session.Client.Do(req)

	if err != nil {
		i.Ctx = context.WithValue(i.Ctx, FLOW_ERROR, err)
		return
	}

	i.AuthorizationRequest.Request = req
	i.AuthorizationRequest.Response = resp
}

func (i *FlowInstance) GenerateAuthorizationURL(flowType FlowType, state string) *url.URL {
	var option oauth2.AuthCodeOption = oauth2.SetAuthURLParam(RESPONSE_TYPE, string(flowType))
	URLString := config.OAuthConfig.AuthCodeURL(state, option)
	URL, err := url.Parse(URLString)
	if err != nil {
		log.Fatal(err)
	}
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
