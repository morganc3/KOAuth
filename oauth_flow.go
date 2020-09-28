package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

type FlowType string

const (
	IMPLICIT           = "IMPLICIT"
	AUTHORIZATION_FLOW = "AUTHORIZATION_FLOW"
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

func NewInstance(ft FlowType) FlowInstance {
	ctx := context.Background()
	flowInstance := FlowInstance{
		Ctx:      ctx,
		FlowType: ft,
	}
	flowInstance.AuthorizationURL = flowInstance.GenerateAuthorizationURL(ft, "random_state_value")
	return flowInstance
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

// Sets value of the first key in the URL Query
func (i *FlowInstance) SetQueryParameter(key, value string) {
	url := i.AuthorizationURL
	q := url.Query()
	q.Set(key, value)
	url.RawQuery = q.Encode()
}

// Adds a query parameter value. If a value already exists with
// the specified key, this will add a second key/value pair in the URL
func (i *FlowInstance) AddQueryParameter(key, value string) {
	url := i.AuthorizationURL
	queryString := url.RawQuery
	if queryString == "" {
		queryString += fmt.Sprintf("%s=%s", key, value)
	} else {
		queryString += fmt.Sprintf("&%s=%s", key, value)
	}

	url.RawQuery = queryString
}

// Returns all values in the URL query with the specified key
func (i *FlowInstance) GetQueryParameter(key string) []string {
	url := i.AuthorizationURL
	values := url.Query()[key]
	return values
}

// Delete first instance of key pair in URL
func (i *FlowInstance) DelQueryParameter(key string) {
	url := i.AuthorizationURL
	q := url.Query()
	q.Del(key)
	url.RawQuery = q.Encode()
}
