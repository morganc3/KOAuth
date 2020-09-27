package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

type FlowInstance struct {
	Ctx                  context.Context
	Session              KOAuthSession
	Config               KOAuthConfig
	AuthorizationURL     *url.URL
	AuthorizationRequest AuthorizationRequest
}

type AuthorizationRequest struct {
	Values   map[string][]string
	Request  *http.Request
	Response *http.Response
}

func (i *FlowInstance) GenerateAuthorizationURL(state string) *url.URL {
	var option oauth2.AuthCodeOption = oauth2.SetAuthURLParam("response_type", "token")
	URLString := i.Config.OAuthConfig.AuthCodeURL(state, option)
	URL, err := url.Parse(URLString)
	if err != nil {
		log.Fatal(err)
	}
	return URL
}

// Sets value of the first key in the URL Query
func (i *FlowInstance) SetQueryParameter(key, value string) {
	url := i.AuthorizationURL
	url.Query().Set(key, value)
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
	url.Query().Del(key)
}

func NewInstance(conf KOAuthConfig, sess KOAuthSession) FlowInstance {
	ctx := context.Background()
	flowInstance := FlowInstance{
		Ctx:     ctx,
		Config:  conf,
		Session: sess,
	}
	flowInstance.AuthorizationURL = flowInstance.GenerateAuthorizationURL("random_state_value")
	return flowInstance
}

func getImplicitAccessTokenFromURL(urlString string) string {
	u, err := url.Parse(urlString)
	if err != nil {
		log.Fatal(err)
	}

	values, _ := url.ParseQuery(u.Fragment)
	tokenString := values.Get("access_token")
	return tokenString
}
