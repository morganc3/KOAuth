package main

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

type ImplicitFlowInstance struct {
	Ctx                  context.Context
	Session              KOAuthSession
	Config               KOAuthConfig
	AuthorizationURL     string
	AuthorizationRequest AuthorizationRequest
}

type AuthorizationRequest struct {
	Values   map[string][]string
	Request  http.Request
	Response http.Response
}

func (i *ImplicitFlowInstance) GenerateAuthorizationURL(state string) string {
	var implicitOption oauth2.AuthCodeOption = oauth2.SetAuthURLParam("response_type", "token")
	implicitURL := i.Config.OAuthConfig.AuthCodeURL(state, implicitOption)
	return implicitURL
}

func NewInstance(conf KOAuthConfig, sess KOAuthSession) ImplicitFlowInstance {
	ctx := context.Background()
	implicitInstance := ImplicitFlowInstance{
		Ctx:     ctx,
		Config:  conf,
		Session: sess,
	}
	implicitInstance.AuthorizationURL = implicitInstance.GenerateAuthorizationURL("random_state_value")
	return implicitInstance
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
