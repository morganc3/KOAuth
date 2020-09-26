package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
)

func main() {
	config := NewConfig("config.json")

	u, err := url.Parse(config.OAuthConfig.Endpoint.AuthURL)
	if err != nil {
		log.Fatal(err)
	}
	session := NewSession("session.json", u)

	implicit := NewInstance(config, session)
	req, _ := http.NewRequest("GET", implicit.AuthorizationURL, nil)

	resp, err := implicit.Session.Client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	ur := resp.Header.Get("Location")
	implicitAccessToken := getImplicitAccessTokenFromURL(ur)
	fmt.Println(implicitAccessToken)

	// authorizationCodeURL := config.GenerateAuthorizationCodeURL(state)

	// req2, _ := http.NewRequest("GET", authorizationCodeURL, nil)
	// session.setCookies(req2)
	// resp2, err := httpClient.Do(req2)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// u2 := resp2.Header.Get("Location")
	// authorizationCode := getAuthorizationCodeFromURL(u2)
	// fmt.Println(authorizationCode)
	// ctx := context.Background()
	// token, err := config.OAuthConfig.Exchange(ctx, authorizationCode)
	// fmt.Println(token.AccessToken)
}
