package main

import (
	"fmt"
	"log"
	"net/http/httputil"
	"net/url"
	"os"
)

var config KOAuthConfig
var session KOAuthSession

func main() {
	config = NewConfig("config.json")

	u, err := url.Parse(config.OAuthConfig.Endpoint.AuthURL)
	if err != nil {
		log.Fatal(err)
	}
	session = NewSession("session.json", u)

	// Perform normal implicit flow token exchange to validate session has been properly setup
	if instance, ok := session.validateSession(); !ok {
		exitWithAuthInfo(instance)
	}

	chk := NewCheck("redirect-uri-change", "high", "certain", IMPLICIT_FLOW_RESPONSE_TYPE, redirectURITotalChange)
	chk.DoCheck()
	fmt.Println(chk.Pass)

	chk = NewCheck("state-supported", "medium", "certain", AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE, stateSupported)
	chk.DoCheck()
	fmt.Println(chk.Pass)

	chk = NewCheck("pkce-supported", "medium", "certain", AUTHORIZATION_CODE_FLOW_RESPONSE_TYPE, pkceSupported)
	chk.DoCheck()
	fmt.Println(chk.Pass)

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

func exitWithAuthInfo(fi *FlowInstance) {
	respBodyPretty, err := httputil.DumpResponse(fi.AuthorizationRequest.Response, true)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Could not perform normal implicit flow, cancelling scan")
	url := fi.GenerateAuthorizationURL(IMPLICIT_FLOW_RESPONSE_TYPE, "stateval")
	log.Printf("You likely need to reauthenticate here: %s", url.String())
	log.Printf("Received following response from authorization endpoint:")
	fmt.Printf("%s", respBodyPretty)
	os.Exit(1)
}
