package main

import (
	"log"
	"net/url"
)

func getAuthorizationCodeFromURL(urlString string) string {
	u, err := url.Parse(urlString)
	if err != nil {
		log.Fatal(err)
	}
	values, _ := url.ParseQuery(u.RawQuery)
	authzCodeString := values.Get("code")
	return authzCodeString
}
