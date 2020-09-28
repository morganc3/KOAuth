package main

import (
	"fmt"
	"net/http"
	"net/url"
)

func GetLocationHeader(resp *http.Response) string {
	return resp.Header.Get("Location")
}

// Sets value of the first key in the URL Query
func SetQueryParameter(u *url.URL, key, value string) {
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
}

// Adds a query parameter value. If a value already exists with
// the specified key, this will add a second key/value pair in the URL
func AddQueryParameter(u *url.URL, key, value string) {
	queryString := u.RawQuery
	if queryString == "" {
		queryString += fmt.Sprintf("%s=%s", key, value)
	} else {
		queryString += fmt.Sprintf("&%s=%s", key, value)
	}

	u.RawQuery = queryString
}

// Returns all values in the URL query with the specified key
func GetQueryParameterAll(u *url.URL, key string) []string {
	values := u.Query()[key]
	return values
}

// Get first instance of key pair in URL
func GetQueryParameterFirst(u *url.URL, key string) string {
	return u.Query().Get(key)
}

// Delete first instance of key pair in URL
func DelQueryParameter(u *url.URL, key string) {
	q := u.Query()
	q.Del(key)
	u.RawQuery = q.Encode()
}
