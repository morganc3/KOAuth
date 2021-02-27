package oauth

import (
	"log"
	"net/url"
)

// SetQueryParameter - Sets value of the first key in the URL Query
func SetQueryParameter(u *url.URL, key, value string) {
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
}

// AddQueryParameter - Adds a query parameter value. If a value already exists with
// the specified key, this will add a second key/value pair in the URL
func AddQueryParameter(u *url.URL, key, value string) {
	q := u.Query()
	if len(q[key]) == 0 {
		q[key] = []string{value}
	} else {
		q[key] = append(q[key], value)
	}

	u.RawQuery = q.Encode()
}

// GetFragmentParameterAll - Returns all values in the URL fragment
func GetFragmentParameterAll(u *url.URL, key string) []string {
	values, err := url.ParseQuery(u.Fragment)
	if err != nil {
		log.Println("Error: Could not parse Fragment params")
		log.Println(err)
		return values[key]
	}
	return values[key]
}

// GetFragmentParameterFirst - Returns first instance of key in URL fragment
func GetFragmentParameterFirst(u *url.URL, key string) string {
	values, err := url.ParseQuery(u.Fragment)
	if err != nil {
		log.Println("Error: Could not parse Fragment params")
		log.Println(err)
		return ""
	}
	return values.Get(key)
}

// GetQueryParameterAll - Returns all values in the URL query with the specified key
func GetQueryParameterAll(u *url.URL, key string) []string {
	values := u.Query()[key]
	return values
}

// GetQueryParameterFirst - Get first instance of key in URL
func GetQueryParameterFirst(u *url.URL, key string) string {
	return u.Query().Get(key)
}

// DelQueryParameter - Delete first instance of key pair in URL
func DelQueryParameter(u *url.URL, key string) {
	q := u.Query()
	q.Del(key)
	u.RawQuery = q.Encode()
}
