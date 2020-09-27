package main

import (
	"log"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURLFunctions(t *testing.T) {
	config := NewConfig("config.json")

	u, err := url.Parse(config.OAuthConfig.Endpoint.AuthURL)
	if err != nil {
		log.Fatal(err)
	}
	session := NewSession("session.json", u)

	flow := NewInstance(config, session)
	flow.AuthorizationURL, _ = url.Parse("http://example.com")
	flow.AddQueryParameter("k1", "v1")
	assert.Equal(t, "http://example.com?k1=v1", flow.AuthorizationURL.String())

	flow.AddQueryParameter("k2", "v2")
	assert.Equal(t, "http://example.com?k1=v1&k2=v2", flow.AuthorizationURL.String())

}
