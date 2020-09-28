package main

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURLFunctions(t *testing.T) {
	flow := NewInstance(IMPLICIT)
	flow.AuthorizationURL, _ = url.Parse("http://example.com")
	flow.AddQueryParameter("k1", "v1")
	assert.Equal(t, "http://example.com?k1=v1", flow.AuthorizationURL.String())

	flow.AddQueryParameter("k2", "v2")
	assert.Equal(t, "http://example.com?k1=v1&k2=v2", flow.AuthorizationURL.String())

	flow.DelQueryParameter("k1")
	assert.Equal(t, "http://example.com?k2=v2", flow.AuthorizationURL.String())

	flow.DelQueryParameter("k2")
	assert.Equal(t, "http://example.com", flow.AuthorizationURL.String())

	flow.AddQueryParameter("k1", "v1")
	flow.SetQueryParameter("k1", "newvalue")
	assert.Equal(t, "http://example.com?k1=newvalue", flow.AuthorizationURL.String())

}
