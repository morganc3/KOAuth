package oauth

import (
	"context"
	"net/url"
	"testing"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
)

func TestURLFunctions(t *testing.T) {
	ctx, cancel := chromedp.NewContext(context.Background())
	flow := NewInstance(ctx, cancel, ImplicitFlowResponseType, "none")
	flow.AuthorizationURL, _ = url.Parse("http://example.com")
	AddQueryParameter(flow.AuthorizationURL, "k1", "v1")
	assert.Equal(t, "http://example.com?k1=v1", flow.AuthorizationURL.String())

	AddQueryParameter(flow.AuthorizationURL, "k2", "v2")
	assert.Equal(t, "http://example.com?k1=v1&k2=v2", flow.AuthorizationURL.String())

	DelQueryParameter(flow.AuthorizationURL, "k1")
	assert.Equal(t, "http://example.com?k2=v2", flow.AuthorizationURL.String())

	DelQueryParameter(flow.AuthorizationURL, "k2")
	assert.Equal(t, "http://example.com", flow.AuthorizationURL.String())

	AddQueryParameter(flow.AuthorizationURL, "k1", "v1")
	SetQueryParameter(flow.AuthorizationURL, "k1", "newvalue")
	assert.Equal(t, "http://example.com?k1=newvalue", flow.AuthorizationURL.String())

}
