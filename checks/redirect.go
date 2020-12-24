package checks

import (
	"net/url"

	"github.com/morganc3/KOAuth/config"
	"github.com/morganc3/KOAuth/oauth"
)

// update the provided redirect URI in the FlowInstance
// and update the redirect_uri parameter in the already generated
// authorization URL
func updateRedirectURI(fi *oauth.FlowInstance, redirectUri string) {
	maliciousRedirectURI, _ := url.Parse(redirectUri)
	fi.ProvidedRedirectURL = maliciousRedirectURI
	oauth.SetQueryParameter(fi.AuthorizationURL, oauth.REDIRECT_URI, maliciousRedirectURI.String())
}

// Run test with redirectUri as redirect_uri URL parameter
// All redirect_uri testing should use this helper
func RedirectURICheck(fi *oauth.FlowInstance, redirectUri string) (State, error) {
	updateRedirectURI(fi, redirectUri)
	err := fi.DoAuthorizationRequest()

	// this will only be set with a value
	// if we were redirected to the provided redirect_uri
	// therefore, if this is not empty, we were redirected
	// to the malicious URI
	if fi.RedirectedToURL.String() != "" {
		return FAIL, nil
	}

	if err != nil {
		return WARN, err
	}

	return PASS, nil
}

// totally change redirect URI
func RedirectURITotalChange(fi *oauth.FlowInstance) (State, error) {
	return RedirectURICheck(fi, "http://fakedomain123321.com/callback")
}

// downgrade from HTTPS to HTTP
// Skip if redirect_uri uses HTTP
func RedirectURISchemeDowngrade(fi *oauth.FlowInstance) (State, error) {
	uri, _ := url.Parse(config.Config.OAuthConfig.RedirectURL)
	if uri.Scheme == "https" {
		uri.Scheme = "http"
	} else {
		return INFO, nil
	}
	uriStr := uri.String()

	return RedirectURICheck(fi, uriStr)
}

// func RedirectURIPathChange(fi *oauth.FlowInstance) (State, error) {

// }
