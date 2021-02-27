package config

import (
	"log"
	"net/url"

	"github.com/hoisie/mustache"
)

// TODO: process skips here, add flag to skip?

// GenerateChecksInput - Makes values from config file available to
// checks so that check JSON input file can use
// values, such as the domain of the redirect_uri
// Supported keys: REDIRECT_URI, REDIRECT_SCHEME, REDIRECT_DOMAIN, REDIRECT_PATH,
// CLIENT_ID, CLIENT_SECRET, SCOPES, AUTH_URL, TOKEN_URL
func GenerateChecksInput(configFile string) []byte {
	templateKeyMap := make(map[string]interface{})
	redirectURI, err := url.Parse(OAuthConfig.OAuth2Config.RedirectURL)
	if err != nil {
		log.Fatal("invalid redirect_uri provided")
	}

	templateKeyMap["REDIRECT_URI"] = redirectURI.String()
	templateKeyMap["REDIRECT_SCHEME"] = redirectURI.Scheme
	templateKeyMap["REDIRECT_DOMAIN"] = redirectURI.Host
	templateKeyMap["REDIRECT_PATH"] = redirectURI.Path
	templateKeyMap["CLIENT_ID"] = OAuthConfig.OAuth2Config.ClientID
	templateKeyMap["CLIENT_SECRET"] = OAuthConfig.OAuth2Config.ClientSecret
	templateKeyMap["SCOPES"] = OAuthConfig.OAuth2Config.Scopes
	templateKeyMap["AUTH_URL"] = OAuthConfig.OAuth2Config.Endpoint.AuthURL
	templateKeyMap["TOKEN_URL"] = OAuthConfig.OAuth2Config.Endpoint.TokenURL

	data := mustache.RenderFile(configFile, templateKeyMap)
	bytes := []byte(data)
	return bytes

}
