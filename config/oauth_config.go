package config

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/url"
	"os"

	"golang.org/x/oauth2"
)

// OAuthConfig - KOAuth oauth config. different from Golang's oauth2 config object.
var OAuthConfig kOAuthConfig

type endpointWrapper struct {
	AuthURL  string `json:"auth_url"`
	TokenURL string `json:"token_url"`
}

type oAuthConfigWrapper struct {
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	Endpoint     endpointWrapper `json:"endpoint"`
	RedirectURL  string          `json:"redirect_url"`
	Scopes       []string        `json:"scopes"`
}

type kOAuthConfig struct {
	OAuth2Config oauth2.Config
}

// Get an oauth2 config from JSON file
func readOAuthConfig(oauthConfigFile string, authStyle string) oauth2.Config {
	jsonFile, err := os.Open(oauthConfigFile)
	if err != nil {
		panic("Error opening oauth config file")
	}
	defer jsonFile.Close()
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		panic("Error reading oauth config JSON file")
	}
	var conf oAuthConfigWrapper
	err = json.Unmarshal(byteValue, &conf)
	if err != nil {
		panic("Error unmarshalling oauth config")
	}

	var clientAuth oauth2.AuthStyle
	switch authStyle {
	case "BASIC":
		clientAuth = oauth2.AuthStyleInHeader
	case "BODY":
		clientAuth = oauth2.AuthStyleInParams
	default:
		clientAuth = oauth2.AuthStyleAutoDetect
	}
	var oauthConfig = &oauth2.Config{
		RedirectURL:  conf.RedirectURL,
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Scopes:       conf.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   conf.Endpoint.AuthURL,
			TokenURL:  conf.Endpoint.TokenURL,
			AuthStyle: clientAuth,
		},
	}
	return *oauthConfig
}

func getHost(urlStr string) string {
	url, err := url.Parse(urlStr)
	if err != nil {
		log.Fatal(err)
	}
	return url.Host
}

func (c *kOAuthConfig) GetRedirectURIHost() string {
	return getHost(c.OAuth2Config.RedirectURL)
}

func (c *kOAuthConfig) GetConfigHost() string {
	return getHost(c.OAuth2Config.Endpoint.AuthURL)
}

func newConfig(oauthConfigFile, authStyle string) kOAuthConfig {
	conf := new(kOAuthConfig)
	conf.OAuth2Config = readOAuthConfig(oauthConfigFile, authStyle)
	return *conf
}

// Init - initialize KOAuthConfig object based on cli flags and oauth config file
func (c *kOAuthConfig) Init() {
	configFile := GetOpt(FlagConfig)
	clientAuth := GetOpt(FlagClientAuth)
	OAuthConfig = newConfig(configFile, clientAuth)
}
