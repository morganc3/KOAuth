package config

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/url"
	"os"

	"golang.org/x/oauth2"
)

var OAuthConfig KOAuthConfig

type EndpointWrapper struct {
	AuthURL  string `json:"auth_url"`
	TokenURL string `json:"token_url"`
}

type OAuthConfigWrapper struct {
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	Endpoint     EndpointWrapper `json:"endpoint"`
	RedirectURL  string          `json:"redirect_url"`
	Scopes       []string        `json:"scopes"`
}

type KOAuthConfig struct {
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
	var conf OAuthConfigWrapper
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

func (c *KOAuthConfig) GetRedirectURIHost() string {
	return getHost(c.OAuth2Config.RedirectURL)
}

func (c *KOAuthConfig) GetConfigHost() string {
	return getHost(c.OAuth2Config.Endpoint.AuthURL)
}

func NewConfig(oauthConfigFile, authStyle string) KOAuthConfig {
	conf := new(KOAuthConfig)
	conf.OAuth2Config = readOAuthConfig(oauthConfigFile, authStyle)
	return *conf
}

func (c *KOAuthConfig) Init() {
	configFile := GetOpt(FLAG_CONFIG)
	clientAuth := GetOpt(FLAG_CLIENT_AUTH)
	OAuthConfig = NewConfig(configFile, clientAuth)
}
