package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/url"
	"os"

	"golang.org/x/oauth2"
)

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
	OAuthConfig oauth2.Config
}

// Get an oauth2 config from JSON file
func readOAuthConfig(oauthConfigFile string) oauth2.Config {
	jsonFile, err := os.Open(oauthConfigFile)
	if err != nil {
		panic("Error opening session JSON file")
	}
	defer jsonFile.Close()
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		panic("Error reading session JSON file")
	}
	var conf OAuthConfigWrapper
	json.Unmarshal(byteValue, &conf)

	var oauthConfig = &oauth2.Config{
		RedirectURL:  conf.RedirectURL,
		ClientID:     conf.ClientID,
		ClientSecret: conf.ClientSecret,
		Scopes:       conf.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   conf.Endpoint.AuthURL,
			TokenURL:  conf.Endpoint.TokenURL,
			AuthStyle: 0,
		},
	}
	return *oauthConfig
}

func (c *KOAuthConfig) getConfigHost() string {
	url, err := url.Parse(c.OAuthConfig.Endpoint.AuthURL)
	if err != nil {
		log.Fatal(err)
	}
	return url.Host
}

func NewConfig(oauthConfigFile string) KOAuthConfig {
	conf := new(KOAuthConfig)
	conf.OAuthConfig = readOAuthConfig(oauthConfigFile)
	return *conf
}
