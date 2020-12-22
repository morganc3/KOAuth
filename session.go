package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)

// Electron Cookie format
type SessionCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HttpOnly bool   `json:"httpOnly,omitempty"`
}

type LocalStorageItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type KOAuthSession struct {
	Cookies      []SessionCookie    `json:"cookies"`
	LocalStorage []LocalStorageItem `json:"localStorage"`
	Client       http.Client
}

func NewSession(sessionFile string, u *url.URL) KOAuthSession {
	return readSessionInformation(sessionFile)
}

func readSessionInformation(sessionFile string) KOAuthSession {
	jsonFile, err := os.Open(sessionFile)
	if err != nil {
		log.Fatal("Error opening session JSON file")
	}
	defer jsonFile.Close()
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatal("Error reading session JSON file")
	}
	var sess KOAuthSession
	json.Unmarshal(byteValue, &sess)
	return sess
}

// TODO - this should check both authz code flow and implicit flow
// Attempt normal implicit flow to see if we successfully get an Access Token back
func (session *KOAuthSession) validateSession() (*FlowInstance, bool) {
	implicitInstance := NewInstance(IMPLICIT_FLOW_RESPONSE_TYPE)
	err := implicitInstance.DoAuthorizationRequest()
	if err != nil {
		log.Println(err)
		return nil, false
	}

	ur := implicitInstance.RedirectedToURL
	implicitAccessToken := getImplicitAccessTokenFromURL(ur.String())

	ok := len(implicitAccessToken) > 0

	return implicitInstance, ok
}
