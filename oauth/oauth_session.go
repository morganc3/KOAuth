package oauth

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)

var Session KOAuthSession

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
func (session *KOAuthSession) ValidateSession() (*FlowInstance, bool) {
	implicitInstance := NewInstance(IMPLICIT_FLOW_RESPONSE_TYPE)
	err := implicitInstance.DoAuthorizationRequest()
	if err != nil {
		log.Println(err)
		return nil, false
	}

	ur := implicitInstance.RedirectedToURL
	implicitAccessToken := GetImplicitAccessTokenFromURL(ur.String())

	ok := len(implicitAccessToken) > 0

	return implicitInstance, ok
}
