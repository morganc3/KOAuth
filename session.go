package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)

type KOAuthSession struct {
	InitialCookies map[string]string `json:"cookies"`
	InitialHeaders map[string]string `json:"headers"`
	Client         http.Client
}

func NewSession(sessionFile string, u *url.URL) KOAuthSession {
	sess := readSessionInformation(sessionFile)

	jar := NewJar()
	sess.setInitialCookies(jar, u)
	httpClient := http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// TODO: Check if redirect location is different than current domain
			// It's possible some servers will first 302 to themselves for some reason
			// Right now we're assuming it will immediately redirect to redirect_uri
			return http.ErrUseLastResponse
		},
	}

	sess.Client = httpClient

	return sess
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

func (session *KOAuthSession) setInitialCookies(jar *Jar, u *url.URL) {
	var cookies []*http.Cookie
	for k, v := range session.InitialCookies {
		cookie := &http.Cookie{Name: k, Value: v}
		cookies = append(cookies, cookie)
	}
	jar.SetCookies(u, cookies)
}

func (session *KOAuthSession) setHeaders(r *http.Request) {
	for headerName, headerValue := range session.InitialHeaders {
		r.Header.Set(headerName, headerValue)
	}
}
