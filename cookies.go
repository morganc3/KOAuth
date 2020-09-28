package main

import (
	"net/http"
	"net/url"
	"sync"
)

// Implements Cookie Jar interface

type Jar struct {
	lk      sync.Mutex
	cookies map[string][]*http.Cookie
}

func NewJar() *Jar {
	jar := new(Jar)
	jar.cookies = make(map[string][]*http.Cookie)
	return jar
}

// Will be called for Set-Cookie response headers,
// update cookie jar with new cookies
func (jar *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	jar.lk.Lock()
	for _, c := range cookies {
		jar.cookies[u.Host] = append(jar.cookies[u.Host], c)
	}
	jar.lk.Unlock()
}

// return existing cookies for Host
func (jar *Jar) Cookies(u *url.URL) []*http.Cookie {
	return jar.cookies[u.Host]
}
