package oauth

import (
	"context"
)

var ChromeContext context.Context

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
