package checks

import (
	"context"
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"

	"github.com/morganc3/KOAuth/config"
	"github.com/morganc3/KOAuth/oauth"
	"golang.org/x/oauth2"
)

// checks if pkce is supported
func PkceSupported(fi *oauth.FlowInstance) (State, error) {
	// TODO probably add helper function here to add pkce params
	data := []byte("random-code-verifier-value-012939123891238912398123")
	hash := sha256.Sum256(data)
	hashb64 := b64.URLEncoding.EncodeToString(hash[:])

	pkceCodeChallenge := hashb64
	fmt.Println(pkceCodeChallenge)
	fmt.Println(oauth.PKCE_S256)
	oauth.SetQueryParameter(fi.AuthorizationURL, oauth.PKCE_CODE_CHALLENGE, pkceCodeChallenge)
	oauth.SetQueryParameter(fi.AuthorizationURL, oauth.PKCE_CODE_CHALLENGE_METHOD, oauth.PKCE_S256)

	err := fi.DoAuthorizationRequest()
	if err != nil {
		return WARN, err
	}
	redirectedTo := fi.RedirectedToURL

	authorizationCode := oauth.GetQueryParameterFirst(redirectedTo, oauth.AUTHORIZATION_CODE)
	opt := oauth2.SetAuthURLParam(oauth.PKCE_CODE_VERIFIER, string(data))
	opt2 := oauth2.SetAuthURLParam(oauth.PKCE_CODE_CHALLENGE_METHOD, oauth.PKCE_S256)
	tok, err := config.Config.OAuthConfig.Exchange(context.TODO(), authorizationCode, opt, opt2)
	if err != nil {
		return WARN, err
	}
	if err == nil && len(tok.AccessToken) > 0 {
		return PASS, nil
	}

	return FAIL, nil
}
