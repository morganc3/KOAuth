package checks

// // checks if pkce is supported
// func PkceSupported(fi *oauth.FlowInstance) (State, error) {
// 	// TODO probably add helper function here to add pkce params
// 	data := []byte("rasdijasdjiasiudaradsiasdmkue012939123891238912398123")
// 	hash := sha256.Sum256(data)
// 	hashb64 := b64.URLEncoding.EncodeToString(hash[:])

// 	pkceCodeChallenge := hashb64

// 	oauth.SetQueryParameter(fi.AuthorizationURL, oauth.PKCE_CODE_CHALLENGE, pkceCodeChallenge)
// 	oauth.SetQueryParameter(fi.AuthorizationURL, oauth.PKCE_CODE_CHALLENGE_METHOD, oauth.PKCE_S256)

// 	err := fi.DoAuthorizationRequest()
// 	if err != nil {
// 		return WARN, err
// 	}
// 	redirectedTo := fi.RedirectedToURL

// 	authorizationCode := oauth.GetQueryParameterFirst(redirectedTo, oauth.AUTHORIZATION_CODE)
// 	opt := oauth2.SetAuthURLParam(oauth.PKCE_CODE_VERIFIER, string(data))

// 	v := url.Values{
// 		"grant_type": {"authorization_code"},
// 		"code":       {code},
// 	}

// 	tok, err := config.Config.OAuthConfig.Exchange(context.TODO(), authorizationCode, opt)
// 	if err != nil {
// 		return WARN, err
// 	}
// 	if err == nil && len(tok.AccessToken) > 0 {
// 		return PASS, nil
// 	}

// 	return FAIL, nil
// }
