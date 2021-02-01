package checks

// func TestAuthUrlFuncs(t *testing.T) {
// 	authUrl := "https://google.com?client_id=28923189123&state=random_state&redirect_uri=http://example.com&response_type=code"
// 	urlp, _ := url.Parse(authUrl)
// 	deleteRequiredParams(urlp, []string{"redirect_uri", "client_id", "response_type"})
// 	assert.Equal(t, "https://google.com?state=random_state", urlp.String())

// 	urlp, _ = url.Parse(authUrl)
// 	addAuthURLParams(urlp, map[string][]string{"redirect_uri": {"https://example.com"}})
// 	assert.Equal(t, fmt.Sprintf("%s%s", authUrl, "&redirect_uri=https://example.com"), urlp.String())

// 	urlp, _ = url.Parse(authUrl)
// 	deleteRequiredParams(urlp, []string{"redirect_uri", "state"})
// 	addAuthURLParams(urlp, map[string][]string{"redirect_uri": {"https://zzz1.com", "https://zzz2.com"}})
// 	expected := "https://google.com?client_id=28923189123&response_type=code&redirect_uri=https://zzz1.com&redirect_uri=https://zzz2.com"
// 	assert.Equal(t, expected, urlp.String())
// }
