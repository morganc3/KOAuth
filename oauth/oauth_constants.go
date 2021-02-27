package oauth

// OAuth 2.0 HTTP parameter constants
const (
	RedirectURIParam             = "redirect_uri"
	ResponseTypeParam            = "response_type"
	GrantTypeParam               = "grant_type"
	StateParam                   = "state"
	TokenTypeParam               = "token_type"
	ExpiresInParam               = "expires_in"
	ScopeParam                   = "scope"
	RefreshTokenParam            = "refresh_token"
	AccessTokenParam             = "access_token"
	ClientIDParam                = "client_id"
	ClientSecretParam            = "client_secret"
	UsernameParam                = "username"
	PasswordParam                = "password"
	ErrorParam                   = "error"
	PKCECodeVerifierParam        = "code_verifier"
	PKCECodeChallengeParam       = "code_challenge"
	PKCECodeChallengeMethodParam = "code_challenge_method"
)

// PKCE code challenge method param values
const (
	PKCES256  = "S256"
	PKCEPLAIN = "plain"
)

// OAuth 2.0 flow types, as defined in provided JSON check structure
const (
	FlowAuthorizationCode = "authorization-code"
	FlowImplicit          = "implicit"
)
