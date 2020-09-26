package main

type OAuthFlowInstance interface {
	NewInstance() interface{}
	CreateSession()
	GenerateAuthorizationURL() string
}
