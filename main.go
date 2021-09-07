package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	pkce "github.com/nirasan/go-oauth-pkce-code-verifier"
	"golang.org/x/oauth2"
)

func login(ctx context.Context, server string, clientID string) (*http.Client, error) {
	const authRedirect = "http://localhost:11123/auth/callback"

	provider, err := oidc.NewProvider(ctx, server)
	if err != nil {
		log.Fatal(err)
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	tokenVerifier := provider.Verifier(oidcConfig)

	conf := &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
		RedirectURL: authRedirect,
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	codeVerifier, err := pkce.CreateCodeVerifier()
	if err != nil {
		return nil, err
	}
	state := fmt.Sprintf("%x", rand.Int63())
	url := conf.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeVerifier.CodeChallengeS256()))
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	handleRedirect := http.Server{
		Addr: "localhost:11123",
	}

	cleanup := func(err error) {
		if err != nil {
			fmt.Printf("ERROR: %v\n\n", err)
		}
		if err := handleRedirect.Shutdown(ctx); err != nil {
			fmt.Printf("ERROR: %v\n", err)
		}
	}

	var tok *oauth2.Token
	handleRedirect.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stateCheck := r.URL.Query().Get("state"); stateCheck != state {
			cleanup(fmt.Errorf("state check mismatch (expected %s but got %s)", state, stateCheck))
			return
		}

		authCode := r.URL.Query().Get("code")
		oauth2Token, err := conf.Exchange(ctx, authCode, oauth2.SetAuthURLParam("code_verifier", codeVerifier.String()))
		if err != nil {
			cleanup(err)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			cleanup(err)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := tokenVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			cleanup(err)
			return
		}

		// Extract custom claims
		var claims struct {
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := idToken.Claims(&claims); err != nil {
			cleanup(err)
			return
		}

		fmt.Printf("Identified user %s\n", claims.Email)

		tok = oauth2Token
		cleanup(nil)
	})

	if err := handleRedirect.ListenAndServe(); err != http.ErrServerClosed {
		return nil, err
	}

	// Use the custom HTTP client when requesting a token.
	httpClient := &http.Client{Timeout: 2 * time.Second}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	client := conf.Client(ctx, tok)
	return client, nil
}

func main() {
	ctx := context.Background()
	if client, err := login(ctx, "https://dev-433811.oktapreview.com", "0oa11fbh947AaFdm20h8"); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("%v", client)
	}
}
