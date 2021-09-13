package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	pkce "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

type TerminalAuth struct {
	ClientID string
	Issuer   string

	tokenVerifier *oidc.IDTokenVerifier
	authConfig    *oauth2.Config
	lastGoodToken *oauth2.Token
	port          int16
	logger        *log.Logger
	clientSecret  string
}

type Option func(*TerminalAuth)

func WithLogger(logger *log.Logger) Option {
	return func(ta *TerminalAuth) {
		ta.logger = logger
	}
}

func WithRedirectPort(port int16) Option {
	return func(ta *TerminalAuth) {
		ta.port = port
	}
}

func WithClientSecret(secret string) Option {
	return func(ta *TerminalAuth) {
		ta.clientSecret = secret
	}
}

func NewTerminalAuth(ctx context.Context, issuer string, clientID string, options ...Option) (*TerminalAuth, error) {
	ta := &TerminalAuth{
		ClientID: clientID,
		Issuer:   issuer,
		port:     11123,
		logger:   log.Default(),
	}

	for _, opt := range options {
		opt(ta)
	}

	authRedirect := fmt.Sprintf("http://localhost:%d/auth/callback", ta.port)

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	ta.logger.Println("Using authorization endpoint ", provider.Endpoint())

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	ta.authConfig = &oauth2.Config{
		ClientID: clientID,
		Endpoint: provider.Endpoint(),
		Scopes: []string{
			oidc.ScopeOpenID,
			oidc.ScopeOfflineAccess,
			"profile",
			"email"},
		RedirectURL: authRedirect,
	}

	ta.tokenVerifier = provider.Verifier(oidcConfig)

	// restore the saved token if it exists
	if err := ta.loadToken(); err != nil && err != ErrNoSavedToken {
		return nil, err
	} else if ta.lastGoodToken.Valid() {
		// we have a valid token that's not timed out
		return ta, nil
	} else if newToken, err := ta.tokenSource(ctx).Token(); err != nil {
		// failed to refresh the old token
		return nil, err
	} else {
		// keep the most recent refreshed token
		ta.lastGoodToken = newToken
		return ta, nil
	}
}

// Valid returns "true" if a non-expired token has been loaded
func (ta *TerminalAuth) Valid() bool {
	return ta.lastGoodToken != nil && ta.lastGoodToken.Valid()
}

// Login will present a URL to the terminal for the user to click and then follow the oauth2 flow
// to acquire token data
func (ta *TerminalAuth) Login(ctx context.Context) error {
	ta.lastGoodToken = nil
	if tok, err := ta.login(ctx); err != nil {
		return err
	} else {
		return ta.setToken(tok)
	}
}

func (ta *TerminalAuth) login(ctx context.Context) (*oauth2.Token, error) {
	ta.logger.Println("Starting new login")
	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	codeVerifier, err := pkce.CreateCodeVerifier()
	if err != nil {
		return nil, err
	}
	state := fmt.Sprintf("%x", rand.Int63())
	url := ta.authConfig.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeVerifier.CodeChallengeS256()))
	fmt.Printf("Visit the URL for the auth dialog: %v\n", url)

	handleRedirect := http.Server{
		Addr: fmt.Sprintf("localhost:%d", ta.port),
	}

	cleanup := func(err error) {
		if err != nil {
			ta.logger.Println(err)
		}
		if err := handleRedirect.Shutdown(ctx); err != nil {
			ta.logger.Println(err)
		}
	}

	var tok *oauth2.Token
	handleRedirect.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ta.logger.Println("Received auth callback")
		if stateCheck := r.URL.Query().Get("state"); stateCheck != state {
			cleanup(fmt.Errorf("state check mismatch (expected %s but got %s)", state, stateCheck))
			return
		}

		authCode := r.URL.Query().Get("code")
		oauth2Token, err := ta.authConfig.Exchange(ctx, authCode, oauth2.SetAuthURLParam("code_verifier", codeVerifier.String()))
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
		idToken, err := ta.tokenVerifier.Verify(ctx, rawIDToken)
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

		ta.logger.Println("Received valid token")
		tok = oauth2Token
		cleanup(nil)

	})

	if err := handleRedirect.ListenAndServe(); err != http.ErrServerClosed {
		return nil, err
	}

	return tok, nil
}

func (ta *TerminalAuth) tokenSource(ctx context.Context) oauth2.TokenSource {
	return &NotifyRefreshTokenSource{
		new: ta.authConfig.TokenSource(ctx, ta.lastGoodToken),
		t:   ta.lastGoodToken,
		f:   ta.setToken,
	}
}

// Client returns an http client which uses the token and will automatically refresh
// it when the token expires
func (ta *TerminalAuth) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, ta.tokenSource(ctx))
}

var ErrNoSavedToken = errors.New("no saved token")

func (ta *TerminalAuth) loadToken() error {
	tok := oauth2.Token{}
	if data, err := keyring.Get(ta.Issuer, "token"); err != nil {
		if err == keyring.ErrNotFound {
			return ErrNoSavedToken
		} else {
			return err
		}
	} else if err := json.NewDecoder(strings.NewReader(data)).Decode(&tok); err != nil {
		return err
	} else {
		//tok.Expiry = tok.Expiry.Add(-10 * time.Hour) // hack to force expiration
		ta.logger.Printf("Loaded token that expires in %f seconds\n", time.Until(tok.Expiry).Seconds())
		ta.lastGoodToken = &tok
		return nil
	}
}

func (ta *TerminalAuth) setToken(tok *oauth2.Token) error {
	ta.lastGoodToken = tok
	b := strings.Builder{}
	if err := json.NewEncoder(&b).Encode(tok); err != nil {
		return err
	} else if err := keyring.Set(ta.Issuer, "token", b.String()); err != nil {
		return err
	} else {
		ta.logger.Println("Token updated and saved")
		return nil
	}
}
