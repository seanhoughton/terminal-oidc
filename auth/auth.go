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
	"github.com/pkg/browser"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

const defaultPort = 11123

type promptFunc func(authURL string) error

type TerminalAuth struct {
	ClientID string
	Issuer   string

	tokenVerifier  *oidc.IDTokenVerifier
	authConfig     *oauth2.Config
	lastGoodToken  *oauth2.Token
	port           int16
	logger         *log.Logger
	clientSecret   string
	prompt         promptFunc
	keychainPrefix string
	scopes         []string
	extraFields    []string
}

type Option func(*TerminalAuth)

// WithLogger installs a custom logger instance
func WithLogger(logger *log.Logger) Option {
	return func(ta *TerminalAuth) {
		ta.logger = logger
	}
}

// WithRedirectPort customizes the local OAuth redirect port (default: 11123)
func WithRedirectPort(port int16) Option {
	return func(ta *TerminalAuth) {
		ta.port = port
	}
}

// WithClientSecret adds a client secret to the authorization request
// Note that this is required by some providers but not all.
func WithClientSecret(secret string) Option {
	return func(ta *TerminalAuth) {
		ta.clientSecret = secret
	}
}

// WithStdoutPrompt prints the authorization URL to stdout
func WithStdoutPrompt() Option {
	return func(ta *TerminalAuth) {
		ta.prompt = func(authURL string) error {
			fmt.Printf("Visit the URL for the auth dialog: %v\n", authURL)
			return nil
		}
	}
}

// WithBrowserPrompt opens the authorization URL in the default browser
func WithBrowserPrompt() Option {
	return func(ta *TerminalAuth) {
		ta.prompt = func(authURL string) error {
			return browser.OpenURL(authURL)
		}
	}
}

// WithKeychainPrefix sets a prefix for naming the stored secret
func WithKeychainPrefix(prefix string) Option {
	return func(ta *TerminalAuth) {
		ta.keychainPrefix = prefix
	}
}

// WithScopes adds additional scopes to the authentication request
// Note that some providers (e.g. Okta) require the "offline_access" scope to get
// a refresh token while Google will fail if the "offline_access" scope is requested
func WithScopes(scopes ...string) Option {
	return func(ta *TerminalAuth) {
		ta.scopes = append(ta.scopes, scopes...)
	}
}

// NewTerminalAuth returns an initialized TerminalAuth instance
func NewTerminalAuth(ctx context.Context, issuer string, clientID string, options ...Option) (*TerminalAuth, error) {
	// default configuration
	ta := &TerminalAuth{
		ClientID: clientID,
		Issuer:   issuer,
	}
	WithLogger(log.Default())(ta)
	WithRedirectPort(defaultPort)(ta)
	WithScopes(oidc.ScopeOpenID, "profile", "email")(ta)
	WithStdoutPrompt()(ta)
	WithKeychainPrefix("terminaloidc")(ta)

	// options
	for _, opt := range options {
		opt(ta)
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	ta.logger.Println("Using authorization endpoint ", provider.Endpoint())

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}

	ta.authConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: ta.clientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       ta.scopes,
		RedirectURL:  fmt.Sprintf("http://localhost:%d/auth/callback", ta.port),
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
		ta.logger.Printf("Stored token is not usable: %v\n", err)
		return ta, nil
	} else {
		// keep the most recent refreshed token
		ta.lastGoodToken = newToken
		return ta, nil
	}
}

func (ta *TerminalAuth) Token(ctx context.Context) (*oauth2.Token, error) {
	return ta.tokenSource(ctx).Token()
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

func (ta *TerminalAuth) IDToken(ctx context.Context) (*oidc.IDToken, error) {
	if ta.lastGoodToken == nil {
		return nil, ErrNoLoadedToken
	} else if rawIDToken, ok := ta.lastGoodToken.Extra("id_token").(string); !ok {
		return nil, fmt.Errorf("invalid loaded token")
	} else if idToken, err := ta.tokenVerifier.Verify(ctx, rawIDToken); err != nil {
		return nil, err
	} else {
		return idToken, nil
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
	authURL := ta.authConfig.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeVerifier.CodeChallengeS256()))

	if err := ta.prompt(authURL); err != nil {
		return nil, err
	}

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

		if oauth2Token.RefreshToken == "" {
			log.Println("Warning: auth response contains no refresh toke")
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			cleanup(err)
			return
		}

		// Parse and verify ID Token payload.
		_, err = ta.tokenVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			cleanup(err)
			return
		}

		ta.logger.Println("Received valid token")
		tok = oauth2Token
		cleanup(nil)

	})

	ta.logger.Printf("Waiting for redirect to %s\n", ta.authConfig.RedirectURL)
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
var ErrNoLoadedToken = errors.New("no loaded token")

func (ta *TerminalAuth) keychainName() string {
	return fmt.Sprintf("%s-%s", ta.keychainPrefix, ta.Issuer)
}

func (ta *TerminalAuth) loadToken() error {
	tok := oauth2.Token{}
	if data, err := keyring.Get(ta.keychainName(), "token"); err != nil {
		if err == keyring.ErrNotFound {
			return ErrNoSavedToken
		} else {
			return err
		}
	} else if err := json.NewDecoder(strings.NewReader(data)).Decode(&tok); err != nil {
		return err
	} else if idToken, err := keyring.Get(ta.keychainName(), "id-token"); err != nil {
		if err == keyring.ErrNotFound {
			return ErrNoSavedToken
		} else {
			return err
		}
	} else {
		fullTok := tok.WithExtra(map[string]interface{}{"id_token": idToken})
		expiresIn := time.Until(fullTok.Expiry).Seconds()
		if expiresIn < 0 {
			ta.logger.Printf("Loaded token at %s is expired\n", ta.keychainName())
		} else {
			ta.logger.Printf("Loaded token at %s that expires in %f seconds\n", ta.keychainName(), expiresIn)
		}
		ta.lastGoodToken = fullTok
		return nil
	}
}

func (ta *TerminalAuth) setToken(tok *oauth2.Token) error {
	ta.lastGoodToken = tok
	b := strings.Builder{}
	if err := json.NewEncoder(&b).Encode(tok); err != nil {
		return err
	} else if err := keyring.Set(ta.keychainName(), "token", b.String()); err != nil {
		return err
	} else if idToken, ok := tok.Extra("id_token").(string); !ok {
		return fmt.Errorf("bad id token")
	} else if err := keyring.Set(ta.keychainName(), "id-token", idToken); err != nil {
		return err
	} else {
		ta.logger.Printf("Token updated and saved as %s (field: token)\n", ta.keychainName())
		return nil
	}
}
