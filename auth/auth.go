package auth

import (
	"context"
	"crypto/sha1"
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

type Option func(*TerminalAuth) error

// WithLogger installs a custom logger instance
func WithLogger(logger *log.Logger) Option {
	return func(ta *TerminalAuth) error {
		ta.logger = logger
		return nil
	}
}

// WithRedirectPort customizes the local OAuth redirect port (default: 11123)
func WithRedirectPort(port int16) Option {
	return func(ta *TerminalAuth) error {
		ta.port = port
		return nil
	}
}

// WithClientSecret adds a client secret to the authorization request
// Note that this is required by some providers but not all.
func WithClientSecret(secret string) Option {
	return func(ta *TerminalAuth) error {
		ta.clientSecret = secret
		return nil
	}
}

// WithStdoutPrompt prints the authorization URL to stdout
func WithStdoutPrompt() Option {
	return func(ta *TerminalAuth) error {
		ta.prompt = func(authURL string) error {
			fmt.Printf("Visit the URL for the auth dialog: %v\n", authURL)
			return nil
		}
		return nil
	}
}

// WithBrowserPrompt opens the authorization URL in the default browser
func WithBrowserPrompt() Option {
	return func(ta *TerminalAuth) error {
		ta.prompt = func(authURL string) error {
			return browser.OpenURL(authURL)
		}
		return nil
	}
}

// WithKeychainPrefix sets a prefix for naming the stored secret
func WithKeychainPrefix(prefix string) Option {
	return func(ta *TerminalAuth) error {
		ta.keychainPrefix = prefix
		return nil
	}
}

// WithScopes adds additional scopes to the authentication request
// Note that some providers (e.g. Okta) require the "offline_access" scope to get
// a refresh token while Google will fail if the "offline_access" scope is requested
func WithScopes(scopes ...string) Option {
	return func(ta *TerminalAuth) error {
		ta.scopes = append(ta.scopes, scopes...)
		return nil
	}
}

// WithRefreshToken will install an initial refresh token to be used
// and should be used in a provisioned setting where refresh tokens
// are known
func WithRefreshToken(token string) Option {
	return func(ta *TerminalAuth) error {
		return ta.setToken(&oauth2.Token{
			RefreshToken: token,
		})
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
	if err := ta.loadToken(); err != nil && err != ErrNoSavedToken && err != ErrTokenScopesChanged {
		return nil, err
	} else if ta.lastGoodToken.Valid() {
		// we have a valid token that's not timed out
		ta.logger.Println("Loaded token is valid and has not expired")
		return ta, nil
	} else if newToken, err := ta.TokenSource(ctx).Token(); err != nil {
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
	return ta.TokenSource(ctx).Token()
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

	var tokenErr error
	cleanup := func(w http.ResponseWriter, err error) {
		tokenErr = err
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("Error: %v", err)))
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Access has been granted, you can now close this browser page."))
		}

		go func() {
			// do this asynchronously so the response can be written
			if err := handleRedirect.Shutdown(ctx); err != nil {
				ta.logger.Println(err)
			}
		}()
	}

	var tok *oauth2.Token
	handleRedirect.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ta.logger.Println("Received auth callback")

		if r.URL.Query().Get("error") != "" {
			cleanup(w, fmt.Errorf("%s", r.URL.Query().Get("error_description")))
			return
		}

		if stateCheck := r.URL.Query().Get("state"); stateCheck != state {
			cleanup(w, fmt.Errorf("state check mismatch (expected %s but got %s)", state, stateCheck))
			return
		}

		authCode := r.URL.Query().Get("code")
		if authCode == "" {
			cleanup(w, fmt.Errorf("missing authorization code"))
			return
		}
		oauth2Token, err := ta.authConfig.Exchange(ctx, authCode, oauth2.SetAuthURLParam("code_verifier", codeVerifier.String()))
		if err != nil {
			cleanup(w, err)
			return
		}

		if oauth2Token.RefreshToken == "" {
			log.Println("Warning: auth response contains no refresh toke")
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			cleanup(w, err)
			return
		}

		// Parse and verify ID Token payload.
		_, err = ta.tokenVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			cleanup(w, err)
			return
		}

		ta.logger.Println("Received valid token")
		tok = oauth2Token
		cleanup(w, nil)

	})

	ta.logger.Printf("Waiting for redirect to %s\n", ta.authConfig.RedirectURL)
	if err := handleRedirect.ListenAndServe(); err != http.ErrServerClosed {
		return nil, err
	}

	if tokenErr != nil {
		return nil, tokenErr
	}
	return tok, nil
}

func (ta *TerminalAuth) TokenSource(ctx context.Context) oauth2.TokenSource {
	return &NotifyRefreshTokenSource{
		new: ta.authConfig.TokenSource(ctx, ta.lastGoodToken),
		t:   ta.lastGoodToken,
		f:   ta.setToken,
	}
}

// Client returns an http client which uses the token and will automatically refresh
// it when the token expires
func (ta *TerminalAuth) Client(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, ta.TokenSource(ctx))
}

var ErrNoSavedToken = errors.New("no saved token")
var ErrNoLoadedToken = errors.New("no loaded token")
var ErrTokenScopesChanged = errors.New("requested scopes have changed")

func (ta *TerminalAuth) keychainName() string {
	return fmt.Sprintf("%s-%s", ta.keychainPrefix, ta.Issuer)
}

func (ta *TerminalAuth) scopeHash() string {
	h := sha1.New()
	for _, s := range ta.scopes {
		h.Write([]byte(s))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (ta *TerminalAuth) loadToken() error {
	// check current scopes

	tok := oauth2.Token{}
	if data, err := keyring.Get(ta.keychainName(), "scopes"); err != nil {
		if err == keyring.ErrNotFound {
			return ErrNoSavedToken
		} else {
			return err
		}
	} else if data != ta.scopeHash() {
		return ErrTokenScopesChanged
	} else if data, err := keyring.Get(ta.keychainName(), "token"); err != nil {
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
	if err := keyring.Set(ta.keychainName(), "scopes", ta.scopeHash()); err != nil {
		return err
	} else if err := json.NewEncoder(&b).Encode(tok); err != nil {
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
