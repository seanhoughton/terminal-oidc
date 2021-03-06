package auth

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	pkce "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/pkg/browser"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

const (
	defaultRedirect = "http://localhost:8080/auth/callback"

	// key names for saving in the keyring
	oidcIssuerURLKey    = "oidc-issuer-url"
	oidcClientIDKey     = "oidc-client-id"
	oidcClientSecretKey = "oidc-client-secret"
	scopesKey           = "scopes"
	tokenKey            = "token"
	idTokenKey          = "id-token"
)

var (
	ErrNoSavedToken       = errors.New("no saved token")
	ErrNoLoadedToken      = errors.New("no loaded token")
	ErrTokenScopesChanged = errors.New("requested scopes have changed")
	ErrNoOIDCConfig       = errors.New("no oidc configuration was provided or cached")
	ErrNoIDToken          = errors.New("no id token")
	ErrRefreshFailed      = errors.New("failed to refresh the token")

	keyringKeys = []string{oidcIssuerURLKey, oidcClientIDKey, oidcClientSecretKey, scopesKey, tokenKey, idTokenKey}
)

type promptFunc func(authURL string) error

type TerminalAuth struct {
	clientID          string
	issuerURL         string
	serviceIdentifier string
	tokenVerifier     *oidc.IDTokenVerifier
	authConfig        *oauth2.Config
	lastGoodToken     *oauth2.Token
	provider          *oidc.Provider
	port              uint16
	redirectURL       string
	logger            logrus.StdLogger
	clientSecret      string
	prompt            promptFunc
	keychainPrefix    string
	scopes            []string
	successBody       string
	store             Storage
}

type Option func(*TerminalAuth) error

// WithClientID sets the OIDC client_id
// If this is not provided the currently saved
// client ID from a previous login will be used
func WithClientID(clientID string) Option {
	return func(ta *TerminalAuth) error {
		ta.clientID = clientID
		return ta.store.Set(ta.keychainName(), oidcClientIDKey, clientID)
	}
}

// WithIssuer sets the OIDC issuer base URL
// If this is not provided the currently saved
// issuer from a previous login will be used
func WithIssuerURL(issuerURL string) Option {
	return func(ta *TerminalAuth) error {
		ta.issuerURL = issuerURL
		return ta.store.Set(ta.keychainName(), oidcIssuerURLKey, issuerURL)
	}
}

// WithLogger installs a custom logger instance
func WithLogger(logger logrus.StdLogger) Option {
	return func(ta *TerminalAuth) error {
		ta.logger = logger
		return nil
	}
}

// WithRedirect customizes the local OAuth redirect port (default: 11123)
func WithRedirect(redirect string) Option {
	return func(ta *TerminalAuth) error {
		if parsed, err := url.Parse(redirect); err != nil {
			return err
		} else if port, err := strconv.ParseUint(parsed.Port(), 10, 16); err != nil {
			return err
		} else {
			ta.port = uint16(port)
			ta.redirectURL = redirect
		}
		return nil
	}
}

// WithClientSecret adds a client secret to the authorization request
// Note that this is required by some providers (e.g. Google) but not all.
func WithClientSecret(secret string) Option {
	return func(ta *TerminalAuth) error {
		ta.clientSecret = secret
		return ta.store.Set(ta.keychainName(), oidcClientSecretKey, secret)
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

// WithCustomPrompt calls a custom function to handle the prompt
func WithCustomPrompt(prompt func(authURL string) error) Option {
	return func(ta *TerminalAuth) error {
		ta.prompt = prompt
		return nil
	}
}

// WithAutoFollowRedirectForTesting will follow the redirect for automated testing purposes only
func WithAutoFollowRedirectForTesting() Option {
	return func(ta *TerminalAuth) error {
		ta.prompt = func(authURL string) error {
			if resp, err := http.Get(authURL); err != nil {
				return err
			} else if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("authorization endpoint responded with %s", resp.Status)
			} else if resp.Body == nil {
				return nil
			} else if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				return err
			} else {
				return resp.Body.Close()
			}
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
		return ta.store.Set(ta.keychainName(), scopesKey, ta.scopeHash())
	}
}

// WithRefreshToken will install an initial refresh token to be used
// and should be used in a provisioned setting where refresh tokens
// are known.
// NOTE: this assumes the scopes have not changed and does
// check the saved scope hash for invalidation. Use at your own risk.
func WithRefreshToken(refreshToken string) Option {
	return func(ta *TerminalAuth) error {
		var token *oauth2.Token
		if loadedToken, err := loadToken(ta.store, ta.keychainName()); err != nil && err != ErrNoSavedToken {
			return err
		} else if err == ErrNoSavedToken {
			// no previously saved token, use a fresh one with an empty id_token
			token = (&oauth2.Token{}).WithExtra(map[string]interface{}{"id_token": ""})
		} else {
			// use the loaded token so any additional claims are not cleared
			token = loadedToken
		}
		token.RefreshToken = refreshToken
		return saveToken(ta.store, token, ta.keychainName())
	}
}

// WithSuccessBody sets the content of the web response to users when
// a successful authentication flow has completed.
func WithSuccessBody(body string) Option {
	return func(ta *TerminalAuth) error {
		ta.successBody = body
		return nil
	}
}

// NewTerminalAuth returns an initialized TerminalAuth instance
// serviceIdentifier is an key for caching authentication values
func NewTerminalAuth(ctx context.Context, serviceIdentifier string, store Storage, options ...Option) (*TerminalAuth, error) {
	// default configuration
	ta := &TerminalAuth{
		serviceIdentifier: serviceIdentifier,
		store:             store,
	}
	WithLogger(log.Default())(ta)
	WithRedirect(defaultRedirect)(ta)
	WithStdoutPrompt()(ta)
	WithKeychainPrefix("terminaloidc")(ta)
	WithSuccessBody(defaultSuccessBody)(ta)

	// options
	for _, opt := range options {
		if err := opt(ta); err != nil {
			return nil, err
		}
	}

	// make sure we always have at least one scope
	if len(ta.scopes) == 0 {
		WithScopes(oidc.ScopeOpenID)(ta)
	}

	// load any unset values from the cache
	if err := ta.loadOIDC(); err != nil {
		return nil, fmt.Errorf("failed to load cached oidc settings: %v", err)
	}

	if ta.issuerURL == "" {
		return nil, ErrNoOIDCConfig
	}

	if provider, err := oidc.NewProvider(ctx, ta.issuerURL); err != nil {
		return nil, err
	} else {
		ta.provider = provider
	}

	ta.logger.Println("Using authorization endpoint ", ta.provider.Endpoint())

	oidcConfig := &oidc.Config{
		ClientID: ta.clientID,
	}

	ta.authConfig = &oauth2.Config{
		ClientID:     ta.clientID,
		ClientSecret: ta.clientSecret,
		Endpoint:     ta.provider.Endpoint(),
		Scopes:       ta.scopes,
		RedirectURL:  ta.redirectURL,
	}

	ta.tokenVerifier = ta.provider.Verifier(oidcConfig)

	// restore the saved token if it exists
	if err := ta.load(); err != nil && err != ErrNoSavedToken && err != ErrTokenScopesChanged {
		return nil, err
	}

	return ta, nil
}

func (ta *TerminalAuth) Token(ctx context.Context) (*oauth2.Token, error) {
	return ta.TokenSource(ctx).Token()
}

// HasValidToken returns "true" if a non-expired token has been loaded
func (ta *TerminalAuth) HasValidToken(ctx context.Context) bool {
	if ta.lastGoodToken == nil {
		return false
	} else if ta.lastGoodToken.Valid() {
		return true
	} else if _, err := ta.TokenSource(ctx).Token(); err != nil {
		return false
	} else {
		return true
	}
}

// Login will present a URL to the terminal for the user to click and then follow the oauth2 flow
// to acquire token data
func (ta *TerminalAuth) Login(ctx context.Context) error {
	ta.lastGoodToken = nil
	if tok, err := ta.login(ctx); err != nil {
		return err
	} else {
		return ta.save(tok)
	}
}

// IDToken returns the OIDC token
func (ta *TerminalAuth) IDToken(ctx context.Context) (*oidc.IDToken, error) {
	if tok, err := ta.Token(ctx); err != nil {
		return nil, err
	} else if rawIDToken, ok := tok.Extra("id_token").(string); !ok {
		return nil, ErrNoIDToken
	} else if idToken, err := ta.tokenVerifier.Verify(ctx, rawIDToken); err != nil {
		return nil, err
	} else {
		return idToken, nil
	}
}

const defaultSuccessBody = `
<html>

<head>
    <title>OAuth Request Successful</title>
</head>

<body>
    <p style='font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol"; font-size: 22px; color: #333; width: 400px; margin: 0 auto; text-align: center; line-height: 1.7; padding: 20px;'>
        <strong style='font-size: 28px; color: #000;'>Success</strong><br />This browser window can now be closed
	</p>
</body>

</html>
`

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
			_, _ = w.Write([]byte(fmt.Sprintf("Error: %v", err)))
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(ta.successBody))
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
			log.Println("Warning: auth response contains no refresh token")
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			cleanup(w, ErrNoIDToken)
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
	return NotifyRefreshTokenSource(ta.lastGoodToken, ta.authConfig.TokenSource(ctx, ta.lastGoodToken), ta.save)
}

// AccessClient returns an http client which uses the access token and will automatically refresh
// it when the token expires
func (ta *TerminalAuth) AccessClient(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, ta.TokenSource(ctx))
}

// IDClient returns an http client which uses the ID token and will automatically refresh
// it when the token expires
func (ta *TerminalAuth) IDClient(ctx context.Context) *http.Client {
	return &http.Client{
		Transport: NewIDTransport(ctx, ta.TokenSource(ctx), http.DefaultTransport),
	}
}

func (ta *TerminalAuth) keychainName() string {
	return fmt.Sprintf("%s-%s", ta.keychainPrefix, ta.serviceIdentifier)
}

func (ta *TerminalAuth) UserInfo(ctx context.Context) (*oidc.UserInfo, error) {
	return ta.provider.UserInfo(ctx, ta.TokenSource(ctx))
}

func (ta *TerminalAuth) scopeHash() string {
	h := sha1.New()
	for _, s := range ta.scopes {
		h.Write([]byte(s))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// loadOIDC loads stored OIDC settings if they aren't currently set
func (ta *TerminalAuth) loadOIDC() error {
	if ta.issuerURL == "" {
		if data, err := ta.store.Get(ta.keychainName(), oidcIssuerURLKey); err != nil && err != ErrSettingNotFound {
			return fmt.Errorf("could not load %s: %v", oidcIssuerURLKey, err)
		} else if err == nil {
			ta.logger.Printf("Loading cached %s: %s\n", oidcIssuerURLKey, data)
			ta.issuerURL = data
		}
	}

	if ta.clientID == "" {
		if data, err := ta.store.Get(ta.keychainName(), oidcClientIDKey); err != nil && err != ErrSettingNotFound {
			return fmt.Errorf("could not load %s: %v", oidcClientIDKey, err)
		} else if err == nil {
			ta.logger.Printf("Loading cached %s: %s\n", oidcClientIDKey, data)
			ta.clientID = data
		}
	}

	if ta.clientSecret == "" {
		if data, err := ta.store.Get(ta.keychainName(), oidcClientSecretKey); err != nil && err != ErrSettingNotFound {
			return fmt.Errorf("could not load %s: %v", oidcClientSecretKey, err)
		} else if err == nil {
			ta.logger.Printf("Loading cached %s: <redacted>\n", oidcClientSecretKey)
			ta.clientSecret = data
		}
	}
	return nil
}

// loadToken loads just the token data from the keychain
func loadToken(persistence Storage, keychainName string) (*oauth2.Token, error) {
	token := oauth2.Token{}
	if tokenData, err := persistence.Get(keychainName, tokenKey); err != nil {
		if err == ErrSettingNotFound {
			return nil, ErrNoSavedToken
		} else {
			return nil, err
		}
	} else if err := json.NewDecoder(strings.NewReader(tokenData)).Decode(&token); err != nil {
		return nil, err
	} else if idToken, err := persistence.Get(keychainName, idTokenKey); err != nil {
		if err == ErrSettingNotFound {
			return nil, ErrNoSavedToken
		} else {
			return nil, err
		}
	} else {
		return token.WithExtra(map[string]interface{}{"id_token": idToken}), nil
	}
}

// saveToken saves the token data to the keychain
func saveToken(persistence Storage, token *oauth2.Token, keychainName string) error {
	b := strings.Builder{}
	if err := json.NewEncoder(&b).Encode(token); err != nil {
		return err
	} else if err := persistence.Set(keychainName, tokenKey, b.String()); err != nil {
		return err
	} else if idToken, ok := token.Extra("id_token").(string); !ok {
		return ErrNoIDToken
	} else if err := persistence.Set(keychainName, idTokenKey, idToken); err != nil {
		return err
	} else {
		return nil
	}
}

// load loads cached token data
func (ta *TerminalAuth) load() error {
	if scopesData, err := ta.store.Get(ta.keychainName(), scopesKey); err != nil {
		if err == ErrSettingNotFound {
			return ErrNoSavedToken
		} else {
			return err
		}
	} else if scopesData != ta.scopeHash() {
		return ErrTokenScopesChanged
	} else if loadedToken, err := loadToken(ta.store, ta.keychainName()); err != nil {
		return err
	} else {
		expiresIn := time.Until(loadedToken.Expiry).Seconds()
		if expiresIn < 0 {
			ta.logger.Printf("Loaded token at %s is expired\n", ta.keychainName())
		} else {
			ta.logger.Printf("Loaded token at %s that expires in %f seconds\n", ta.keychainName(), expiresIn)
		}
		ta.lastGoodToken = loadedToken
		return nil
	}
}

// save caches all configuration options
func (ta *TerminalAuth) save(tok *oauth2.Token) error {
	ta.lastGoodToken = tok
	if err := ta.store.Set(ta.keychainName(), oidcIssuerURLKey, ta.issuerURL); err != nil {
		return err
	} else if err := ta.store.Set(ta.keychainName(), oidcClientIDKey, ta.clientID); err != nil {
		return err
	} else if err := ta.store.Set(ta.keychainName(), oidcClientSecretKey, ta.clientSecret); err != nil {
		return err
	} else if err := ta.store.Set(ta.keychainName(), scopesKey, ta.scopeHash()); err != nil {
		return err
	} else if err := saveToken(ta.store, tok, ta.keychainName()); err != nil {
		return err
	} else {
		ta.logger.Printf("Token updated and saved as %s in [fields: %v]\n", ta.keychainName(), keyringKeys)
		return nil
	}
}

func (ta *TerminalAuth) Logout() error {
	for _, key := range keyringKeys {
		if err := ta.store.Delete(ta.keychainName(), key); err != nil && err != ErrSettingNotFound {
			return fmt.Errorf("Failed to delete keyring key %s: %w", key, err)
		}
	}
	return nil
}
