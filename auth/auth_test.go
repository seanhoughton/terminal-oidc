package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

func TestNoConfigShouldError(t *testing.T) {
	ctx := context.Background()
	_, err := NewTerminalAuth(ctx, "test", WithNoPersistence())
	if err == nil {
		t.Fatal("No config should produce an error")
	}
	if err != ErrNoOIDCConfig {
		t.Errorf("Incorrect error returned: %v", err)
	}
}

const refreshToken = "myrefreshtoken"
const clientName = "myclient"

var signingKey = []byte("mysigningkey")

type providerJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Algorithms  []string `json:"id_token_signing_alg_values_supported"`
}

type tokenJSON struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func mockAuthServer(t *testing.T) *httptest.Server {
	var svr *httptest.Server
	svr = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			config := providerJSON{
				Issuer:   svr.URL,
				AuthURL:  svr.URL + "/authorize",
				TokenURL: svr.URL + "/token",
			}
			if err := json.NewEncoder(w).Encode(&config); err != nil {
				t.Error(err)
			}
		case "/authorize":
			// ??
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			} else if r.Form.Get("refresh_token") != refreshToken {
				t.Errorf("incorrect refresh token: got %s, expected %s", r.Form.Get("refresh_token"), refreshToken)
			} else if r.Form.Get("grant_type") != "refresh_token" {
				t.Errorf("incorrect grant type: got %s, expected %s", r.Form.Get("grant_type"), "refresh_token")
			}
			// don't need to check client id, etc. - we're not testing the oauth2 module

			w.Header().Set("content-type", "application/json")
			w.WriteHeader(http.StatusOK)

			claims := &jwt.StandardClaims{
				ExpiresAt: 15000,
				Issuer:    svr.URL,
				Audience:  clientName,
			}
			idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			if idTokenEncoded, err := idToken.SignedString(signingKey); err != nil {
				t.Error(err)
			} else if err := json.NewEncoder(w).Encode(&tokenJSON{
				AccessToken:  "the_opaque_access_token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				RefreshToken: refreshToken,
				IDToken:      idTokenEncoded,
			}); err != nil {
				t.Error(err)
			}
		}
	}))
	return svr
}

func TestRefreshExpiredToken(t *testing.T) {
	ctx := context.Background()
	svr := mockAuthServer(t)
	defer svr.Close()

	// stash an existing token into the storage
	//
	keyring.MockInit() // manually set this so we always use the in-memory store
	token := &oauth2.Token{
		Expiry:       time.Now(),
		AccessToken:  "the_opaque_access_token",
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
	}
	claims := &jwt.StandardClaims{
		ExpiresAt: 0,
		Issuer:    svr.URL,
		Audience:  clientName,
	}
	idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	if idTokenEncoded, err := idToken.SignedString(signingKey); err != nil {
		t.Error(err)
	} else {
		token = token.WithExtra(map[string]interface{}{"id_token": idTokenEncoded})
	}
	if err := saveToken(token, "test-test"); err != nil {
		t.Error(err)
	}

	// create a client that loads above token and refreshes it
	opts := []Option{
		WithKeychainPrefix("test"),
		WithIssuerURL(svr.URL),
		WithClientID(clientName),
	}

	if a, err := NewTerminalAuth(ctx, "test", opts...); err != nil {
		t.Error(err)
	} else if tok, err := a.Token(ctx); err != nil {
		t.Error(err)
	} else if !tok.Valid() {
		t.Error("Invalid token")
	} else if tok.AccessToken != "the_opaque_access_token" {
		t.Error("incorrect access token")
	}
}

func TestRestoreUsingOnlyRefreshToken(t *testing.T) {
	ctx := context.Background()
	svr := mockAuthServer(t)
	defer svr.Close()

	opts := []Option{
		WithNoPersistence(),
		WithKeychainPrefix("test"),
		WithIssuerURL(svr.URL),
		WithClientID("myclient"),
		WithRefreshToken("myrefreshtoken"),
	}

	if a, err := NewTerminalAuth(ctx, "test", opts...); err != nil {
		t.Error(err)
	} else if tok, err := a.Token(ctx); err != nil {
		t.Error(err)
	} else if !tok.Valid() {
		t.Error("Invalid token")
	} else if tok.AccessToken != "the_opaque_access_token" {
		t.Error("incorrect access token")
	}
}
