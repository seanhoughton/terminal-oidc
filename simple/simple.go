package simple

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

type authType string

const (
	authorizationHeader = "Authorization"

	// known header types
	RundeckHeader = "X-Rundeck-Auth-Token"
	VaultHeader   = "X-Vault-Token"
)

type authedTransport struct {
	header string
	value  string
}

type Option func(t *authedTransport)

func NewAuthedClient(options ...Option) *http.Client {
	t := &authedTransport{
		header: authorizationHeader,
		value:  "",
	}
	for _, opt := range options {
		opt(t)
	}
	return &http.Client{Transport: t}
}

// WithHeader sets the header key to use
// note: not needed if using one of the "all-required settings" options
func WithHeader(header string) Option {
	return func(t *authedTransport) {
		t.header = header
	}
}

// WithValue sets the entire value of the header
// note: not needed if using one of the "all-required settings" options
func WithValue(token string) Option {
	return func(t *authedTransport) {
		t.value = token
	}
}

// WithBasicAuth configures all required settings for basic authentication
func WithBearerToken(token string) Option {
	return func(t *authedTransport) {
		t.header = authorizationHeader
		t.value = fmt.Sprintf("Bearer %s", token)
	}
}

// WithBasicAuth configures all required settings for basic authentication
func WithBasicAuth(username string, password string) Option {
	return func(t *authedTransport) {
		t.header = authorizationHeader
		t.value = fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password))))
	}
}

// WithVaultAuth configures all required settings for basic authentication
func WithCustomToken(header string, token string) Option {
	return func(t *authedTransport) {
		t.header = header
		t.value = token
	}
}

func (t authedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(t.header, t.value)
	return http.DefaultTransport.RoundTrip(req)
}
