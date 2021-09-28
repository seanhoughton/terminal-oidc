package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

// Transport is an http.RoundTripper that makes OAuth 2.0 HTTP requests,
// wrapping a base RoundTripper and adding an Authorization header
// with a token from the supplied Sources.
//
// Note: this differes from the Oauth2 Transport in that it sends an ID token
// rather than an access token
//
// Transport is a low-level mechanism. Most code will use the
// higher-level Config.Client method instead.
type Transport struct {
	// Source supplies the token to add to outgoing requests'
	// Authorization headers.
	Source oauth2.TokenSource

	// Base is the base RoundTripper used to make HTTP requests.
	// If nil, http.DefaultTransport is used.
	Base http.RoundTripper
}

// RoundTrip authorizes and authenticates the request with an
// access token from Transport's Source.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				req.Body.Close()
			}
		}()
	}

	if t.Source == nil {
		return nil, errors.New("oauth2: Transport's Source is nil")
	}
	token, err := t.Source.Token()
	if err != nil {
		return nil, err
	}

	req2 := cloneRequest(req) // per RoundTripper contract

	// Use the id_token as the Bearer token
	if idToken := token.Extra("id_token"); idToken == nil {
		return nil, fmt.Errorf("no id_token in token")
	} else if idTokenStr, ok := idToken.(string); !ok {
		return nil, fmt.Errorf("invalid id_token value")
	} else {
		req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", idTokenStr))
	}

	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true
	return t.base().RoundTrip(req2)
}

var cancelOnce sync.Once

// CancelRequest does nothing. It used to be a legacy cancellation mechanism
// but now only it only logs on first use to warn that it's deprecated.
//
// Deprecated: use contexts for cancellation instead.
func (t *Transport) CancelRequest(req *http.Request) {
	cancelOnce.Do(func() {
		log.Printf("deprecated: golang.org/x/oauth2: Transport.CancelRequest no longer does anything; use contexts")
	})
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}

func newIDClient(ctx context.Context, src oauth2.TokenSource) *http.Client {
	return &http.Client{
		Transport: &Transport{
			Base:   http.DefaultTransport,
			Source: oauth2.ReuseTokenSource(nil, src),
		},
	}
}
