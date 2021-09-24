package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/seanhoughton/terminal-oidc/auth"
	"golang.org/x/oauth2"
)

var issuer = os.Getenv("AUTH_ISSUER")
var clientID = os.Getenv("AUTH_CLIENT_ID")
var clientSecret = os.Getenv("AUTH_CLIENT_SECRET")

func main() {

	var refreshToken = flag.String("r", "", "Pre-configured refresh token")
	var scopes = flag.String("s", "", "Additional scopes to request")
	flag.Parse()

	ctx := context.Background()

	logger := log.New(os.Stdout, "[AUTH] ", log.LstdFlags)

	options := []auth.Option{
		auth.WithClientSecret(clientSecret),
		auth.WithLogger(logger),
		auth.WithScopes(oidc.ScopeOfflineAccess),
		auth.WithRedirectPort(19978),
	}
	if refreshToken != nil {
		options = append(options, auth.WithRefreshToken(*refreshToken))
	}
	if scopes != nil {
		options = append(options, auth.WithScopes(strings.Split(*scopes, ",")...))
	}
	ta, err := auth.NewTerminalAuth(ctx,
		issuer,
		clientID,
		options...)
	if err != nil {
		log.Fatal(err)
	}

	if !ta.Valid() {
		if err := ta.Login(ctx); err != nil {
			log.Fatalf("Failed to log in: %v", err)
		}
	}

	// Extract custom claims
	var claims struct {
		Name          string `json:"name"`
		PreferredName string `json:"preferred_username"`
		Email         string `json:"email"`
		Verified      bool   `json:"email_verified"`
	}

	if token, err := ta.Token(ctx); err != nil {
		log.Fatal(err)
	} else if idToken, err := ta.IDToken(ctx); err != nil {
		log.Fatal(err)
	} else if err := idToken.Claims(&claims); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("access:    %s\n", token.AccessToken)
		log.Printf("refresh:   %s\n", token.RefreshToken)
		log.Printf("id token:  %s\n", token.Extra("id_token"))
		log.Printf("id issuer: %s\n", idToken.Issuer)
		log.Printf("id info:   %v\n", claims)

		//introspect(token)

		if err := localhost(ctx, ta.TokenSource(ctx)); err != nil {
			log.Fatal(err)
		}
	}
}

func localhost(ctx context.Context, tokens oauth2.TokenSource) error {
	if req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/test", nil); err != nil {
		return err
	} else if token, err := tokens.Token(); err != nil {
		return err
	} else {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Extra("id_token")))
		reqDump, _ := httputil.DumpRequest(req, false)
		fmt.Println(string(reqDump))
		if resp, err := http.DefaultClient.Do(req); err != nil {
			return err
		} else if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Error: %s", resp.Status)
		} else if data, err := ioutil.ReadAll(resp.Body); err != nil {
			return err
		} else {
			fmt.Printf("\n%s\n", string(data))
			return nil
		}
	}
}

func introspect(token *oauth2.Token) {
	// now test the access token using introspect endpoint
	//client := ta.Client(ctx)
	args := url.Values{
		"token_type_hint": {"access_token"},
		"token":           {token.AccessToken},
		//"client_id":       {clientID},
	}
	if resp, err := http.DefaultClient.Post(fmt.Sprintf("%s/v1/introspect?client_id=%s", issuer, clientID), "application/x-www-form-urlencoded", strings.NewReader(args.Encode())); err != nil {
		log.Fatal(err)
	} else if body, err := ioutil.ReadAll(resp.Body); err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("%s\n", string(body))
	}
}
