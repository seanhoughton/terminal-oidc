package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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
var serviceID = os.Getenv("AUTH_SERVICE_ID")

func main() {

	var refreshToken = flag.String("r", "", "Pre-configured refresh token")
	var scopes = flag.String("s", "", "Additional scopes to request")
	flag.Parse()

	ctx := context.Background()

	logger := log.New(os.Stdout, "[AUTH] ", log.LstdFlags)

	options := []auth.Option{
		auth.WithClientID(clientID),
		auth.WithIssuerURL(issuer),
		auth.WithClientSecret(clientSecret),
		auth.WithLogger(logger),
		auth.WithScopes(oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "groups"),
		//auth.WithRedirect("http://127.0.0.1:19978/login/callback"),
	}
	if *refreshToken != "" {
		options = append(options, auth.WithRefreshToken(*refreshToken))
	}
	if *scopes != "" {
		options = append(options, auth.WithScopes(strings.Split(*scopes, ",")...))
	}

	ta, err := auth.NewTerminalAuth(ctx,
		serviceID,
		auth.NewEphemeralStorage(),
		options...)
	if err != nil {
		logger.Fatal(err)
	}

	if !ta.HasValidToken(ctx) {
		if err := ta.Login(ctx); err != nil {
			logger.Fatalf("Failed to log in: %v", err)
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
		logger.Fatal(err)
	} else if idToken, err := ta.IDToken(ctx); err != nil {
		logger.Fatal(err)
	} else if err := idToken.Claims(&claims); err != nil {
		logger.Fatal(err)
	} else {
		logger.Println("----------------------------------------")
		logger.Printf("access:    %s\n", token.AccessToken)
		logger.Printf("refresh:   %s\n", token.RefreshToken)
		logger.Printf("id token:  %s\n", token.Extra("id_token"))
		logger.Printf("id issuer: %s\n", idToken.Issuer)
		logger.Printf("id info:   %v\n", claims)
		logger.Println("----------------------------------------")

		userInfoClaims := struct {
			Groups []string `json:"groups"`
		}{}
		if userInfo, err := ta.UserInfo(ctx); err != nil {
			logger.Fatal(err)
		} else if err := userInfo.Claims(&userInfoClaims); err != nil {
			logger.Fatal(err)
		} else {
			logger.Printf("%v", userInfoClaims)
		}

		//if err := localhost(ctx, ta.IDClient(ctx), logger); err != nil {
		//	log.Fatal(err)
		//}
	}

	// now create a new auth client and re-use cached values

	/*

		if ta2, err := auth.NewTerminalAuth(ctx,
			serviceIdentifier,
			auth.WithLogger(logger),
			auth.WithScopes(oidc.ScopeOfflineAccess),
		); err != nil {
			logger.Fatal(err)
		} else if err := localhost(ctx, ta2.IDClient(ctx), logger); err != nil {
			logger.Fatal(err)
		}*/
}

func localhost(ctx context.Context, client *http.Client, logger *log.Logger) error {
	if req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/test", nil); err != nil {
		return err
	} else {
		if resp, err := client.Do(req); err != nil {
			return err
		} else if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Error: %s", resp.Status)
		} else if data, err := ioutil.ReadAll(resp.Body); err != nil {
			return err
		} else {
			logger.Printf("------------ ( response ) --------------")
			logger.Printf("\n%s\n", string(data))
			logger.Printf("----------------------------------------")
			return nil
		}
	}
}

func introspect(token *oauth2.Token, logger *log.Logger) {
	// now test the access token using introspect endpoint
	//client := ta.Client(ctx)
	args := url.Values{
		"token_type_hint": {"access_token"},
		"token":           {token.AccessToken},
		//"client_id":       {clientID},
	}
	if resp, err := http.DefaultClient.Post(fmt.Sprintf("%s/v1/introspect?client_id=%s", issuer, clientID), "application/x-www-form-urlencoded", strings.NewReader(args.Encode())); err != nil {
		logger.Fatal(err)
	} else if body, err := ioutil.ReadAll(resp.Body); err != nil {
		logger.Fatal(err)
	} else {
		logger.Printf("%s\n", string(body))
	}
}
