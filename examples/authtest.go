package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/seanhoughton/terminal-oidc/auth"
)

var issuer = os.Getenv("AUTH_ISSUER")
var clientID = os.Getenv("AUTH_CLIENT_ID")
var clientSecret = os.Getenv("AUTH_CLIENT_SECRET")

func main() {

	ctx := context.Background()

	logger := log.New(os.Stdout, "[AUTH] ", log.LstdFlags)

	ta, err := auth.NewTerminalAuth(ctx,
		issuer,
		clientID,
		auth.WithClientSecret(clientSecret),
		auth.WithLogger(logger),
		auth.WithScopes(oidc.ScopeOfflineAccess), // required for Okta refresh tokens
		auth.WithRedirectPort(19978))
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

	if idToken, err := ta.IDToken(ctx); err != nil {
		log.Fatal(err)
	} else if err := idToken.Claims(&claims); err != nil {
		log.Fatal(err)
	} else {
		log.Printf("id issuer: %s\n", idToken.Issuer)
		log.Printf("id info: %v\n", claims)
	}

	client := ta.Client(ctx)

	if resp, err := client.Get("http://localhost:8080/foo/bar"); err != nil {
		log.Fatal(err)
	} else if body, err := ioutil.ReadAll(resp.Body); err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("%s\n", string(body))
	}

	// Use the custom HTTP client when requesting a token.
	//httpClient := &http.Client{Timeout: 2 * time.Second}
	//ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	//client := conf.Client(ctx, tok)

}
