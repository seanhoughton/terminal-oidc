package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/seanhoughton/terminal-oidc/auth"
)

func main() {
	const oktaIssuer = "https://dev-433811.oktapreview.com"
	const oktaClientID = "0oa11fbh947AaFdm20h8"

	ctx := context.Background()

	logger := log.New(os.Stdout, "[AUTH] ", log.LstdFlags)

	ta, err := auth.NewTerminalAuth(ctx, oktaIssuer, oktaClientID, auth.WithLogger(logger))
	if err != nil {
		log.Fatal(err)
	}

	if !ta.Valid() {
		if err := ta.Login(ctx); err != nil {
			log.Fatalf("Failed to log in: %v", err)
		}
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
