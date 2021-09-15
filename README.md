# Terminal OIDC
### OIDC authentication for command line GO applications

The terminal-oidc module will handle the OAuth2 code authorization flow using PKCE to acquire authorization, refresh, and ID tokens. The reponse will be cached in the local machine's [keyring](github.com/zalando/go-keyring) and refreshed on subsequent runs. Updated refresh tokens are automatically stored.

The default scope settings will request `email` and `profile` scopes.

## Installation 

```
go get github.com/seanhoughton/terminal-oidc
```


## Usage

**important:** production code should handle errors

```go

import auth "github.com/seanhoughton/terminal-oidc"

func main() {
    issuer := "https://dev-123456.oktapreview.com/"
    clientID := "1234abcd"
    ta, _ := auth.NewTerminalAuth(ctx, issuer, clientID, auth.WithStdoutPrompt())
    client, _ := ta.Client(context.TODO())
    resp, _ := client.Get("https://authenticated.com/path")
}
```

## Issuer Notes

| Issuer |                                                                                                             |
| ------ | ----------------------------------------------------------------------------------------------------------- |
| Okta   | Requires the "offline_access" scope (`auth.WithScopes(oidc.ScopeOfflineAccess)`) to receive a refresh token |
| Google | Fails if "offline_access" scope is requested (`auth.WithScopes(oidc.ScopeOfflineAccess)`)                   |
| Google | Requires a client secret (`auth.WithClientSecret("xxxxx")`) even though PKCE is used                        |