# Terminal OIDC
### OIDC authentication for command line GO applications

The terminal-oidc module will handle the OAuth2 code authorization flow using PKCE to acquire authorization, refresh, and ID tokens. The reponse will be cached in the local machine's [keyring](github.com/zalando/go-keyring) and refreshed on subsequent runs. Updated refresh tokens are automatically stored.

The default scope settings will request `email` and `profile` scopes.

## Installation 

```sh
> go get github.com/seanhoughton/terminal-oidc
```


## Usage

Clients that need to send access tokens should use the provided client which will automatically add the `Authorization: Bearer xxx` header to all request and refresh the token when needed.

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

Clients that need to send ID tokens should use the token source and 


```go

import auth "github.com/seanhoughton/terminal-oidc"

func main() {
    issuer := "https://dev-123456.oktapreview.com/"
    clientID := "1234abcd"
    ta, _ := auth.NewTerminalAuth(ctx, issuer, clientID, auth.WithStdoutPrompt())
    tokens := ta.TokenSource(context.TODO())
    req, _ := http.NewRequest(http.MethodGet, "https://authenticated.com/path", nil)
    token, _ := tokens.Token()
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Extra("id_token")))
    resp, _ := http.DefaultClient.Do(req)
}
```

### Cached values and integration patterns

The module will store both the configuration and token locally for re-use. Applications integrating the terminal-auth module should break up integrations into a login step and a cached use step.

The login step should provide all required configuration options. This login step will cache the provided values for future use. For example:

```golang
scopes = []string{"myscope"}

// the initial use must provide OIDC configuration

ta1, _ := auth.NewTerminalAuth(ctx, auth.WithIssuerURL("https://xxxx"), auth.WithClientID("xxxxx"), auth.WithScopes(scopes))

// subsequent usage can omit OIDC configuration and used cached values

ta2, _ := auth.NewTerminalAuth(ctx, auth.WithScopes(scopes)))
```


### Pre-configured refresh tokens

Clients that don't want to use the built-in flow handling a pre-configured refresh token can be provided using the `WithRefreshToken("xxx")` option. This may be convenient for situations where the refresh
token is used by multiple clients and distributed with a provisioning system like Puppet or a shared secrets tool like Vault.

The [step](https://github.com/smallstep/cli) tool can be used to easily get a refresh token for distribution.

```
step oauth --client-id=xxxxxx --client-secret="" --provider https://dev-xxxxxx.oktapreview.com/.well-known/openid-configuration --listen :19978 --oidc --scope "openid email offline_access groups" | jq --raw-output ".id_token"
```


## Issuer Notes

| Issuer |                                                                                                             |
| ------ | ----------------------------------------------------------------------------------------------------------- |
| Okta   | Requires the "offline_access" scope (`auth.WithScopes(oidc.ScopeOfflineAccess)`) to receive a refresh token |
| Google | Fails if "offline_access" scope is requested (`auth.WithScopes(oidc.ScopeOfflineAccess)`)                   |
| Google | Requires a client secret (`auth.WithClientSecret("xxxxx")`) even though PKCE is used                        |