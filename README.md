# oidc

[![Go Reference](https://pkg.go.dev/badge/github.com/lstoll/oidc.svg)](https://pkg.go.dev/github.com/lstoll/oidc)

Module that provides extensions for OIDC usage with [x/oauth2](https://pkg.go.dev/golang.org/x/oauth2), as well as some other extended oauth2 usage.

The root package provides functions around interacting with an OIDC provider. The provider can be discovered from the issuer URL, or manually configured. The provider instance can be used to verify the issued ID tokens, and access tokens if they comply with the [JWT Profile](https://datatracker.ietf.org/doc/html/rfc9068).

Some other packages are provided:
* [**clitoken**](https://pkg.go.dev/github.com/lstoll/oidc/clitoken) Implements the three-legged OIDC flow for local/CLI applications, with a dynamic server on the loopback to handle the callback
* [**middleware**](https://pkg.go.dev/github.com/lstoll/oidc/middleware) Provides a HTTP middleware to secure a path against an OIDC issuer
* [**tokencache**](https://pkg.go.dev/github.com/lstoll/oidc/tokencache) Provides a mechanism for caching and refreshing tokens.

Examples:
* **cmd/oidc-example-rp** An example of a webapp that authenticates via OIDC
* **cmd/oidcli** A CLI tool that uses the [clitoken](https://pkg.go.dev/github.com/lstoll/oidc/clitoken) package to retrieve ID/Access tokens, and return them or information about them.
