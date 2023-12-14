[![Go Reference](https://pkg.go.dev/badge/github.com/MicahParks/verifier.svg)](https://pkg.go.dev/github.com/MicahParks/verifier)

# verifier

The purpose of this package is to provide a
[`jwt.Verifier`](https://pkg.go.dev/github.com/cristalhq/jwt/v5#Verifier) for the
[github.com/cristalhq/jwt/v5](https://github.com/cristalhq/jwt) package using a JSON Web Key Set (JWK Set) for parsing
and verifying JSON Web Tokens (JWTs).

It's common for an identity providers, particularly those
using [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
or [OpenID Connect](https://openid.net/developers/how-connect-works/), such
as [Keycloak](https://github.com/MicahParks/verifier/blob/verifier/examples/keycloak/main.go)
or [Amazon Cognito (AWS)](https://github.com/MicahParks/verifier/blob/verifier/examples/aws_cognito/main.go) to expose a
JWK Set via an HTTPS endpoint. This package has the ability to consume that JWK Set and produce a
[`jwt.Verifier`](https://pkg.go.dev/github.com/cristalhq/jwt/v5#Verifier) or parse and verify tokens directly. It is
important that a JWK Set endpoint is using HTTPS to ensure the keys are from the correct trusted source.

This repository only depends on:

* [github.com/cristalhq/jwt/v5](https://github.com/cristalhq/jwt)
* [github.com/MicahParks/jwkset](https://github.com/MicahParks/jwkset)

## Basic usage

For complete examples, please see the `examples` directory.

```go
import "github.com/MicahParks/verifier"
```

### Step 1: Create the `verifier.JWKSetVerifier`

```go
// Create the verifier.JWKSetVerifier.
jwks, err := verifier.NewDefault([]string{server.URL})
if err != nil {
	log.Fatalf("Failed to create a verifier.JWKSetVerifier from the server's URL.\nError: %s", err)
}
```

When using the `verifier.NewDefault` function, the JWK Set will be automatically refreshed using
[`jwkset.NewDefaultHTTPClient`](https://pkg.go.dev/github.com/MicahParks/jwkset#NewHTTPClient).

### Step 2: Use the `verifier.JWKSetVerifier` to parse and verify JWTs

```go
// Parse the JWT.
token, err = jwks.Parse(signed)
if err != nil {
	log.Fatalf("Failed to parse the JWT.\nError: %s", err)
}
```

## Additional features

This project's primary purpose is to provide a [`jwt.Verifier`](https://pkg.go.dev/github.com/cristalhq/jwt/v5#Verifier)
or parse and verify tokens directly using JWK Sets.

Access the [`jwkset.Storage`](https://pkg.go.dev/github.com/MicahParks/jwkset#Storage) from a `verifier.JWKSetVerifier`
via the `.Storage()` method. Using the [github.com/MicahParks/jwkset](https://github.com/MicahParks/jwkset) package
provides the below features, and more:

* An HTTP client that automatically updates one or more remote JWK Set resources.
* X.509 URIs or embedded [certificate chains](https://pkg.go.dev/crypto/x509#Certificate), when a JWK contains them.
* Support for private asymmetric keys.
* Specified key operations and usage.

## Related projects

### [`github.com/MicahParks/jwkset`](https://github.com/MicahParks/jwkset):

A JWK Set implementation. The `verifier` project is a wrapper around this project.

### [`github.com/MicahParks/jcp`](https://github.com/MicahParks/jcp):

A JWK Set client proxy. JCP for short. This project is a standalone service that uses `verifier` under the hood. It
primarily exists for these use cases:

1. The language or shell a program is written in does not have an adequate JWK Set client. Validate JWTs with `curl`?
   Why not?
2. Restrictive networking policies prevent a program from accessing the remote JWK Set directly.
3. Many co-located services need to validate JWTs that were signed by a key that lives in a remote JWK Set.

If you can integrate `verifier` directly into your program, you likely don't need JCP.
