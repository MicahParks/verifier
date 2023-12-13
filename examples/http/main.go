package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/MicahParks/jwkset"
	"github.com/cristalhq/jwt/v5"

	"github.com/MicahParks/verifier"
)

const (
	keyID = "my-key-id"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a cryptographic key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate given key.\nError: %s", err)
	}

	// Turn the key into a JWK.
	marshalOptions := jwkset.JWKMarshalOptions{
		Private: true,
	}
	metadata := jwkset.JWKMetadataOptions{
		KID: keyID,
	}
	options := jwkset.JWKOptions{
		Marshal:  marshalOptions,
		Metadata: metadata,
	}
	jwk, err := jwkset.NewJWKFromKey(pub, options)
	if err != nil {
		log.Fatalf("Failed to create a JWK from the given key.\nError: %s", err)
	}

	// Write the JWK to the server's storage.
	serverStore := jwkset.NewMemoryStorage()
	err = serverStore.KeyWrite(ctx, jwk)
	if err != nil {
		log.Fatalf("Failed to write the JWK to the server's storage.\nError: %s", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawJWKS, err := serverStore.JSONPublic(ctx)
		if err != nil {
			log.Fatalf("Failed to get the server's JWKS.\nError: %s", err)
		}
		_, _ = w.Write(rawJWKS)
	}))

	// Sign a JWT with this key.
	signer, err := jwt.NewSignerEdDSA(priv)
	if err != nil {
		log.Fatalf("Failed to create a signer.\nError: %s", err)
	}
	token, err := jwt.NewBuilder(signer, jwt.WithKeyID(keyID)).Build(jwt.RegisteredClaims{})
	if err != nil {
		log.Fatalf("Failed to build a JWT.\nError: %s", err)
	}
	signed := token.Bytes()

	// Create the verifier.JWKSetVerifier.
	jwks, err := verifier.NewDefault([]string{server.URL})
	if err != nil {
		log.Fatalf("Failed to create a verifier.JWKSetVerifier from the server's URL.\nError: %s", err)
	}

	// Parse the JWT.
	token, err = jwks.Parse(signed)
	if err != nil {
		log.Fatalf("Failed to parse the JWT.\nError: %s", err)
	}

	_ = token
	log.Println("The JWT is valid.")
}
