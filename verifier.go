package verifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"

	"github.com/MicahParks/jwkset"
	"github.com/cristalhq/jwt/v5"
)

var (
	// ErrJWKSetVerifier is returned when a verifier error occurs.
	ErrJWKSetVerifier = errors.New("failed to create JWKSetVerifier from JWK Set")
)

// JWKSetVerifier is meant to create a jwt.Verifier for github.com/cristalhq/jwt/v5. It uses
// github.com/MicahParks/jwkset as a JWK Set storage.
type JWKSetVerifier interface {
	Parse(raw []byte) (*jwt.Token, error)
	Storage() jwkset.Storage
	Verifier(raw []byte) (jwt.Verifier, error)
}

// Options are used to create a new JWKSetVerifier.
type Options struct {
	Ctx          context.Context
	Storage      jwkset.Storage
	UseWhitelist []jwkset.USE
}

type jwksetVerifier struct {
	alg          jwt.Algorithm
	ctx          context.Context
	storage      jwkset.Storage
	useWhitelist []jwkset.USE
	mux          sync.Mutex
}

// New creates a new JWKSetVerifier.
func New(options Options) (JWKSetVerifier, error) {
	ctx := options.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if options.Storage == nil {
		return nil, fmt.Errorf("%w: no JWK Set storage given in options", ErrJWKSetVerifier)
	}
	v := &jwksetVerifier{
		ctx:          ctx,
		storage:      options.Storage,
		useWhitelist: options.UseWhitelist,
	}
	return v, nil
}

// NewDefault creates a new JWKSetVerifier with a default JWK Set storage and options.
//
// This will launch "refresh goroutines" to automatically refresh the remote HTTP resources.
func NewDefault(urls []string) (JWKSetVerifier, error) {
	client, err := jwkset.NewDefaultHTTPClient(urls)
	if err != nil {
		return nil, err
	}
	options := Options{
		Storage: client,
	}
	return New(options)
}

func (v *jwksetVerifier) Verifier(raw []byte) (jwt.Verifier, error) {
	token, err := jwt.ParseNoVerify(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: could not parse JWT", errors.Join(err, ErrJWKSetVerifier))
	}

	kid := token.Header().KeyID
	if kid == "" {
		return nil, fmt.Errorf("%w: could not find kid in JWT header", ErrJWKSetVerifier)
	}
	alg := token.Header().Algorithm
	if alg == "" {
		return nil, fmt.Errorf("%w: could not find alg in JWT header", ErrJWKSetVerifier)
	}

	jwk, err := v.storage.KeyRead(v.ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: could not read JWK from storage", errors.Join(err, ErrJWKSetVerifier))
	}

	if a := jwk.Marshal().ALG.String(); a != "" && a != alg.String() {
		return nil, fmt.Errorf(`%w: JWK "alg" parameter value %q does not match token "alg" parameter value %q`, ErrJWKSetVerifier, a, alg)
	}
	if len(v.useWhitelist) > 0 {
		found := false
		for _, u := range v.useWhitelist {
			if jwk.Marshal().USE == u {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf(`%w: JWK "use" parameter value %q is not in whitelist`, ErrJWKSetVerifier, jwk.Marshal().USE)
		}
	}

	type publicKeyer interface {
		Public() crypto.PublicKey
	}

	key := jwk.Key()
	pk, ok := key.(publicKeyer)
	if ok {
		key = pk.Public()
	}

	var ver jwt.Verifier
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ver, err = jwt.NewVerifierES(alg, k)
		if err != nil {
			return nil, fmt.Errorf("%w: could not create ECDSA JWKSetVerifier", errors.Join(err, ErrJWKSetVerifier))
		}
	case ed25519.PublicKey:
		ver, err = jwt.NewVerifierEdDSA(k)
		if err != nil {
			return nil, fmt.Errorf("%w: could not create Ed25519 JWKSetVerifier", errors.Join(err, ErrJWKSetVerifier))
		}
	case []byte:
		ver, err = jwt.NewVerifierHS(alg, k)
		if err != nil {
			return nil, fmt.Errorf("%w: could not create HMAC JWKSetVerifier", errors.Join(err, ErrJWKSetVerifier))
		}
	case *rsa.PublicKey:
		switch jwkset.ALG(alg) {
		case jwkset.AlgPS256, jwkset.AlgPS384, jwkset.AlgPS512:
			ver, err = jwt.NewVerifierPS(alg, k)
			if err != nil {
				return nil, fmt.Errorf("%w: could not create RSA PSS JWKSetVerifier", errors.Join(err, ErrJWKSetVerifier))
			}
		default:
			ver, err = jwt.NewVerifierRS(alg, k)
			if err != nil {
				return nil, fmt.Errorf("%w: could not create RSA JWKSetVerifier", errors.Join(err, ErrJWKSetVerifier))
			}
		}
	default:
		return nil, fmt.Errorf("%w: unsupported key type %T", ErrJWKSetVerifier, key)
	}

	return ver, nil
}
func (v *jwksetVerifier) Parse(raw []byte) (*jwt.Token, error) {
	ver, err := v.Verifier(raw)
	if err != nil {
		return nil, err
	}
	return jwt.Parse(raw, ver)
}
func (v *jwksetVerifier) Storage() jwkset.Storage {
	return v.storage
}
