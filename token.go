package twilio

import (
	"fmt"
	"log"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

const (
	keyIdentity      = "identity"
	keyGrants        = "grants"
	keyContentType   = "cty"
	tokenContentType = "twilio-fpa;v=1"

	// the default ttl, one hour
	defaultTTL = time.Hour
)

var (
	// supported jwt signing algorithms: HS256, HS384, HS512
	supportedSigningMethods = map[string]interface{}{
		crypto.SigningMethodHS256.Alg(): true,
		crypto.SigningMethodHS384.Alg(): true,
		crypto.SigningMethodHS512.Alg(): true,
	}
)

// AccessToken is a builder struct to setup and generate JSON Web Token for
// accessing twilio services.
type AccessToken struct {
	accountSid string
	keySid     string
	keySecret  string
	identity   string
	ttl        time.Duration
	notBefore  time.Time
	grants     []Grant
}

// NewAccessToken creates a default access token instance.  The account information
// must not be empty otherwise an error is emitted while formatting to JWT.
func NewAccessToken(accountSid, keySid, keySecret string) *AccessToken {
	return &AccessToken{
		accountSid: accountSid,
		keySid:     keySid,
		keySecret:  keySecret,
		ttl:        defaultTTL,
	}
}

// SetIdentity sets the identity of this access token.  This field must be set before generating a JWT.
func (a *AccessToken) SetIdentity(identity string) *AccessToken {
	a.identity = identity
	return a
}

// AddGrant adds a permission grant to this access token. Optional.
func (a *AccessToken) AddGrant(grant Grant) *AccessToken {
	a.grants = append(a.grants, grant)
	return a
}

// SetTTL sets the time to live of this access token.  By default, the expiration time
// is one hour after token is signed as JWT.
func (a *AccessToken) SetTTL(ttl time.Duration) *AccessToken {
	a.ttl = ttl
	return a
}

// SetNotBefore sets the time before which the token is not accepted for processing.
func (a *AccessToken) SetNotBefore(notBefore time.Time) *AccessToken {
	a.notBefore = notBefore
	return a
}

// ToJWT transforms token into JWT format to access twilio services. The token is signed with HS256 algorithm.
func (a *AccessToken) ToJWT() ([]byte, error) {
	return a.ToJWTWithMethod(crypto.SigningMethodHS256)
}

// ToJWTWithMethod transforms token into JWT format and signed by a specified method.
func (a *AccessToken) ToJWTWithMethod(method crypto.SigningMethod) ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	} else if allowed := isAllowedSigningMethod(method); !allowed {
		return nil, ErrUnsupportedAlgorithm
	}

	grants := map[string]interface{}{
		keyIdentity: a.identity,
	}
	for _, v := range a.grants {
		grants[v.Key()] = v.Payload()
	}

	claims := jws.Claims{}
	claims.Set(keyGrants, grants)
	claims.SetIssuer(a.keySid)
	claims.SetSubject(a.accountSid)
	now := nowTime()
	claims.SetJWTID(a.jwtID(now))
	claims.SetIssuedAt(now)
	exp := now.Add(a.ttl)
	claims.SetExpiration(exp)
	if !a.notBefore.IsZero() {
		claims.SetNotBefore(a.notBefore)
		if a.notBefore.After(exp) {
			log.Println("")
		}
	}
	jwt := jws.NewJWT(claims, method)
	jwt.(jws.JWS).Protected().Set(keyContentType, tokenContentType)
	return jwt.Serialize([]byte(a.keySecret))
}

func (a *AccessToken) validate() error {
	if a.accountSid == "" {
		return ErrMissingAccountSid
	} else if a.keySid == "" {
		return ErrMissingKeySid
	} else if a.keySecret == "" {
		return ErrMissingKeySecret
	} else if a.identity == "" {
		return ErrEmptyIdentity
	}
	return nil
}

// jwtID provides unique JWT id of an access token.
func (a *AccessToken) jwtID(m time.Time) string {
	return fmt.Sprintf("%s-%d", a.keySid, m.Unix())
}

func isAllowedSigningMethod(method crypto.SigningMethod) bool {
	if method == nil {
		return false
	}
	_, exists := supportedSigningMethods[method.Alg()]
	return exists
}

// wrap for unit test
var nowTime = time.Now
