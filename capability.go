package twilio

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
)

const (
	serviceClient = "client"
	serviceStream = "stream"

	keyClientName = "clientName"
	keyScope      = "scope"
	keyAppSid     = "appSid"
	keyAppParams  = "appParams"
)

// Capability is a builder struct to setup and generate Capability Token for
// twilio client communication.
type Capability struct {
	accountSid          string
	authToken           string
	ttl                 time.Duration
	capabilities        []string
	clientName          string
	outgoingScopeParams url.Values
}

// NewCapability creates a default capability token instance. The account information
// must not be empty otherwise an error is emitted while formatting to JWT.
func NewCapability(accountSid, authToken string) *Capability {
	return &Capability{
		accountSid:          accountSid,
		authToken:           authToken,
		ttl:                 defaultTTL,
		capabilities:        []string{},
		outgoingScopeParams: make(url.Values),
	}
}

// AllowClientIncoming adds the permissions to allow incoming connections to a
// specified twilio client name.
func (c *Capability) AllowClientIncoming(clientName string) *Capability {
	const privilege = "incoming"
	scopeParams := make(url.Values)
	scopeParams.Set(keyClientName, clientName)
	capability := scopeURIFor(serviceClient, privilege, scopeParams)
	c.clientName = clientName
	c.capabilities = append(c.capabilities, capability)
	return c
}

// AllowClientOutgoing adds permissions to allow twilio client making outgoing connections.
func (c *Capability) AllowClientOutgoing(appSid string, appParams map[string]string) *Capability {
	c.outgoingScopeParams.Set(keyAppSid, appSid)
	if len(appParams) > 0 {
		c.outgoingScopeParams.Set(keyAppParams, encodeParams(appParams))
	}
	return c
}

// AllowEventStream add permissions to allow twilio client subscribing to event streams.
func (c *Capability) AllowEventStream(filters string) *Capability {
	const privilege = "subscribe"
	params := newEventParams()
	if filters != "" {
		params.Set("params", filters)
	}
	capability := scopeURIFor(serviceStream, privilege, params)
	c.capabilities = append(c.capabilities, capability)
	return c
}

func newEventParams() (params url.Values) {
	params.Set("path", "/2010-04-01/Events")
	return
}

// SetTTL sets the time to live of this capability token.  By default, the expiration time
// is one hour after token is signed as JWT.
func (c *Capability) SetTTL(ttl time.Duration) *Capability {
	c.ttl = ttl
	return c
}

// ToJWT transforms token into JWT format for twilio client usage.
func (c *Capability) ToJWT() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if len(c.outgoingScopeParams) > 0 {
		const privilege = "outgoing"
		if c.clientName != "" {
			c.outgoingScopeParams.Set(keyClientName, c.clientName)
		}
		capability := scopeURIFor(serviceClient, privilege, c.outgoingScopeParams)
		c.capabilities = append(c.capabilities, capability)
	}
	scopes := strings.Join(c.capabilities, " ")

	method := crypto.SigningMethodHS256
	claims := jws.Claims{}
	claims.Set(keyScope, scopes)
	claims.SetIssuer(c.accountSid)
	exp := nowTime().Add(c.ttl)
	claims.SetExpiration(exp)
	jwt := jws.NewJWT(claims, method)
	return jwt.Serialize([]byte(c.authToken))
}

func (c *Capability) validate() error {
	if c.accountSid == "" {
		return ErrMissingAccountSid
	} else if c.authToken == "" {
		return ErrMissingAuthToken
	}
	return nil
}

func scopeURIFor(service, privilege string, params url.Values) string {
	uri := url.URL{
		Opaque:   fmt.Sprintf("scope:%s:%s", service, privilege),
		RawQuery: params.Encode(),
	}
	return uri.String()
}

func encodeParams(params map[string]string) string {
	query := make(url.Values)
	for k, v := range params {
		query.Add(k, v)
	}
	return query.Encode()
}
