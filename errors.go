package twilio

import "errors"

var (
	// ErrMissingAccountSid is returned if trying to sign a JWT token without
	// setup account sid information.
	ErrMissingAccountSid = errors.New("twilio accounSid not set")
	// ErrMissingAuthToken is returned if trying to sign a JWT token without setup
	// account auth token information.
	ErrMissingAuthToken = errors.New("twilio auth token not set")
	// ErrMissingKeySid is returned if trying to sign a JWT token without setup key sid.
	ErrMissingKeySid = errors.New("twilio key sid not set")
	// ErrMissingKeySecret is returned if trying to sign a JWT token without setup key secret.
	ErrMissingKeySecret = errors.New("twilio key secret not set")
	// ErrUnsupportedAlgorithm is returned if trying to format token in JWT but using
	// unsupported signing method.
	ErrUnsupportedAlgorithm = errors.New("signing method is not supported")
	// ErrEmptyIdentity is returned if trying to sign a jwt access token without
	// setup an identity.
	ErrEmptyIdentity = errors.New("generate access token for empty identity")
)
