package twilio

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCapabilityToJWT(t *testing.T) {
	var accountSid, authToken = "AaaaaDASMAI1ON6655", "aaaaauthh"
	_, err := NewCapability("", authToken).ToJWT()
	assert.EqualError(t, err, "twilio accounSid not set")
	_, err = NewCapability(accountSid, "").ToJWT()
	assert.EqualError(t, err, "twilio auth token not set")
	_, err = NewCapability(accountSid, authToken).ToJWT()
	assert.NoError(t, err)
}

func TestCapabilitySetTTL(t *testing.T) {
	nowTime = func() time.Time {
		return time.Unix(1470116000, 0)
	}
	defer func() {
		nowTime = time.Now
	}()
	token := NewCapability("account", "authToken")

	tokenBytes, err := token.ToJWT()
	assert.NoError(t, err)
	exp, err := expirationFromJWT(tokenBytes)
	assert.NoError(t, err)
	assert.EqualValues(t, exp, 1470119600)

	tokenBytes, err = token.SetTTL(time.Minute).ToJWT()
	assert.NoError(t, err)
	exp, err = expirationFromJWT(tokenBytes)
	assert.NoError(t, err)
	assert.EqualValues(t, exp, 1470116060)
}
