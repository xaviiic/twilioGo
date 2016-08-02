package twilio

import (
	"errors"
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/stretchr/testify/assert"
)

func TestAccessTokenToJWT(t *testing.T) {
	var accountSid, keySid, secret = "AaaaaDASMAI1ON6655", "SKdc9c6882b389762ff0a759b8cbaa152f", "secret"
	_, err := NewAccessToken("", keySid, secret).SetIdentity("9527").ToJWT()
	assert.EqualError(t, err, "twilio accounSid not set")
	_, err = NewAccessToken(accountSid, "", secret).SetIdentity("9527").ToJWT()
	assert.EqualError(t, err, "twilio key sid not set")
	_, err = NewAccessToken(accountSid, keySid, "").SetIdentity("9527").ToJWT()
	assert.EqualError(t, err, "twilio key secret not set")
	_, err = NewAccessToken(accountSid, keySid, secret).ToJWT()
	assert.EqualError(t, err, "generate access token for empty identity")
	_, err = NewAccessToken(accountSid, keySid, secret).SetIdentity("9527").ToJWT()
	assert.NoError(t, err)
}

func TestAccessTokenToJWTWithAlgorithm(t *testing.T) {
	token := NewAccessToken("account", "sid", "secret").SetIdentity("111").AddGrant(NewConversationGrant("profile-sid"))
	checkSignWith := func(method crypto.SigningMethod) (err error) {
		_, err = token.ToJWTWithMethod(method)
		return
	}
	err := checkSignWith(crypto.SigningMethodHS256)
	assert.NoError(t, err)
	err = checkSignWith(crypto.SigningMethodHS384)
	assert.NoError(t, err)
	err = checkSignWith(crypto.SigningMethodHS512)
	assert.NoError(t, err)
	// unsupported algorithms
	err = checkSignWith(nil)
	assert.EqualError(t, err, "signing method is not supported")
	err = checkSignWith(crypto.SigningMethodRS256)
	assert.EqualError(t, err, "signing method is not supported")
}

func TestAccessTokenSetTTL(t *testing.T) {
	nowTime = func() time.Time {
		return time.Unix(1470114000, 0)
	}
	defer func() {
		nowTime = time.Now
	}()
	token := NewAccessToken("account", "keyId", "secret").SetIdentity("111").SetNotBefore(time.Unix(1470115000, 0))

	tokenBytes, err := token.ToJWT()
	assert.NoError(t, err)
	exp, err := expirationFromJWT(tokenBytes)
	assert.NoError(t, err)
	assert.EqualValues(t, exp, 1470117600)

	tokenBytes, err = token.SetTTL(10 * time.Minute).ToJWT()
	assert.NoError(t, err)
	exp, err = expirationFromJWT(tokenBytes)
	assert.NoError(t, err)
	assert.EqualValues(t, exp, 1470114600)
}

func TestAccessTokenAddConversationGrant(t *testing.T) {
	token := NewAccessToken("account", "keyId", "secret").SetIdentity("jojo")

	tokenBytes, err := token.ToJWT()
	assert.NoError(t, err)
	grants, err := grantsFromJWT(tokenBytes)
	assert.NoError(t, err)
	assert.EqualValues(t, map[string]interface{}{
		"identity": "jojo",
	}, grants)

	tokenBytes, err = token.AddGrant(NewConversationGrant("pid")).ToJWT()
	assert.NoError(t, err)
	grants, err = grantsFromJWT(tokenBytes)
	assert.NoError(t, err)
	assert.EqualValues(t, map[string]interface{}{
		"identity": "jojo",
		"rtc":      map[string]interface{}{"configuration_profile_sid": "pid"},
	}, grants)
}

func TestAccessTokenAddIpMessagingGrant(t *testing.T) {
	tokenBytes, err := NewAccessToken("account", "keyId", "secret").SetIdentity("jojo").
		AddGrant(NewIPMessagingGrant("aaaaa", "bbbbb", "ccccc", "")).ToJWT()
	assert.NoError(t, err)
	grants, err := grantsFromJWT(tokenBytes)
	assert.NoError(t, err)
	assert.EqualValues(t, map[string]interface{}{
		"identity": "jojo",
		"ip_messaging": map[string]interface{}{
			"service_sid":         "aaaaa",
			"endpoint_id":         "bbbbb",
			"deployment_role_sid": "ccccc",
		},
	}, grants)
}

func TestAccessTokenAddConversationAndIpMessagingGrant(t *testing.T) {
	tokenBytes, err := NewAccessToken("account", "keyId", "secret").SetIdentity("jojo").
		AddGrant(NewConversationGrant("pid")).AddGrant(NewIPMessagingGrant("aaaaa", "bbbbb", "ccccc", "ddddd")).
		ToJWT()
	assert.NoError(t, err)
	grants, err := grantsFromJWT(tokenBytes)
	assert.NoError(t, err)
	assert.EqualValues(t, map[string]interface{}{
		"identity": "jojo",
		"rtc":      map[string]interface{}{"configuration_profile_sid": "pid"},
		"ip_messaging": map[string]interface{}{
			"service_sid":         "aaaaa",
			"endpoint_id":         "bbbbb",
			"deployment_role_sid": "ccccc",
			"push_credential_sid": "ddddd",
		},
	}, grants)
}

func grantsFromJWT(jwtBytes []byte) (map[string]interface{}, error) {
	jwt, err := jws.ParseJWT(jwtBytes)
	if err != nil {
		return nil, err
	}
	grant := jwt.Claims().Get(keyGrants)
	grantValues, _ := grant.(map[string]interface{})
	return grantValues, nil
}

func expirationFromJWT(jwtBytes []byte) (int64, error) {
	var unix int64
	if jwt, err := jws.ParseJWT(jwtBytes); err != nil {
		return 0, err
	} else if exp, exists := jwt.Claims().Expiration(); !exists {
		return 0, errors.New("expiration time not exists")
	} else {
		unix = exp.Unix()
	}
	return unix, nil
}
