# TwilioGo

A Golang library for twilio server side SDK.

## Installation

Install the package with go:

    go get github.com/xaviiic/twilioGo

Import the package to your go file:

```go
import (
    twilio "github.com/xaviiic/twilioGo"
)
```

## Usage

#### Access Token
> [Access Tokens are short-lived tokens that you can use to authenticate Twilio Client SDKs like Video and IP Messaging. You create them on your server to verify a client's identity and grant access to client API features.][1]

To create an access token, pass the Twilio API account information first.
```go
// first create token with twilio api configurations
token := twilio.NewAccessToken(accountID, keyID, secret)
// setup token identity
token.SetIdentity(identity)
```
Once you have created a token instance, you can add access grant with desired API features.
```go
// grant token access to progammable video API
grant := twilio.NewConversationGrant(configurationProfileID)
token.AddGrant(grant)
```
Then transform token to JWT format for client side usages.
```go
jwt, err := token.ToJWT()
```

#### Capability Token
> [Capability tokens allow you to add Twilio capabilities to web and mobile applications without exposing your AuthToken in JavaScript or any other client-side environment.][2]

Create a capability token instance first with API account information.
```go
capability := twilio.NewCapability(accountID, authToken)
```
Then setup the capabilities of token and output a JWT format token.
```go
// allow incoming connections
capability.AllowClientIncoming(clientName)
// allow outgoing connections
capability.AllowClientOutgoing(appID, nil)
jwt, err := capability.ToJWT()
```

#### Chaining
Generating token steps can be chained together.
```go
token, err := twilio.NewAccessToken(accountSid, apiKey, apiSecret).
    SetIdentity(identity).
    AddGrant(twilio.NewConversationGrant(configurationSid)).
    SetTTL(30 * time.Minute).
    ToJWT()
```


## License

    Copyright 2016 xaviiic

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

[1]: https://www.twilio.com/docs/api/rest/access-tokens "Twilio API: Access Tokens"
[2]: https://www.twilio.com/docs/api/client/capability-tokens "Twilio Client: Capability Tokens"