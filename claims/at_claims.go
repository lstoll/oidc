package claims

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
)

// AccessTokenClaims represents the set of JWT claims for an OAuth2 JWT Access
// token.
//
// https://datatracker.ietf.org/doc/html/rfc9068
type AccessTokenClaims struct {
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
	Expiry UnixTime `json:"exp,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
	Audience StrOrSlice `json:"aud,omitempty"`
	// REQUIRED - as defined in Section 4.1.2 of [RFC7519]. In cases
	// of access tokens obtained through grants where a resource owner is
	// involved, such as the authorization code grant, the value of "sub" SHOULD
	// correspond to the subject identifier of the resource owner. In cases of
	// access tokens obtained through grants where no resource owner is
	// involved, such as the client credentials grant, the value of "sub" SHOULD
	// correspond to an identifier the authorization server uses to indicate the
	// client application. See Section 5 for more details on this scenario.
	// Also, see Section 6 for a discussion about how different choices in
	// assigning "sub" values can impact privacy.
	// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc8693#section-4.3
	ClientID string `json:"client_id,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6
	IssuedAt UnixTime `json:"iat,omitempty"`
	// REQUIRED. https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7
	JWTID string `json:"jti,omitempty"`
	// https://www.rfc-editor.org/rfc/rfc8693#section-4.2
	Scope string `json:"scope,omitempty"`
	// Time when the End-User authentication occurred. Its value is a JSON
	// number representing the number of seconds from 1970-01-01T0:0:0Z as
	// measured in UTC until the date/time. When a max_age request is made or
	// when auth_time is requested as an Essential Claim, then this Claim is
	// REQUIRED; otherwise, its inclusion is OPTIONAL. (The auth_time Claim
	// semantically corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time
	// response parameter.)
	//
	// https://openid.net/specs/openid-connect-core-1_0.html
	AuthTime UnixTime `json:"auth_time,omitempty"`
	// OPTIONAL. Authentication Context Class Reference. String specifying an
	// Authentication Context Class Reference value that identifies the
	// Authentication Context Class that the authentication performed satisfied.
	// The value "0" indicates the End-User authentication did not meet the
	// requirements of ISO/IEC 29115 [ISO29115] level 1. Authentication using a
	// long-lived browser cookie, for instance, is one example where the use of
	// "level 0" is appropriate. Authentications with level 0 SHOULD NOT be used
	// to authorize access to any resource of any monetary value. (This
	// corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.) An
	// absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as
	// the acr value; registered names MUST NOT be used with a different meaning
	// than that which is registered. Parties using this claim will need to
	// agree upon the meanings of the values used, which may be
	// context-specific. The acr value is a case sensitive string.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html
	ACR string `json:"acr,omitempty"`
	// OPTIONAL. Authentication Methods References. JSON array of strings that
	// are identifiers for authentication methods used in the authentication.
	// For instance, values might indicate that both password and OTP
	// authentication methods were used. The definition of particular values to
	// be used in the amr Claim is beyond the scope of this specification.
	// Parties using this claim will need to agree upon the meanings of the
	// values used, which may be context-specific. The amr value is an array of
	// case sensitive strings.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html
	AMR []string `json:"amr,omitempty"`

	// https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.3.1 |
	// https://www.rfc-editor.org/rfc/rfc7643#section-4.1.2
	//
	// TODO(lstoll) - do we want to support the more complex than a list version
	// of these, i.e https://www.rfc-editor.org/rfc/rfc7643#section-8.2 ?
	Groups []string `json:"groups,omitempty"`
	// https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.3.1 |
	// https://www.rfc-editor.org/rfc/rfc7643#section-4.1.2
	Roles []string `json:"roles,omitempty"`
	// https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.3.1 |
	// https://www.rfc-editor.org/rfc/rfc7643#section-4.1.2
	Entitlements []string `json:"entitlements,omitempty"`
	// Extra contains any other claims that are not part of the standard set.
	// These claims will be marshalled and unmarshalled from the JWT.
	Extra map[string]any `json:"-"`
}

func (a *AccessTokenClaims) MarshalJSON() ([]byte, error) {
	// Get all the json tags from the struct to check for conflicts
	tags := make(map[string]struct{})
	val := reflect.TypeOf(*a)
	for j := 0; j < val.NumField(); j++ {
		field := val.Field(j)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			tags[name] = struct{}{}
		}
	}

	for k := range a.Extra {
		if _, ok := tags[k]; ok {
			return nil, fmt.Errorf("extra claim %q conflicts with standard claim", k)
		}
	}

	type alias AccessTokenClaims
	b, err := json.Marshal(alias(*a)) // use alias to prevent recursion
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}

	for k, v := range a.Extra {
		m[k] = v
	}

	return json.Marshal(m)
}

func (a *AccessTokenClaims) UnmarshalJSON(b []byte) error {
	type alias AccessTokenClaims
	if err := json.Unmarshal(b, (*alias)(a)); err != nil {
		return err
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}

	// Get all the json tags from the struct to know which fields are standard
	tags := make(map[string]struct{})
	val := reflect.TypeOf(*a)
	for j := 0; j < val.NumField(); j++ {
		field := val.Field(j)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name != "" {
			tags[name] = struct{}{}
		}
	}
	a.Extra = make(map[string]any)
	for k, v := range m {
		if _, ok := tags[k]; !ok {
			a.Extra[k] = v
		}
	}

	return nil
}

func (a *AccessTokenClaims) String() string {
	m, err := json.Marshal(a)
	if err != nil {
		return fmt.Sprintf("sub: %s failed: %v", a.Subject, err)
	}

	return string(m)
}

func (a *AccessTokenClaims) ToJWT(extraClaims map[string]any) (*jwt.RawJWT, error) {
	var exp *time.Time
	if a.Expiry != 0 {
		t := a.Expiry.Time()
		exp = &t
	}
	var iat *time.Time
	if a.IssuedAt != 0 {
		t := a.IssuedAt.Time()
		iat = &t
	}

	opts := &jwt.RawJWTOptions{
		TypeHeader:   ptr(typJWTAccessToken),
		Issuer:       ptrOrNil(a.Issuer),
		Subject:      ptrOrNil(a.Subject),
		Audiences:    a.Audience,
		ExpiresAt:    exp,
		JWTID:        ptrOrNil(a.JWTID),
		IssuedAt:     iat,
		CustomClaims: make(map[string]any),
	}
	if a.Scope != "" {
		opts.CustomClaims["scope"] = a.Scope
	}
	if a.ClientID != "" {
		opts.CustomClaims["client_id"] = a.ClientID
	}
	if a.AuthTime != 0 {
		opts.CustomClaims["auth_time"] = int(a.AuthTime)
	}
	if a.ACR != "" {
		opts.CustomClaims["acr"] = a.ACR
	}
	if a.AMR != nil {
		opts.CustomClaims["amr"] = sliceToAnySlice(a.AMR)
	}
	if a.Groups != nil {
		opts.CustomClaims["groups"] = sliceToAnySlice(a.Groups)
	}
	if a.Groups != nil {
		opts.CustomClaims["roles"] = sliceToAnySlice(a.Roles)
	}
	if a.Entitlements != nil {
		opts.CustomClaims["entitlements"] = sliceToAnySlice(a.Entitlements)
	}
	if len(a.Extra) > 0 {
		opts.CustomClaims["extra_claims"] = a.Extra
	}
	for k, v := range extraClaims {
		if _, ok := opts.CustomClaims[k]; ok {
			return nil, fmt.Errorf("duplicate/reserved claim %s", k)
		}
		opts.CustomClaims[k] = v
	}

	raw, err := jwt.NewRawJWT(opts)
	if err != nil {
		return nil, fmt.Errorf("constructing raw JWT from claims: %w", err)
	}

	return raw, nil
}

func AccessTokenClaimsFromJWT(verified *jwt.VerifiedJWT) (*AccessTokenClaims, error) {
	c := new(AccessTokenClaims)
	var errs error
	if verified.HasIssuer() {
		v, err := verified.Issuer()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Issuer = v
	}
	if verified.HasSubject() {
		v, err := verified.Subject()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Subject = v
	}
	if verified.HasAudiences() {
		v, err := verified.Audiences()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Audience = StrOrSlice(v)
	}
	if verified.HasExpiration() {
		v, err := verified.ExpiresAt()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Expiry = UnixTime(v.Unix())
	}
	if verified.HasIssuedAt() {
		v, err := verified.IssuedAt()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.IssuedAt = UnixTime(v.Unix())
	}
	if verified.HasJWTID() {
		v, err := verified.JWTID()
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.JWTID = v
	}

	if verified.HasStringClaim("client_id") {
		v, err := verified.StringClaim("client_id")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.ClientID = v
	}
	if verified.HasStringClaim("scope") {
		v, err := verified.StringClaim("scope")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Scope = v
	}
	if verified.HasNumberClaim("auth_time") {
		v, err := verified.NumberClaim("auth_time")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.AuthTime = UnixTime(v)
	}
	if verified.HasStringClaim("acr") {
		v, err := verified.StringClaim("acr")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.ACR = v
	}
	if verified.HasArrayClaim("amr") {
		v, err := verified.ArrayClaim("amr")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		sv, err := anySliceToSlice[string](v)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.AMR = sv
	}
	if verified.HasArrayClaim("groups") {
		v, err := verified.ArrayClaim("groups")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		sv, err := anySliceToSlice[string](v)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Groups = sv
	}
	if verified.HasArrayClaim("roles") {
		v, err := verified.ArrayClaim("roles")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		sv, err := anySliceToSlice[string](v)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Roles = sv
	}
	if verified.HasArrayClaim("entitlements") {
		v, err := verified.ArrayClaim("entitlements")
		if err != nil {
			errs = errors.Join(errs, err)
		}
		sv, err := anySliceToSlice[string](v)
		if err != nil {
			errs = errors.Join(errs, err)
		}
		c.Entitlements = sv
	}

	if verified.HasObjectClaim("extra_claims") {
		extra, err := verified.ObjectClaim("extra_claims")
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("parsing extra_claims: %w", err))
		} else {
			c.Extra = extra
		}
	}
	if errs != nil {
		return nil, errs
	}
	return c, nil
}
