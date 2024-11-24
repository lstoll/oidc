package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"golang.org/x/oauth2"
)

const DefaultProviderCacheDuration = 15 * time.Minute

type PublicHandle interface {
	PublicHandle(context.Context) (*keyset.Handle, error)
}

// Provider represents an OIDC Provider/issuer. It can provide a set of oauth2
// endpoints for the authentication flow, and verify tokens issued by the
// provider against it. It can be constructed via DiscoverProvider
type Provider struct {
	// Metadata for the OIDC provider configuration
	Metadata *ProviderMetadata
	// HTTPClient used for keyset fetching. Defaults to http.DefaultClient
	HTTPClient *http.Client
	// CacheDuration sets the time a keyset is cached for, before considering
	// re-fetching it. If not set, DefaultProviderCacheDuration is used.
	CacheDuration time.Duration
	// OverridePublicHandle allows setting an alternate source for the public
	// keyset for this provider. If set, rather than retrieving the JWKS from
	// the provider this function will be called to get a handle to the keyset
	// to verify against. Results from this will not be subject to the normal
	// cache duration for the provider.
	OverrideHandle PublicHandle

	lastHandle         *keyset.Handle
	lastHandleFetched  time.Time
	lastHandleCacheFor time.Duration
	cacheMu            sync.Mutex
}

// DiscoverOptions are used to customize the discovery process. If fields are
// set, the corresponding field will be set on the returned provider as well.
type DiscoverOptions struct {
	// OverridePublicHandle allows setting an alternate source for the public
	// keyset for this provider. If set, rather than retrieving the JWKS from
	// the provider this function will be called to get a handle to the keyset
	// to verify against. Results from this will not be subject to the normal
	// cache duration for the provider.
	OverridePublicHandle PublicHandle

	// HTTPClient sets the client used for discovery actions. Defaults to
	// http.DefaultClient
	HTTPClient *http.Client
}

// DiscoverProvider will discover Provider from the given issuer. The returned
// provider can be modified as needed.
func DiscoverProvider(ctx context.Context, issuer string, opts *DiscoverOptions) (*Provider, error) {
	p := &Provider{
		Metadata: new(ProviderMetadata),
	}

	if opts != nil {
		if opts.HTTPClient != nil {
			p.HTTPClient = opts.HTTPClient
		}
		if opts.OverridePublicHandle != nil {
			p.OverrideHandle = opts.OverridePublicHandle
		}
	}

	cfgURL := issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfgURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", cfgURL, err)
	}
	res, err := p.getHTTPClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching %s: %v", cfgURL, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status %d from %s, got: %d", http.StatusOK, cfgURL, res.StatusCode)
	}
	err = json.NewDecoder(res.Body).Decode(p.Metadata)
	if err != nil {
		return nil, fmt.Errorf("error decoding provider metadata response: %v", err)
	}
	if _, err := p.PublicHandle(ctx); err != nil {
		return nil, fmt.Errorf("getting public keys: %w", err)
	}

	return p, nil
}

// Endpoint returns the OAuth2 endpoint configuration for this provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:  p.Metadata.AuthorizationEndpoint,
		TokenURL: p.Metadata.TokenEndpoint,
	}
}

// PublicHandle returns a public handle to the verification keyset for this
// issuer. If there is a cached version within its life it will be returned,
// otherwise it will be refreshed from the provider.
func (p *Provider) PublicHandle(ctx context.Context) (*keyset.Handle, error) {
	if p.OverrideHandle != nil {
		h, err := p.OverrideHandle.PublicHandle(ctx)
		if err != nil {
			return nil, fmt.Errorf("calling overridden public handle: %w", err)
		}
		return h, nil
	}

	cacheFor := p.lastHandleCacheFor
	if cacheFor == 0 {
		cacheFor = DefaultProviderCacheDuration
	}

	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	if p.lastHandle == nil || time.Now().After(p.lastHandleFetched.Add(cacheFor)) {
		if err := p.FetchKeys(ctx); err != nil {
			return nil, err
		}
	}

	return p.lastHandle, nil
}

// FetchKeys retrieve the current signing keyset from the discovered jwks URL,
// and updates the cache on the provider. This can be used in a background
// routine to ensure the cache is always up-to-date, and avoid the verification
// methods potentially having to wait on a fetch. It can also be used to
// implement revocation.
func (p *Provider) FetchKeys(ctx context.Context) error {
	if p.OverrideHandle != nil {
		return fmt.Errorf("cannot fetch keys when handle is overridden")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Metadata.JWKSURI, nil)
	if err != nil {
		return fmt.Errorf("creating request for %s: %w", p.Metadata.JWKSURI, err)
	}
	req = req.WithContext(ctx)
	res, err := p.getHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("failed to get keys from %s: %v", p.Metadata.JWKSURI, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status %d, got: %d", http.StatusOK, res.StatusCode)
	}
	jwksb, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("reading JWKS body: %w", err)
	}

	h, err := jwt.JWKSetToPublicKeysetHandle(jwksb)
	if err != nil {
		return fmt.Errorf("creating handle from response: %w", err)
	}

	p.lastHandle = h
	p.lastHandleFetched = time.Now()

	return nil
}

// VerifyToken is a low-level function that verifies the raw JWT against the
// keyset for this provider. In most cases, one of the higher level ID
// token/access token methods should be used. This will always try and use the
// cached keyset, only falling back to a refresh if validation with the current
// keys fails.. It will return the verified JWT contents. This can be used
// against a JWT issued by this provider for any purpose. The validator opts
// should be provided to verify the audience/client ID and other required
// fields. Opts can be used to pass validation opts for the token, the issuer
// will always be set to the issuer for this provider and cannot be ignored.
func (p *Provider) VerifyToken(ctx context.Context, rawJWT string, opts *jwt.ValidatorOpts) (*jwt.VerifiedJWT, error) {
	if opts == nil {
		opts = &jwt.ValidatorOpts{}
	}

	opts.IgnoreIssuer = false
	opts.ExpectedIssuer = &p.Metadata.Issuer

	if p.OverrideHandle != nil {
		// handle is overridden, fetch and use it
		h, err := p.OverrideHandle.PublicHandle(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting handle: %w", err)
		}
		return p.verifyWithHandle(h, rawJWT, opts)
	}
	if p.lastHandle != nil {
		// we have a cached handle, try it first to shortcut any fetch.
		if v, err := p.verifyWithHandle(p.lastHandle, rawJWT, opts); err != nil {
			return v, err
		}
	}

	// we don't have a cached handle, or the token did not validate with it. Run
	// through the normal fetch option, to refresh if we're due.
	h, err := p.PublicHandle(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting handle: %w", err)
	}

	return p.verifyWithHandle(h, rawJWT, opts)
}

func (p *Provider) verifyWithHandle(h *keyset.Handle, raw string, opts *jwt.ValidatorOpts) (*jwt.VerifiedJWT, error) {
	verif, err := jwt.NewVerifier(h)
	if err != nil {
		return nil, fmt.Errorf("creating JWT verifier: %w", err)
	}
	valid, err := jwt.NewValidator(opts)
	if err != nil {
		return nil, fmt.Errorf("creating JWT validator: %w", err)
	}
	jwt, err := verif.VerifyAndDecode(raw, valid)
	if err != nil {
		return nil, fmt.Errorf("verifying/decoding JWT: %w", err)
	}
	return jwt, nil
}

// AccessTokenValidationOpts configures the validation of an OAuth2 JWT Access Token
type AccessTokenValidationOpts struct {
	Audience       string
	IgnoreAudience bool

	// IgnoreTokenTypeHeader header ignores the type header for Access
	// Tokens, rather than requiring it to be the correct value.
	IgnoreTokenTypeHeader bool

	// ACRValues can contain a list of ACRs the token should satisfy. If none of
	// these values are found in the token ACR, validation will fail.
	ACRValues []string
}

// VerifyAccessToken verifies an OAuth2 access token issued by this provider. If
// successful, the verified token and standard claims associated with it will be
// returned. Options should either have an audience specified, or have audience
// validation opted out of.
func (p *Provider) VerifyAccessToken(ctx context.Context, tok *oauth2.Token, opts AccessTokenValidationOpts) (*jwt.VerifiedJWT, *AccessTokenClaims, error) {
	if opts.Audience == "" && !opts.IgnoreAudience {
		return nil, nil, fmt.Errorf("audience missing from validation opts")
	}

	vopts := &jwt.ValidatorOpts{
		ExpectedAudience: ptrOrNil(opts.Audience),
		IgnoreAudiences:  opts.IgnoreAudience,
	}

	if !opts.IgnoreTokenTypeHeader {
		// TODO the short version is a "SHOULD", not must. Do we want to
		// fallback check the full one too?
		vopts.ExpectedTypeHeader = ptr(typJWTAccessToken)
	}

	verified, err := p.VerifyToken(ctx, tok.AccessToken, vopts)
	if err != nil {
		return nil, nil, err
	}

	atc, err := AccessTokenClaimsFromJWT(verified)
	if err != nil {
		return nil, nil, fmt.Errorf("loading claims from JWT: %w", err)
	}

	if len(opts.ACRValues) > 0 && !slices.Contains(opts.ACRValues, atc.ACR) {
		return nil, nil, fmt.Errorf("token ACR %q can not satisfy required ACRs [%v]", atc.ACR, opts.ACRValues)
	}

	return verified, atc, nil
}

// IDTokenValidationOpts configures the validation of an OIDC ID token
type IDTokenValidationOpts struct {
	// Audience claim to expect in the ID token. Often corresponds to the Client
	// ID
	Audience       string
	IgnoreAudience bool

	// ACRValues can contain a list of ACRs the token should satisfy. If none of
	// these values are found in the token ACR, validation will fail.
	ACRValues []string
}

// VerifyIDToken verifies an OIDC ID token issued by this provider. If
// successful, the verified token and standard claims associated with it will be
// returned. Options should either have an audience specified, or have audience
// validation opted out of.
func (p *Provider) VerifyIDToken(ctx context.Context, tok *oauth2.Token, opts IDTokenValidationOpts) (*jwt.VerifiedJWT, *IDClaims, error) {
	idt, ok := GetIDToken(tok)
	if !ok {
		return nil, nil, fmt.Errorf("token does not contain an ID token")
	}

	if opts.Audience == "" && !opts.IgnoreAudience {
		return nil, nil, fmt.Errorf("audience missing from validation opts")
	}

	vopts := &jwt.ValidatorOpts{
		ExpectedAudience: ptrOrNil(opts.Audience),
		IgnoreAudiences:  opts.IgnoreAudience,
	}

	verified, err := p.VerifyToken(ctx, idt, vopts)
	if err != nil {
		return nil, nil, err
	}

	idc, err := IDClaimsFromJWT(verified)
	if err != nil {
		return nil, nil, fmt.Errorf("loading claims from JWT: %w", err)
	}

	if len(opts.ACRValues) > 0 && !slices.Contains(opts.ACRValues, idc.ACR) {
		return nil, nil, fmt.Errorf("token ACR %q can not satisfy required ACRs [%v]", idc.ACR, opts.ACRValues)
	}

	return verified, idc, nil
}

// Userinfo calls the OIDC userinfo endpoint with the given credentials,
// returning the raw JSON response and parsed standard ID claims from this.
func (p *Provider) Userinfo(ctx context.Context, tokenSource oauth2.TokenSource) ([]byte, *IDClaims, error) {
	if p.Metadata.UserinfoEndpoint == "" {
		return nil, nil, fmt.Errorf("provider does not have a userinfo endpoint")
	}

	oc := oauth2.NewClient(ctx, tokenSource)

	req, err := http.NewRequest("GET", p.Metadata.UserinfoEndpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating identity fetch request: %v", err)
	}

	resp, err := oc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("error making identity request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, nil, fmt.Errorf("authentication to userinfo endpoint failed")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, fmt.Errorf("bad response from server: http %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("reading userinfo response body: %w", err)
	}

	var cl IDClaims

	if err := json.Unmarshal(b, &cl); err != nil {
		return nil, nil, fmt.Errorf("failed decoding response body: %v", err)
	}

	// TODO(lstoll) the caller should do this, but is there a way we can as well?
	//
	// make sure the returned userinfo subject matches the token, to prevent
	// token substitution attacks
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

	return b, &cl, nil
}

func (p *Provider) getHTTPClient() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

type staticPublicHandle struct {
	h *keyset.Handle
}

func (s *staticPublicHandle) PublicHandle(context.Context) (*keyset.Handle, error) {
	return s.h, nil
}

// NewStaticPublicHandle creates a PublicHandle from a fixed keyset Handle.
func NewStaticPublicHandle(h *keyset.Handle) PublicHandle {
	return &staticPublicHandle{h: h}
}
