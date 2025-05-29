package middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lstoll/oidc"
	"golang.org/x/oauth2"
)

const (
	// maxLoginStatesCookieSizeBytes defines the maximum size of the raw login
	// states string before base64 encoding. Cookies have a general limit of
	// around 4KB. We leave some room for base64 expansion and other cookie
	// attributes.
	maxLoginStatesCookieSizeBytes = 3000

	fieldSeparator  = "\x1f" // ASCII Record Separator
	recordSeparator = "\x1e" // ASCII Field Separator
)

type CookieOpts struct {
	TokenCookieName string
	LoginCookieName string
	Path            string
	Secure          bool
	SameSite        http.SameSite
	// Persist is used to control if the token cookie is persisted across
	// browser sessions. If true, the cookie expiration will be set based on the
	// token lifetime. If false, the cookie will be set to expire when the
	// browser is closed.
	Persist bool
}

var DefaultCookieOpts = CookieOpts{
	TokenCookieName: "__HOST-auth",
	LoginCookieName: "__HOST-logins",
	Path:            "/",
	Secure:          true,
	SameSite:        http.SameSiteLaxMode,
}

// Cookiestore is a basic implementation of the middleware's session store, that
// stores values in a series of cookies. These are not signed or encrypted, so
// only the ID token is tracked - the access token and refresh tokens are
// discarded, to avoid risk of them leaking. The login state is also stored
// unauthenticated, applications should take this in to mind. Cookie storage is
// limited, so too many in-flight logins may cause issues.
//
// This provides a simple default, but it is generally recommended to use a
// server-side session store.
type Cookiestore struct {
	// CookieOpts is used to create the cookie we track the session ID in. If
	// not set, DefaultCookieOpts will be used.
	CookieOpts *CookieOpts
}

func (c *Cookiestore) GetOIDCSession(r *http.Request) (*SessionData, error) {
	sd := &SessionData{}

	idtc, err := r.Cookie(c.getCookieOpts().TokenCookieName)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		return nil, fmt.Errorf("getting cookie: %w", err)
	} else if err == nil {
		// got a cookie, load it
		o2t := new(oauth2.Token)
		o2t = oidc.AddIDToken(o2t, idtc.Value)
		sd.Token = &oidc.TokenWithID{
			Token: o2t,
		}
	}

	// re-construct the login state from a single cookie
	lsCookie, err := r.Cookie(c.getCookieOpts().LoginCookieName)
	if err == nil && lsCookie.Value != "" {
		decodedData, err := base64.RawURLEncoding.DecodeString(lsCookie.Value)
		if err != nil {
			// Malformed base64, treat as no cookie or corrupted
			return sd, nil
		}
		loginStatesStr := string(decodedData)

		for entryStr := range strings.SplitSeq(loginStatesStr, recordSeparator) {
			if entryStr == "" {
				continue
			}
			if strings.Count(entryStr, fieldSeparator) != 3 {
				// Malformed entry, skip
				continue
			}

			parts := strings.SplitN(entryStr, fieldSeparator, 4)
			if len(parts) != 4 {
				// Malformed entry, skip
				continue
			}

			state := parts[0]
			pkceChallenge := parts[1]
			returnToEscaped := parts[2]
			expiresStr := parts[3]

			if state == "" || expiresStr == "" { // State and Expires are mandatory
				// Invalid entry, skip
				continue
			}

			expires, err := strconv.ParseInt(expiresStr, 10, 64)
			if err != nil {
				// Malformed expires, skip
				continue
			}

			if time.Now().Unix() > expires {
				// Expired entry, skip
				continue
			}

			var returnTo string
			if returnToEscaped != "" {
				returnTo, err = url.QueryUnescape(returnToEscaped)
				if err != nil {
					// Malformed returnTo, skip
					continue
				}
			}

			sd.Logins = append(sd.Logins, SessionDataLogin{
				State:         state,
				PKCEChallenge: pkceChallenge,
				ReturnTo:      returnTo,
				Expires:       int(expires),
			})
		}
	} else if !errors.Is(err, http.ErrNoCookie) {
		return nil, fmt.Errorf("getting login states cookie %q: %w", c.getCookieOpts().LoginCookieName, err)
	}

	return sd, nil
}

func (c *Cookiestore) SaveOIDCSession(w http.ResponseWriter, r *http.Request, d *SessionData) error {
	if d.Token != nil {
		tok, exp, err := peekIDT(d.Token.Token)
		if err != nil {
			return fmt.Errorf("processing id_token: %w", err)
		}
		if err := setCookieIfNotSet(w, r, c.newTokenCookie(tok, exp)); err != nil {
			return fmt.Errorf("saving token cookie: %w", err)
		}
	} else {
		// delete if it exists
		if err := setCookieIfNotSet(w, r, c.newTokenCookie("", time.Time{})); err != nil {
			return fmt.Errorf("deleting token cookie: %w", err)
		}
	}

	// 1. Collect and filter non-expired SessionDataLogin items
	validRawLogins := []SessionDataLogin{}
	for _, l := range d.Logins {
		if time.Now().Unix() > int64(l.Expires) {
			continue
		}
		validRawLogins = append(validRawLogins, l)
	}

	// 2. Sort by expiration descending (newest/furthest expiry first)
	sort.Slice(validRawLogins, func(i, j int) bool {
		return validRawLogins[i].Expires > validRawLogins[j].Expires
	})

	loginStatesBuilder := strings.Builder{}

	for _, l := range validRawLogins {
		// Format: State,PKCEChallenge,URLEncodedReturnTo,ExpiresUnixTimestamp
		// Ensure ReturnTo is escaped properly for inclusion in a comma-separated list and then URL context
		returnToStr := ""
		if l.ReturnTo != "" {
			returnToStr = url.QueryEscape(l.ReturnTo)
		}

		stateStr := fmt.Sprintf("%s%s%s%s%s%s%d", l.State, fieldSeparator, l.PKCEChallenge, fieldSeparator, returnToStr, fieldSeparator, l.Expires)

		projectedLen := loginStatesBuilder.Len()
		if projectedLen > 0 {
			projectedLen++ // For the semicolon separator
		}
		projectedLen += len(stateStr)

		if projectedLen > maxLoginStatesCookieSizeBytes {
			break // Adding this state would exceed the size limit
		}

		if loginStatesBuilder.Len() > 0 {
			loginStatesBuilder.WriteString(recordSeparator)
		}
		loginStatesBuilder.WriteString(stateStr)
	}

	// this will automatically delete if we have no state to save.
	finalLoginStatesString := loginStatesBuilder.String()
	var cookieValue string
	if finalLoginStatesString != "" {
		cookieValue = base64.RawURLEncoding.EncodeToString([]byte(finalLoginStatesString))
	}

	return setCookieIfNotSet(w, r, c.newLoginStateCookie(cookieValue))
}

func (c *Cookiestore) newTokenCookie(value string, expires time.Time) *http.Cookie {
	ct := c.getCookieOpts()
	nc := &http.Cookie{
		Name:     ct.TokenCookieName,
		Path:     ct.Path,
		Secure:   ct.Secure,
		SameSite: ct.SameSite,
		Value:    value,
	}
	if value == "" {
		nc.MaxAge = -1
		return nc
	}
	if ct.Persist {
		// use max age, the server clock is hopefully more accurate than the
		// client clock.
		nc.MaxAge = int(time.Until(expires).Seconds())
	}
	return nc
}

func (c *Cookiestore) newLoginStateCookie(value string) *http.Cookie {
	ct := c.getCookieOpts()
	nc := &http.Cookie{
		Name:     ct.LoginCookieName,
		Path:     ct.Path,
		Secure:   ct.Secure,
		SameSite: ct.SameSite,
		Value:    value,
	}
	if value == "" {
		nc.MaxAge = -1
	}
	// login state doesn't make much sense across browser sessions, so we don't
	// persist it
	return nc
}

func (c *Cookiestore) getCookieOpts() *CookieOpts {
	if c.CookieOpts != nil {
		return c.CookieOpts
	}
	return &DefaultCookieOpts
}

func setCookieIfNotSet(w http.ResponseWriter, r *http.Request, c *http.Cookie) error {
	ec, err := r.Cookie(c.Name)
	if errors.Is(err, http.ErrNoCookie) {
		if c.Value != "" {
			http.SetCookie(w, c)
		}
		return nil
	} else if err != nil {
		return fmt.Errorf("getting cookie: %w", err)
	}
	if ec.Value != c.Value {
		http.SetCookie(w, c)
	}
	return nil
}

// peekIDT is a helper to extract expiration from a token. The token SHOULD NOT
// BE TRUSTED, AS IT HAS NOT BEEN VERIFIED. used calculating cookie expiration.
func peekIDT(t *oauth2.Token) (tok string, exp time.Time, _ error) {
	idt, ok := t.Extra("id_token").(string)
	if !ok {
		return "", time.Time{}, errors.New("token contains no ID token")
	}

	if strings.Count(idt, ".") != 2 {
		return "", time.Time{}, fmt.Errorf("id_token not a JWT")
	}

	parts := strings.SplitN(idt, ".", 3)
	if len(parts) != 3 {
		return "", time.Time{}, fmt.Errorf("id_token not a JWT")
	}

	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", time.Time{}, fmt.Errorf("id_token payload decode failed: %w", err)
	}

	var cl *oidc.IDClaims
	if err := json.Unmarshal(cb, &cl); err != nil {
		return "", time.Time{}, fmt.Errorf("unmarshaling claims failed: %w", err)
	}

	return idt, cl.Expiry.Time(), nil
}
