package middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lstoll/oidc"
	"golang.org/x/oauth2"
)

const (
	loginCookiePrefix = "_l_"
	tokenCookieSuffix = "_t"
)

// DefaultCookieTemplate is the default cookie used, unless otherwise
// configured.
var DefaultCookieTemplate = &http.Cookie{
	Name:     "oidc",
	HttpOnly: true,
	Secure:   true,
	SameSite: http.SameSiteLaxMode,
}

// Cookiestore is a basic implementation of the middleware's session store, that
// stores values in a series of cookies. These are not signed or encrypted, so
// only the ID token is tracked - the access token and refresh tokens are
// discareded, to avoid risk of them leaking. The login state is also stored
// unauthenticated, applications should take this in to mind. Cookie storage is
// limited, so too many in-flight logins may cause issues.
//
// This provides a simple default, but it is generally recommended to use a
// server-side session store.
type Cookiestore struct {
	// CookieTemplate is used to create the cookie we track the session ID in.
	// It must have at least the name set. Value and expiration fields will be
	// ignored, and set appropriately. If not set, DefaultCookieTemplate will be
	// used.
	CookieTemplate *http.Cookie
}

func (c *Cookiestore) GetOIDCSession(r *http.Request) (*SessionData, error) {
	sd := &SessionData{}

	idtc, err := r.Cookie(c.cookieNamePrefix() + tokenCookieSuffix)
	if err != nil && !errors.Is(err, http.ErrNoCookie) {
		return nil, fmt.Errorf("getting cookie: %w", err)
	} else if err == nil {
		// got a cookie, load it
		o2t := new(oauth2.Token)
		o2t = oidc.TokenWithID(o2t, idtc.Value)
		sd.Token = &oidc.MarshaledToken{
			Token: o2t,
		}
	}

	// re-construct the login state
	for _, ec := range r.Cookies() {
		if strings.HasPrefix(ec.Name, c.cookieNamePrefix()+loginCookiePrefix) {
			state := strings.TrimPrefix(ec.Name, c.cookieNamePrefix()+loginCookiePrefix)
			v, err := url.ParseQuery(ec.Value)
			if err != nil {
				continue // ignore the data on error
			}
			exp, err := strconv.Atoi(v.Get("ex"))
			if err != nil {
				continue
			}
			sd.Logins = append(sd.Logins, SessionDataLogin{
				State:         state,
				PKCEChallenge: v.Get("cc"),
				ReturnTo:      v.Get("rt"),
				Expires:       exp,
			})
		}
	}

	return sd, nil
}

func (c *Cookiestore) SaveOIDCSession(w http.ResponseWriter, r *http.Request, d *SessionData) error {
	if d.Token != nil {
		tok, exp, err := peekIDT(d.Token.Token)
		if err != nil {
			return fmt.Errorf("processing id_token: %w", err)
		}
		if tc, err := r.Cookie(c.cookieNamePrefix() + tokenCookieSuffix); err != nil || tc.Value != tok {
			// no existing cookie for this, save it
			tc := c.newCookie()
			tc.Name = c.cookieNamePrefix() + tokenCookieSuffix
			tc.Expires = exp
			tc.Value = tok
			http.SetCookie(w, tc)
		}
	} else {
		dc := c.newCookie()
		dc.Name = c.cookieNamePrefix() + tokenCookieSuffix
		dc.MaxAge = -1
		http.SetCookie(w, dc)
	}

	// track current logins, so we can reconcile and delete other
	currLogins := map[string]struct{}{}
	for _, l := range d.Logins {
		currLogins[l.State] = struct{}{}
		_, err := r.Cookie(c.cookieNamePrefix() + loginCookiePrefix + l.State)
		// state data is not mutable, only set if we don't already have a
		// cookie.
		if err != nil {
			v := url.Values{}
			if l.PKCEChallenge != "" {
				v.Set("cc", l.PKCEChallenge)
			}
			if l.ReturnTo != "" {
				v.Set("rt", l.ReturnTo)
			}
			v.Set("ex", strconv.Itoa(l.Expires))
			lc := c.newCookie()
			lc.Expires = time.Unix(int64(l.Expires), 0)
			lc.Name = c.cookieNamePrefix() + loginCookiePrefix + l.State
			lc.Value = v.Encode()
			http.SetCookie(w, lc)
		}
	}
	for _, ec := range r.Cookies() {
		if strings.HasPrefix(ec.Name, c.cookieNamePrefix()+loginCookiePrefix) {
			state := strings.TrimPrefix(ec.Name, c.cookieNamePrefix()+loginCookiePrefix)
			_, ok := currLogins[state]
			if !ok {
				// a cookie exists that is not for a current login, remove
				ec.MaxAge = -1
				ec.Value = ""
				http.SetCookie(w, ec)
			}
		}
	}

	return nil
}

func (c *Cookiestore) newCookie() *http.Cookie {
	nc := new(http.Cookie)
	if c.CookieTemplate != nil {
		*nc = *c.CookieTemplate
	} else {
		*nc = *DefaultCookieTemplate
	}
	return nc
}

func (c *Cookiestore) cookieNamePrefix() string {
	if c.CookieTemplate != nil {
		return c.CookieTemplate.Name
	}
	return DefaultCookieTemplate.Name
}

func peekIDT(t *oauth2.Token) (tok string, exp time.Time, _ error) {
	idt, ok := t.Extra("id_token").(string)
	if !ok {
		return "", time.Time{}, errors.New("token contains no ID token")
	}

	parts := strings.Split(idt, ".")
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
