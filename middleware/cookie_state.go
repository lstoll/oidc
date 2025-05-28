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
)

type CookieOpts struct {
	// Prefix is used to prefix the cookies used by this store. It will use
	// multiple cookies under this.
	Prefix   string
	Path     string
	Secure   bool
	SameSite http.SameSite
	// Persist is used to control if the cookie is persisted across browser
	// sessions. If true, the cookie expiration will be set based ok the login
	// or token lifetime. If false, the cookie will be set to expire when the
	// browser is closed.
	Persist bool
}

var DefaultCookieOpts = CookieOpts{
	Prefix:   "__HOST-auth",
	Path:     "/",
	Secure:   true,
	SameSite: http.SameSiteLaxMode,
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

	idtc, err := r.Cookie(c.cookieNamePrefix())
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
			if time.Now().Unix() > int64(exp) {
				// ignore expired entries
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
		if tc, err := r.Cookie(c.cookieNamePrefix()); err != nil || tc.Value != tok {
			// no existing cookie for this, save it
			tc := c.newCookie("", exp)
			tc.Value = tok
			http.SetCookie(w, tc)
		}
	} else {
		dc := c.newCookie("", time.Time{})
		dc.Name = c.cookieNamePrefix()
		dc.MaxAge = -1
		http.SetCookie(w, dc)
	}

	// track current logins, so we can reconcile and delete other
	currLogins := map[string]struct{}{}
	for _, l := range d.Logins {
		if time.Now().Unix() > int64(l.Expires) {
			// ignore expired entries
			continue
		}
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
			// we track it explicitly, to allow cleanup in login sessions
			v.Set("ex", strconv.Itoa(l.Expires))
			lc := c.newCookie(loginCookiePrefix+l.State, time.Unix(int64(l.Expires), 0))
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

func (c *Cookiestore) newCookie(suffix string, exp time.Time) *http.Cookie {
	ct := c.CookieOpts
	if ct == nil {
		ct = &DefaultCookieOpts
	}
	nc := &http.Cookie{
		Name:     ct.Prefix + suffix,
		Path:     ct.Path,
		Secure:   ct.Secure,
		SameSite: ct.SameSite,
	}
	if ct.Persist {
		nc.Expires = exp
	}
	return nc
}

func (c *Cookiestore) cookieNamePrefix() string {
	if c.CookieOpts != nil {
		return c.CookieOpts.Prefix
	}
	return DefaultCookieOpts.Prefix
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
