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
	loginCookiePrefix = "s-"
	tokenCookieSuffix = "-t"
)

type Cookiestore struct {
	// CookieTemplate is used to create the cookie we track the session ID in.
	// It must have at least the name set.
	CookieTemplate *http.Cookie
}

// NewMemorySessionStore creates a simple session store, that tracks state in
// memory. It is mainly used for testing, it is not suitable for anything
// outside a single process as the state will not be shared. It also does not
// have robust cleaning of stored session data.
//
// It is provided with a "template" http.Cookie - this will be used for the
// cookies the session ID is tracked with. It must have at least a name set.
func NewMemorySessionStore(template http.Cookie) (SessionStore, error) {
	if template.Name == "" {
		return nil, fmt.Errorf("template must have a name")
	}
	return &Cookiestore{
		CookieTemplate: &template,
	}, nil
}

func (c *Cookiestore) Get(r *http.Request) (*SessionData, error) {
	sd := &SessionData{}

	idtc, err := r.Cookie(c.CookieTemplate.Name + tokenCookieSuffix)
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
		if strings.HasPrefix(ec.Name, c.CookieTemplate.Name+loginCookiePrefix) {
			state := strings.TrimPrefix(ec.Name, c.CookieTemplate.Name+loginCookiePrefix)
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

func (c *Cookiestore) Save(w http.ResponseWriter, r *http.Request, d *SessionData) error {
	if d.Token != nil {
		tok, exp, err := peekIDT(d.Token.Token)
		if err != nil {
			return fmt.Errorf("processing id_token: %w", err)
		}
		if tc, err := r.Cookie(c.CookieTemplate.Name + tokenCookieSuffix); err != nil || tc.Value != tok {
			// no existing cookie for this, save it
			tc := c.newCookie()
			tc.Name = c.CookieTemplate.Name + tokenCookieSuffix
			tc.Expires = exp
			tc.Value = tok
			http.SetCookie(w, tc)
		}
	} else {
		dc := c.newCookie()
		dc.Name = c.CookieTemplate.Name + tokenCookieSuffix
		dc.MaxAge = -1
		http.SetCookie(w, dc)
	}

	// track current logins, so we can reconcile and delete other
	currLogins := map[string]struct{}{}
	for _, l := range d.Logins {
		currLogins[l.State] = struct{}{}
		_, err := r.Cookie(c.CookieTemplate.Name + loginCookiePrefix + l.State)
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
			lc.Name = c.CookieTemplate.Name + loginCookiePrefix + l.State
			lc.Value = v.Encode()
			http.SetCookie(w, lc)
		}
	}
	for _, ec := range r.Cookies() {
		if strings.HasPrefix(ec.Name, c.CookieTemplate.Name+loginCookiePrefix) {
			state := strings.TrimPrefix(ec.Name, c.CookieTemplate.Name+loginCookiePrefix)
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
	*nc = *c.CookieTemplate
	return nc
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
