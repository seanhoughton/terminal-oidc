package auth

import (
	"sync"

	"golang.org/x/oauth2"
)

// Code from https://github.com/golang/oauth2/issues/84#issuecomment-332517319

// TokenNotifyFunc is a function that accepts an oauth2 Token upon refresh, and
// returns an error if it should not be used.
type TokenNotifyFunc func(*oauth2.Token) error

// notifyRefreshTokenSource is essentially `oauth2.ResuseTokenSource` with `TokenNotifyFunc` added.
type notifyRefreshTokenSource struct {
	new oauth2.TokenSource
	mu  sync.Mutex // guards t
	t   *oauth2.Token
	f   TokenNotifyFunc // called when token refreshed so new refresh token can be persisted
}

func NotifyRefreshTokenSource(t *oauth2.Token, src oauth2.TokenSource, f TokenNotifyFunc) oauth2.TokenSource {
	return &notifyRefreshTokenSource{
		new: src,
		f:   f,
	}
}

// Token returns the current token if it's still valid, else will
// refresh the current token (using r.Context for HTTP client
// information) and return the new one.
func (s *notifyRefreshTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.t.Valid() {
		return s.t, nil
	}
	t, err := s.new.Token()
	if err != nil {
		return nil, err
	}
	s.t = t
	return t, s.f(t)
}
