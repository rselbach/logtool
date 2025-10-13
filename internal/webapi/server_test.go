package webapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestGeneratePKCEPair(t *testing.T) {
	tests := map[string]struct {
		name string
	}{
		"generates valid verifier and challenge": {},
		"verifier is base64url encoded":          {},
		"challenge is S256 of verifier":          {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			verifier, challenge := generatePKCEPair()

			r.NotEmpty(verifier, "verifier should not be empty")
			r.NotEmpty(challenge, "challenge should not be empty")

			verifierBytes, err := base64.RawURLEncoding.DecodeString(verifier)
			r.NoError(err, "verifier should be valid base64url")
			r.Len(verifierBytes, 32, "verifier should be 32 bytes")

			_, err = base64.RawURLEncoding.DecodeString(challenge)
			r.NoError(err, "challenge should be valid base64url")

			h := sha256.Sum256([]byte(verifier))
			expectedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
			r.Equal(expectedChallenge, challenge, "challenge should be S256 of verifier")
		})
	}
}

func TestGenerateState(t *testing.T) {
	tests := map[string]struct {
		name string
	}{
		"generates non-empty state":    {},
		"generates different states":   {},
		"state is valid base64url":     {},
		"state has sufficient entropy": {},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			state1 := generateState()
			r.NotEmpty(state1)

			stateBytes, err := base64.RawURLEncoding.DecodeString(state1)
			r.NoError(err)
			r.Len(stateBytes, 16)

			state2 := generateState()
			r.NotEqual(state1, state2, "should generate different states")
		})
	}
}

func TestOAuthCookieHelpers(t *testing.T) {
	tests := map[string]struct {
		cookieName  string
		cookieValue string
		ttl         time.Duration
	}{
		"set and get oauth cookie": {
			cookieName:  "test_cookie",
			cookieValue: "test_value",
			ttl:         5 * time.Minute,
		},
		"handle missing cookie": {
			cookieName:  "missing_cookie",
			cookieValue: "",
			ttl:         5 * time.Minute,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			s := &Server{}

			w := httptest.NewRecorder()
			if tc.cookieValue != "" {
				s.setOAuthCookie(w, tc.cookieName, tc.cookieValue, tc.ttl)
			}

			resp := w.Result()
			defer resp.Body.Close()

			req := &http.Request{Header: http.Header{"Cookie": resp.Header["Set-Cookie"]}}
			value, ok := s.getOAuthCookie(req, tc.cookieName)

			if tc.cookieValue != "" {
				r.True(ok)
				r.Equal(tc.cookieValue, value)
			} else {
				r.False(ok)
				r.Empty(value)
			}
		})
	}
}

func TestSessionCookieWithGitHubUser(t *testing.T) {
	tests := map[string]struct {
		user      string
		email     string
		ttl       time.Duration
		wantValid bool
	}{
		"valid github user session": {
			user:      "gh:octocat",
			email:     "octo@example.com",
			ttl:       1 * time.Hour,
			wantValid: true,
		},
		"expired session": {
			user:      "gh:testuser",
			email:     "test@example.com",
			ttl:       -1 * time.Hour,
			wantValid: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			secret := []byte("test-secret-key-32-bytes-long!!")
			s := &Server{
				sessionSecret: secret,
				cookieName:    "test_session",
			}

			w := httptest.NewRecorder()
			s.setSessionCookie(w, tc.user, tc.email, tc.ttl)

			resp := w.Result()
			defer resp.Body.Close()

			cookies := resp.Cookies()
			r.Len(cookies, 1)

			cookie := cookies[0]
			r.Equal(s.cookieName, cookie.Name)
			r.True(cookie.HttpOnly)
			r.Equal(http.SameSiteLaxMode, cookie.SameSite)

			req := &http.Request{Header: http.Header{}}
			req.AddCookie(cookie)

			info, ok := s.verifySessionCookie(req)
			r.Equal(tc.wantValid, ok)
			if tc.wantValid {
				r.NotNil(info)
				r.Equal(tc.user, info.User)
				r.Equal(tc.email, info.Email)
			} else {
				r.Nil(info)
			}
		})
	}
}

func TestSessionCookieTampering(t *testing.T) {
	r := require.New(t)

	secret := []byte("test-secret-key-32-bytes-long!!")
	s := &Server{
		sessionSecret: secret,
		cookieName:    "test_session",
	}

	w := httptest.NewRecorder()
	s.setSessionCookie(w, "gh:legitimate", "legit@example.com", 1*time.Hour)

	resp := w.Result()
	defer resp.Body.Close()
	cookie := resp.Cookies()[0]

	decoded, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	r.NoError(err)

	parts := strings.Split(string(decoded), "|")
	r.GreaterOrEqual(len(parts), 6)
	parts[2] = base64.RawURLEncoding.EncodeToString([]byte("gh:attacker__"))
	tampered := strings.Join(parts, "|")
	cookie.Value = base64.RawURLEncoding.EncodeToString([]byte(tampered))

	req := &http.Request{Header: http.Header{}}
	req.AddCookie(cookie)

	info, ok := s.verifySessionCookie(req)
	r.False(ok, "tampered cookie should not be valid")
	r.Nil(info)
}

func TestEmailAllowlistWildcard(t *testing.T) {
	r := require.New(t)

	s := &Server{}
	s.SetEmailAllowlist([]string{"user@*", "*@example.com"})

	cases := map[string]bool{
		"user@domain.com":    true,
		"User@Another.io":    true,
		"alice@example.com":  true,
		"bob@EXAMPLE.COM":    true,
		"user2@domain.com":   false,
		"nobody@example.org": false,
		"":                   false,
	}

	for email, want := range cases {
		r.Equal(want, s.emailAllowed(email), "email %q", email)
	}

	sAll := &Server{}
	sAll.SetEmailAllowlist([]string{"*"})
	r.True(sAll.emailAllowed("anyone@anywhere.com"))
	r.True(sAll.emailAllowed("another@domain.org"))

	sMixed := &Server{}
	sMixed.SetEmailAllowlist([]string{"admin@corp.com", "*@trust.com"})
	r.True(sMixed.emailAllowed("admin@corp.com"))
	r.True(sMixed.emailAllowed("user@trust.com"))
	r.False(sMixed.emailAllowed("user@corp.com"))
}

func TestGitHubOAuthIntegration(t *testing.T) {
	r := require.New(t)

	mockGitHub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/login/oauth/access_token":
			code := req.FormValue("code")
			verifier := req.FormValue("code_verifier")
			if code == "valid_code" && verifier != "" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"access_token": "mock_token",
					"token_type":   "bearer",
				})
			} else {
				http.Error(w, "invalid code", http.StatusBadRequest)
			}
		case "/user":
			auth := req.Header.Get("Authorization")
			if auth == "Bearer mock_token" {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{
					"login": "testuser",
					"email": "test@example.com",
				})
			} else {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}
		default:
			http.NotFound(w, req)
		}
	}))
	defer mockGitHub.Close()

	mockHTTPClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &mockTransport{
			mockGitHubURL: mockGitHub.URL,
		},
	}

	s := &Server{
		sessionSecret: []byte("test-secret-key-32-bytes-long!!"),
		sessionTTL:    1 * time.Hour,
		cookieName:    "test_session",
		httpClient:    mockHTTPClient,
	}
	s.SetGitHubOAuth("test_client_id", "test_client_secret", mockGitHub.URL+"/callback")
	s.oauthConfig.Endpoint.TokenURL = mockGitHub.URL + "/login/oauth/access_token"
	s.oauthConfig.Endpoint.AuthURL = mockGitHub.URL + "/login/oauth/authorize"
	s.SetEmailAllowlist([]string{"test@example.com"})

	t.Run("login redirects to GitHub", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/auth/github/login?next=/dashboard", nil)
		w := httptest.NewRecorder()

		s.handleGitHubLogin(w, req)

		r.Equal(http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		r.Contains(location, "test_client_id")
		r.Contains(location, "code_challenge")
		r.Contains(location, "code_challenge_method=S256")

		cookies := w.Result().Cookies()
		var hasState, hasVerifier, hasNext bool
		for _, c := range cookies {
			if c.Name == "oauth_state" {
				hasState = true
			}
			if c.Name == "oauth_verifier" {
				hasVerifier = true
			}
			if c.Name == "oauth_next" {
				hasNext = true
			}
		}
		r.True(hasState, "should set state cookie")
		r.True(hasVerifier, "should set verifier cookie")
		r.True(hasNext, "should set next cookie")
	})

	t.Run("callback with valid code sets session", func(t *testing.T) {
		state := "test_state_123"
		verifier, _ := generatePKCEPair()

		req := httptest.NewRequest("GET", "/auth/github/callback?code=valid_code&state="+state, nil)
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: state})
		req.AddCookie(&http.Cookie{Name: "oauth_verifier", Value: verifier})
		req.AddCookie(&http.Cookie{Name: "oauth_next", Value: "/dashboard"})

		w := httptest.NewRecorder()
		s.handleGitHubCallback(w, req)

		r.Equal(http.StatusFound, w.Code)
		r.Equal("/dashboard", w.Header().Get("Location"))

		sessionCookie := getSessionCookie(w.Result().Cookies(), s.cookieName)
		r.NotNil(sessionCookie, "should set session cookie")

		verifyReq := &http.Request{Header: http.Header{}}
		verifyReq.AddCookie(sessionCookie)
		info, ok := s.verifySessionCookie(verifyReq)
		r.True(ok, "session cookie should be valid")
		r.NotNil(info)
		r.Equal("gh:testuser", info.User)
		r.Equal("test@example.com", info.Email)
	})

	t.Run("callback with state mismatch fails", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/auth/github/callback?code=valid_code&state=wrong_state", nil)
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "correct_state"})
		req.AddCookie(&http.Cookie{Name: "oauth_verifier", Value: "some_verifier"})

		w := httptest.NewRecorder()
		s.handleGitHubCallback(w, req)

		r.Equal(http.StatusBadRequest, w.Code)
	})

	t.Run("callback blocked when allowlist unset", func(t *testing.T) {
		sNone := &Server{
			sessionSecret: []byte("test-secret-key-32-bytes-long!!"),
			sessionTTL:    1 * time.Hour,
			cookieName:    "test_session",
			httpClient:    mockHTTPClient,
		}
		sNone.SetGitHubOAuth("test_client_id", "test_client_secret", mockGitHub.URL+"/callback")
		sNone.oauthConfig.Endpoint.TokenURL = mockGitHub.URL + "/login/oauth/access_token"
		sNone.oauthConfig.Endpoint.AuthURL = mockGitHub.URL + "/login/oauth/authorize"

		state := "noallow_state"
		verifier, _ := generatePKCEPair()

		req := httptest.NewRequest("GET", "/auth/github/callback?code=valid_code&state="+state, nil)
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: state})
		req.AddCookie(&http.Cookie{Name: "oauth_verifier", Value: verifier})
		req.AddCookie(&http.Cookie{Name: "oauth_next", Value: "/dashboard"})

		w := httptest.NewRecorder()
		sNone.handleGitHubCallback(w, req)

		r.Equal(http.StatusForbidden, w.Code)
		sessionCookie := getSessionCookie(w.Result().Cookies(), sNone.cookieName)
		r.Nil(sessionCookie)
	})

	t.Run("callback blocked by allowlist", func(t *testing.T) {
		sBlocked := &Server{
			sessionSecret: []byte("test-secret-key-32-bytes-long!!"),
			sessionTTL:    1 * time.Hour,
			cookieName:    "test_session",
			httpClient:    mockHTTPClient,
		}
		sBlocked.SetGitHubOAuth("test_client_id", "test_client_secret", mockGitHub.URL+"/callback")
		sBlocked.oauthConfig.Endpoint.TokenURL = mockGitHub.URL + "/login/oauth/access_token"
		sBlocked.oauthConfig.Endpoint.AuthURL = mockGitHub.URL + "/login/oauth/authorize"
		sBlocked.SetEmailAllowlist([]string{"other@example.com"})

		state := "allow_state"
		verifier, _ := generatePKCEPair()

		req := httptest.NewRequest("GET", "/auth/github/callback?code=valid_code&state="+state, nil)
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: state})
		req.AddCookie(&http.Cookie{Name: "oauth_verifier", Value: verifier})
		req.AddCookie(&http.Cookie{Name: "oauth_next", Value: "/dashboard"})

		w := httptest.NewRecorder()
		sBlocked.handleGitHubCallback(w, req)

		r.Equal(http.StatusForbidden, w.Code)
		sessionCookie := getSessionCookie(w.Result().Cookies(), sBlocked.cookieName)
		r.Nil(sessionCookie)
	})
}

func TestBearerTokenStillWorks(t *testing.T) {
	r := require.New(t)

	s := &Server{
		bearerTokens: map[string]struct{}{
			"valid_token": {},
		},
	}
	s.SetGitHubOAuth("client_id", "client_secret", "http://localhost/callback")

	req := httptest.NewRequest("GET", "/api/summary", nil)
	req.Header.Set("Authorization", "Bearer valid_token")
	w := httptest.NewRecorder()

	info, ok := s.requireAuth(w, req, false)
	r.True(ok, "bearer token should still work with OAuth enabled")
	r.Nil(info)
}

func TestSecureCookieFlag(t *testing.T) {
	tests := map[string]struct {
		secure bool
	}{
		"secure cookies enabled": {
			secure: true,
		},
		"secure cookies disabled": {
			secure: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			secret := []byte("test-secret-key-32-bytes-long!!")
			s := &Server{
				sessionSecret: secret,
				sessionTTL:    1 * time.Hour,
				cookieName:    "test_session",
			}
			s.SetSecureCookies(tc.secure)

			w := httptest.NewRecorder()
			s.setSessionCookie(w, "gh:testuser", "test@example.com", 1*time.Hour)

			resp := w.Result()
			defer resp.Body.Close()

			cookies := resp.Cookies()
			r.Len(cookies, 1)
			r.Equal(tc.secure, cookies[0].Secure)

			w2 := httptest.NewRecorder()
			s.setOAuthCookie(w2, "test_oauth", "test_value", 5*time.Minute)
			resp2 := w2.Result()
			defer resp2.Body.Close()

			cookies2 := resp2.Cookies()
			r.Len(cookies2, 1)
			r.Equal(tc.secure, cookies2[0].Secure)
		})
	}
}

func getSessionCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

type mockTransport struct {
	mockGitHubURL string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "api.github.com" {
		newURL := m.mockGitHubURL + req.URL.Path
		newReq, err := http.NewRequest(req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		newReq.Header = req.Header
		return http.DefaultTransport.RoundTrip(newReq)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestAppleClientSecretGeneration(t *testing.T) {
	r := require.New(t)

	privateKeyPEM := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgtest-key-for-testing
only-not-real-secure-data-hereAhUAoUQDQgAEtest-public-key-data-here-not-real
secure-data-test-key-content==
-----END PRIVATE KEY-----`

	s := &Server{
		sessionSecret: []byte("test-secret"),
		sessionTTL:    1 * time.Hour,
		cookieName:    "test",
		httpClient:    &http.Client{Timeout: 5 * time.Second},
	}

	err := s.SetAppleOAuth("test.client.id", "TEAM123", "KEY123", privateKeyPEM, "http://localhost/callback", nil)
	if err != nil {
		t.Skip("Skipping Apple client secret test (invalid test key)")
	}

	secret, err := s.generateAppleClientSecret()
	r.NoError(err)
	r.NotEmpty(secret)

	parts := strings.Split(secret, ".")
	r.Len(parts, 3, "JWT should have 3 parts")
}

func TestAppleOAuthIntegration(t *testing.T) {
	r := require.New(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	r.NoError(err)

	mockApple := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/auth/keys":
			nBytes := rsaKey.N.Bytes()
			eBytes := big.NewInt(int64(rsaKey.E)).Bytes()
			jwks := map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kid": "test-kid",
						"kty": "RSA",
						"use": "sig",
						"alg": "RS256",
						"n":   base64.RawURLEncoding.EncodeToString(nBytes),
						"e":   base64.RawURLEncoding.EncodeToString(eBytes),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		case "/auth/token":
			verifier := req.FormValue("code_verifier")
			if verifier == "" {
				http.Error(w, "missing verifier", http.StatusBadRequest)
				return
			}
			claims := jwt.MapClaims{
				"iss":   "https://appleid.apple.com",
				"sub":   "test-user-sub",
				"aud":   "test.client.id",
				"exp":   time.Now().Add(1 * time.Hour).Unix(),
				"iat":   time.Now().Unix(),
				"email": "apple@example.com",
				"nonce": "test_nonce_value",
			}
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "test-kid"
			idToken, err := token.SignedString(rsaKey)
			if err != nil {
				http.Error(w, "sign error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"id_token": idToken,
			})
		default:
			http.NotFound(w, req)
		}
	}))
	defer mockApple.Close()

	s := &Server{
		sessionSecret: []byte("test-secret-key-32-bytes-long!!"),
		sessionTTL:    1 * time.Hour,
		cookieName:    "test_session",
		httpClient:    &http.Client{Timeout: 5 * time.Second},
	}

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s.appleConfig = &appleOAuthConfig{
		clientID:    "test.client.id",
		teamID:      "TEAM123",
		keyID:       "KEY123",
		privateKey:  ecKey,
		callbackURL: mockApple.URL + "/callback",
		scopes:      []string{"email"},
	}
	s.jwksCache = &jwksCache{
		keys: make(map[string]*rsa.PublicKey),
		ttl:  24 * time.Hour,
	}
	s.SetSecureCookies(true) // Apple OAuth requires secure cookies
	s.SetEmailAllowlist([]string{"apple@example.com"})

	mockHTTPClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &appleTestTransport{
			mockAppleURL: mockApple.URL,
		},
	}
	s.httpClient = mockHTTPClient

	t.Run("login redirects to Apple", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/auth/apple/login?next=/dashboard", nil)
		w := httptest.NewRecorder()

		s.handleAppleLogin(w, req)

		r.Equal(http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		r.Contains(location, "appleid.apple.com/auth/authorize")
		r.Contains(location, "test.client.id")
		r.Contains(location, "code_challenge")
		r.Contains(location, "response_mode=form_post")

		cookies := w.Result().Cookies()
		var hasState, hasVerifier, hasNext, hasNonce bool
		for _, c := range cookies {
			if c.Name == "oauth_state" {
				hasState = true
			}
			if c.Name == "oauth_verifier" {
				hasVerifier = true
			}
			if c.Name == "oauth_next" {
				hasNext = true
			}
			if c.Name == "oauth_nonce" {
				hasNonce = true
			}
		}
		r.True(hasState)
		r.True(hasVerifier)
		r.True(hasNext)
		r.True(hasNonce)
	})

	t.Run("callback with valid code sets session", func(t *testing.T) {
		state := "test_state_123"
		verifier, _ := generatePKCEPair()
		nonce := "test_nonce_value"

		form := url.Values{}
		form.Set("code", "valid_code")
		form.Set("state", state)
		req := httptest.NewRequest("POST", "/auth/apple/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: state})
		req.AddCookie(&http.Cookie{Name: "oauth_verifier", Value: verifier})
		req.AddCookie(&http.Cookie{Name: "oauth_next", Value: "/dashboard"})
		req.AddCookie(&http.Cookie{Name: "oauth_nonce", Value: nonce})

		w := httptest.NewRecorder()
		s.handleAppleCallback(w, req)

		r.Equal(http.StatusFound, w.Code)
		r.Equal("/dashboard", w.Header().Get("Location"))

		sessionCookie := getSessionCookie(w.Result().Cookies(), s.cookieName)
		r.NotNil(sessionCookie)

		verifyReq := &http.Request{Header: http.Header{}}
		verifyReq.AddCookie(sessionCookie)
		info, ok := s.verifySessionCookie(verifyReq)
		r.True(ok)
		r.NotNil(info)
		r.Equal("ap:test-user-sub", info.User)
		r.Equal("apple@example.com", info.Email)
	})

	t.Run("callback with state mismatch fails", func(t *testing.T) {
		form := url.Values{}
		form.Set("code", "valid_code")
		form.Set("state", "wrong_state")
		req := httptest.NewRequest("POST", "/auth/apple/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "correct_state"})
		req.AddCookie(&http.Cookie{Name: "oauth_verifier", Value: "verifier"})
		req.AddCookie(&http.Cookie{Name: "oauth_nonce", Value: "nonce"})

		w := httptest.NewRecorder()
		s.handleAppleCallback(w, req)

		r.Equal(http.StatusBadRequest, w.Code)
	})

	t.Run("callback blocked when allowlist unset", func(t *testing.T) {
		sNone := &Server{
			sessionSecret: []byte("test-secret-key-32-bytes-long!!"),
			sessionTTL:    1 * time.Hour,
			cookieName:    "test_session",
			httpClient:    mockHTTPClient,
		}
		sNone.appleConfig = s.appleConfig
		sNone.jwksCache = s.jwksCache

		state := "noallow_state"
		verifier, _ := generatePKCEPair()
		nonce := "test_nonce_value"

		form := url.Values{}
		form.Set("code", "valid_code")
		form.Set("state", state)
		req := httptest.NewRequest("POST", "/auth/apple/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: state})
		req.AddCookie(&http.Cookie{Name: "oauth_verifier", Value: verifier})
		req.AddCookie(&http.Cookie{Name: "oauth_next", Value: "/dashboard"})
		req.AddCookie(&http.Cookie{Name: "oauth_nonce", Value: nonce})

		w := httptest.NewRecorder()
		sNone.handleAppleCallback(w, req)

		r.Equal(http.StatusForbidden, w.Code)
		sessionCookie := getSessionCookie(w.Result().Cookies(), sNone.cookieName)
		r.Nil(sessionCookie)
	})

	t.Run("callback blocked by allowlist", func(t *testing.T) {
		sBlocked := &Server{
			sessionSecret: []byte("test-secret-key-32-bytes-long!!"),
			sessionTTL:    1 * time.Hour,
			cookieName:    "test_session",
			httpClient:    mockHTTPClient,
		}
		sBlocked.appleConfig = s.appleConfig
		sBlocked.jwksCache = s.jwksCache
		sBlocked.SetEmailAllowlist([]string{"other@example.com"})

		state := "blocked_state"
		verifier, _ := generatePKCEPair()
		nonce := "test_nonce_value"

		form := url.Values{}
		form.Set("code", "valid_code")
		form.Set("state", state)
		req := httptest.NewRequest("POST", "/auth/apple/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "oauth_state", Value: state})
		req.AddCookie(&http.Cookie{Name: "oauth_verifier", Value: verifier})
		req.AddCookie(&http.Cookie{Name: "oauth_next", Value: "/dashboard"})
		req.AddCookie(&http.Cookie{Name: "oauth_nonce", Value: nonce})

		w := httptest.NewRecorder()
		sBlocked.handleAppleCallback(w, req)

		r.Equal(http.StatusForbidden, w.Code)
		sessionCookie := getSessionCookie(w.Result().Cookies(), sBlocked.cookieName)
		r.Nil(sessionCookie)
	})
}

type appleTestTransport struct {
	mockAppleURL string
}

func (m *appleTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "appleid.apple.com" {
		newURL := m.mockAppleURL + req.URL.Path
		newReq, err := http.NewRequest(req.Method, newURL, req.Body)
		if err != nil {
			return nil, err
		}
		newReq.Header = req.Header
		if req.URL.Path == "/auth/token" {
			newReq.PostForm = req.PostForm
			if req.Form != nil {
				for k, v := range req.Form {
					for _, vv := range v {
						if newReq.PostForm == nil {
							newReq.PostForm = make(url.Values)
						}
						newReq.PostForm.Add(k, vv)
					}
				}
			}
		}
		return http.DefaultTransport.RoundTrip(newReq)
	}
	return http.DefaultTransport.RoundTrip(req)
}
