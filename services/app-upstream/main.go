package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

//go:embed templates/*
var templatesFS embed.FS

var tpl = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

// WhoamiResponse is a generic structure we’ll JSON-encode.
// It includes identity basics and, when present, raw AD PAC data.
type WhoamiResponse struct {
	Authenticated bool                   `json:"authenticated"`
	UserName      string                 `json:"userName,omitempty"`
	Domain        string                 `json:"domain,omitempty"`
	DisplayName   string                 `json:"displayName,omitempty"`
	AuthTime      *time.Time             `json:"authTime,omitempty"`
	AuthzAttrs    []string               `json:"authzAttributes,omitempty"`
	ClientAddr    string                 `json:"clientAddr,omitempty"`
	ADPAC         interface{}            `json:"adPac,omitempty"` // raw ADCredentials struct when AD issues PAC
	Attributes    map[string]interface{} `json:"attributes,omitempty"`
	Bare          string                 `json:"spnego,omitempty"`
}

type Echo struct {
	Now      time.Time           `json:"now"`
	Method   string              `json:"method"`
	Path     string              `json:"path"`
	Query    map[string][]string `json:"query"`
	Form     map[string][]string `json:"form"`
	Headers  map[string][]string `json:"headers"`
	Body     string              `json:"body,omitempty"`
	ClientIP string              `json:"clientIP"`
	User     *WhoamiResponse     `json:"user,omitempty"`
}

/* ----------------------- Session support (optional) ----------------------- */

type sessionData struct {
	User   *WhoamiResponse
	Expiry time.Time
}

var (
	useSession    = getenvBool("USE_SESSION", false)
	sessionTTL    = getenvDuration("SESSION_TTL", 8*time.Hour)
	sessionCookie = getenv("SESSION_COOKIE", "app_session")
	sessionStore  = struct {
		mu sync.RWMutex
		m  map[string]sessionData
	}{m: make(map[string]sessionData)}
)

// getSession returns session user if valid (and refreshes TTL if sliding window desired)
func getSession(r *http.Request) *WhoamiResponse {
	if !useSession {
		return nil
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || c == nil || c.Value == "" {
		return nil
	}
	sessionStore.mu.RLock()
	sd, ok := sessionStore.m[c.Value]
	sessionStore.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(sd.Expiry) {
		// expired: clean it up
		sessionStore.mu.Lock()
		delete(sessionStore.m, c.Value)
		sessionStore.mu.Unlock()
		return nil
	}
	return sd.User
}

// setSession creates a session (sid cookie + server-side map)
func setSession(w http.ResponseWriter, u *WhoamiResponse) {
	if !useSession || u == nil || !u.Authenticated {
		return
	}
	// generate random 32-byte id
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Printf("session id generation failed: %v", err)
		return
	}
	sid := hex.EncodeToString(b)
	exp := time.Now().Add(sessionTTL)

	// persist server-side
	sessionStore.mu.Lock()
	sessionStore.m[sid] = sessionData{User: u, Expiry: exp}
	sessionStore.mu.Unlock()

	// secure-ish defaults; tweak as needed
	c := &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure should be true in HTTPS; keep env control if needed
		Secure: getenvBool("SESSION_SECURE", false),
	}
	http.SetCookie(w, c)
}

func clearSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err == nil && c != nil {
		sessionStore.mu.Lock()
		delete(sessionStore.m, c.Value)
		sessionStore.mu.Unlock()
	}
	// expire the browser cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   getenvBool("SESSION_SECURE", false),
	})
}

/* ------------------------------------------------------------------------- */

func wrapUnauthorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		rr := httptest.NewRecorder()
		next.ServeHTTP(rr, r)

		status := rr.Code

		// If it's 401, replace the body but keep headers (esp. WWW-Authenticate).
		if status == http.StatusUnauthorized {
			// Copy headers first.
			for k, vals := range rr.Header() {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}

			// Make sure content length matches our custom body.
			w.Header().Del("Content-Length")
			w.Header().Del("Content-Type")

			// Ensure the SPNEGO challenge header is present.
			if w.Header().Get("WWW-Authenticate") == "" {
				w.Header().Add("WWW-Authenticate", "Negotiate")
			}
			w.WriteHeader(http.StatusUnauthorized)
			_ = tpl.ExecuteTemplate(w, "unauthorized.html", nil)
			return
		}

		// Otherwise, pass through as-is.
		for k, vals := range rr.Header() {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(status)
		_, _ = io.Copy(w, rr.Body)
	})
}

func whoamiFromRequest(r *http.Request) *WhoamiResponse {
	// 1) If sessions are enabled and valid, prefer them (bypass SPNEGO requirement).
	if u := getSession(r); u != nil {
		return u
	}

	// 2) Fall back to SPNEGO-provided identity (ctx from middleware).
	creds := goidentity.FromHTTPRequestContext(r)
	if creds == nil {
		return &WhoamiResponse{Authenticated: false}
	}
	authTime := creds.AuthTime()
	resp := &WhoamiResponse{
		Authenticated: true,
		ClientAddr:    r.RemoteAddr,
		UserName:      creds.UserName(),
		Domain:        creds.Domain(),
		DisplayName:   creds.DisplayName(),
		AuthTime:      &authTime,
		AuthzAttrs:    creds.AuthzAttributes(),
		Bare:          fmt.Sprintf("%+v", creds),
	}
	resp.Attributes = creds.(interface{ Attributes() map[string]interface{} }).Attributes()
	if attrs := resp.Attributes; attrs != nil {
		if ad, ok := attrs[fmt.Sprintf("%d", credentials.AttributeKeyADCredentials)]; ok {
			resp.ADPAC = ad
		} else if ad2, ok := attrs[credentials.AttributeKeyADCredentials]; ok {
			resp.ADPAC = ad2
		}
	}
	return resp
}

func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	resp := whoamiFromRequest(r)
	if !resp.Authenticated {
		http.Error(w, "Unauthorised.\n", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

// indexHandler renders the bootstrap test UI.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	user := whoamiFromRequest(r)
	if !user.Authenticated {
		w.WriteHeader(http.StatusUnauthorized)
		_ = tpl.ExecuteTemplate(w, "unauthorized.html", nil)
		return
	}
	data := map[string]any{
		"Now":     time.Now(),
		"User":    user,
		"Headers": r.Header,
	}
	if err := tpl.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// testHandler produces HTML, JSON or a file, and supports GET/POST with or without query params.
func testHandler(w http.ResponseWriter, r *http.Request) {
	user := whoamiFromRequest(r)
	if !user.Authenticated {
		http.Error(w, "Unauthorised.\n", http.StatusUnauthorized)
		return
	}

	f := readForm(r)
	q := r.URL.Query()
	respKind := strings.ToLower(q.Get("resp"))
	if respKind == "" {
		respKind = "html"
	}
	status := http.StatusOK
	if v := firstNonEmpty(q.Get("status"), r.Form.Get("status")); v != "" {
		if s, err := parseStatus(v); err == nil {
			status = s
		}
	}

	// echo payload
	headers := map[string][]string{}
	for k, v := range r.Header {
		headers[k] = append([]string(nil), v...)
	}
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20)) // cap 1MB
		body = string(b)
	}
	e := Echo{
		Now:      time.Now(),
		Method:   r.Method,
		Path:     r.URL.Path,
		Query:    copyValues(q),
		Form:     f,
		Headers:  headers,
		Body:     body,
		ClientIP: r.RemoteAddr,
		User:     user,
	}

	switch respKind {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(e)
	case "file":
		filename := firstNonEmpty(q.Get("filename"), r.Form.Get("filename"))
		if filename == "" {
			filename = "test"
		}
		ftype := strings.ToLower(firstNonEmpty(q.Get("type"), r.Form.Get("type")))
		if ftype == "" {
			ftype = "txt"
		}
		var content []byte
		var ctype string
		switch ftype {
		case "csv":
			ctype = "text/csv"
			content = []byte("col1,col2\nvalue1,value2\n")
			if !strings.HasSuffix(strings.ToLower(filename), ".csv") {
				filename += ".csv"
			}
		case "json":
			ctype = "application/json"
			b, _ := json.MarshalIndent(e, "", "  ")
			content = b
			if !strings.HasSuffix(strings.ToLower(filename), ".json") {
				filename += ".json"
			}
		default:
			ctype = "text/plain"
			content = []byte("This is a test file from /test?resp=file\n")
			if !strings.HasSuffix(strings.ToLower(filename), ".txt") {
				filename += ".txt"
			}
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		w.WriteHeader(status)
		_, _ = w.Write(content)
	default: // html
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_ = tpl.ExecuteTemplate(w, "echo.html", map[string]any{
			"Echo": e,
		})
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func parseStatus(s string) (int, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "200", "OK":
		return http.StatusOK, nil
	case "201", "CREATED":
		return http.StatusCreated, nil
	case "204", "NO_CONTENT":
		return http.StatusNoContent, nil
	case "301", "MOVED_PERMANENTLY":
		return http.StatusMovedPermanently, nil
	case "302", "FOUND":
		return http.StatusFound, nil
	case "400", "BAD_REQUEST":
		return http.StatusBadRequest, nil
	case "401", "UNAUTHORIZED":
		return http.StatusUnauthorized, nil
	case "403", "FORBIDDEN":
		return http.StatusForbidden, nil
	case "404", "NOT_FOUND":
		return http.StatusNotFound, nil
	case "418", "I_AM_A_TEAPOT":
		return 418, nil
	case "500", "INTERNAL_SERVER_ERROR":
		return http.StatusInternalServerError, nil
	default:
		var n int
		_, err := fmt.Sscanf(s, "%d", &n)
		if err != nil {
			return http.StatusOK, err
		}
		return n, nil
	}
}

func copyValues(v map[string][]string) map[string][]string {
	out := make(map[string][]string, len(v))
	for k, arr := range v {
		out[k] = append([]string(nil), arr...)
		sort.Strings(out[k]) // stable output
	}
	return out
}

func main() {
	// Config via env:
	// KEYTAB: path to keytab with HTTP/<fqdn>@REALM entry (default /etc/krb5.keytab)
	// SPN:    optional override for keytab principal (e.g., HTTP/web01.example.com@EXAMPLE.COM)
	// BIND:   address to bind (default :8080)
	// USE_SESSION: enable cookie-based session reuse (default false)
	keytabPath := getenv("KEYTAB", "/etc/krb5.keytab")
	spn := getenv("SPN", "HTTP/kerb-app.example.local")
	bind := getenv("BIND", ":8080")

	kt, err := keytab.Load(keytabPath)
	if err != nil {
		log.Fatalf("failed to load keytab %s: %v", keytabPath, err)
	}

	settings := []func(*service.Settings){
		service.Logger(log.Default()),
	}
	if spn != "" {
		settings = append(settings, service.KeytabPrincipal(spn))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/whoami", whoamiHandler)
	mux.HandleFunc("/test", testHandler)

	// Middleware that issues a session after a successful SPNEGO-authenticated request
	issueSessionMiddleware := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// allow handlers to run first, but we need to set cookie BEFORE body is written.
		// So we check identity up front; if SPNEGO has set creds (no session cookie yet), we set session immediately.
		// However, SPNEGO middleware runs before this; at this point, creds (if any) are in ctx.
		if useSession {
			if _, err := r.Cookie(sessionCookie); err != nil {
				// only create a session when the identity came from SPNEGO this round
				if creds := goidentity.FromHTTPRequestContext(r); creds != nil {
					// Build a WhoamiResponse snapshot to store
					authTime := creds.AuthTime()
					u := &WhoamiResponse{
						Authenticated: true,
						ClientAddr:    r.RemoteAddr,
						UserName:      creds.UserName(),
						Domain:        creds.Domain(),
						DisplayName:   creds.DisplayName(),
						AuthTime:      &authTime,
						AuthzAttrs:    creds.AuthzAttributes(),
						Bare:          fmt.Sprintf("%+v", creds),
						Attributes:    creds.(interface{ Attributes() map[string]interface{} }).Attributes(),
					}
					// If we already have PAC in attributes, keep it
					if attrs := u.Attributes; attrs != nil {
						if ad, ok := attrs[fmt.Sprintf("%d", credentials.AttributeKeyADCredentials)]; ok {
							u.ADPAC = ad
						} else if ad2, ok := attrs[credentials.AttributeKeyADCredentials]; ok {
							u.ADPAC = ad2
						}
					}
					setSession(w, u)
				}
			}
		}
	})

	// SPNEGO-protected app (runs AFTER session bypass check)
	protected := spnego.SPNEGOKRB5Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Once SPNEGO has authenticated and placed creds in ctx, run issueSessionMiddleware then app
		issueSessionMiddleware.ServeHTTP(w, r)
		mux.ServeHTTP(w, r)
	}), kt, settings...)

	// Session bypass: if a valid session cookie exists, skip SPNEGO entirely.
	var entry http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if useSession {
			if u := getSession(r); u != nil && u.Authenticated {
				// direct to app, no SPNEGO challenge
				mux.ServeHTTP(w, r)
				return
			}
		}
		// otherwise, go through SPNEGO
		protected.ServeHTTP(w, r)
	})

	customProtected := wrapUnauthorized(entry)
	log.Printf("Kerberos test app listening on %s (keytab=%s, spn=%s, use_session=%v, session_cookie=%s, ttl=%s)",
		bind, keytabPath, spn, useSession, sessionCookie, sessionTTL)
	log.Fatal(http.ListenAndServe(bind, customProtected))
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getenvBool(k string, d bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(k)))
	if v == "1" || v == "true" || v == "yes" || v == "y" {
		return true
	}
	if v == "0" || v == "false" || v == "no" || v == "n" {
		return false
	}
	return d
}

func getenvDuration(k string, d time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if dur, err := time.ParseDuration(v); err == nil {
			return dur
		}
	}
	return d
}

func readForm(r *http.Request) map[string][]string {
	err1 := r.ParseMultipartForm(10 << 20)
	err2 := r.ParseForm()
	if err1 != nil && err2 != nil {
		return nil
	}

	values := make(map[string][]string)
	for key, vals := range r.Form {
		values[key] = vals
	}

	return values
}
