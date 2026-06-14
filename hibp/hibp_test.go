package hibp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tamnd/hibp-cli/hibp"
)

// mockBreach is a synthetic breach record matching HIBP's PascalCase JSON.
var mockBreach = map[string]any{
	"Name":         "Adobe",
	"Title":        "Adobe",
	"Domain":       "adobe.com",
	"BreachDate":   "2013-10-04",
	"AddedDate":    "2013-12-04T00:00:00Z",
	"PwnCount":     152445165,
	"Description":  "In October 2013, 153 million Adobe accounts...",
	"DataClasses":  []string{"Email addresses", "Password hints", "Passwords", "Usernames"},
	"IsVerified":   true,
	"IsFabricated": false,
	"IsSensitive":  false,
	"IsRetired":    false,
	"IsSpamList":   false,
	"IsMalware":    false,
}

func newTestClient(srv *httptest.Server) *hibp.Client {
	c := hibp.NewClient()
	c.BaseURL = srv.URL
	c.Rate = 0
	return c
}

func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestListBreaches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/breaches" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		jsonResponse(w, []any{mockBreach})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	breaches, err := c.ListBreaches(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(breaches) != 1 {
		t.Fatalf("got %d breaches, want 1", len(breaches))
	}
	b := breaches[0]
	if b.Name != "Adobe" {
		t.Errorf("Name = %q, want Adobe", b.Name)
	}
	if b.Domain != "adobe.com" {
		t.Errorf("Domain = %q, want adobe.com", b.Domain)
	}
	if b.PwnCount != 152445165 {
		t.Errorf("PwnCount = %d, want 152445165", b.PwnCount)
	}
	if !b.IsVerified {
		t.Error("expected IsVerified=true")
	}
	if len(b.DataClasses) != 4 {
		t.Errorf("DataClasses len = %d, want 4", len(b.DataClasses))
	}
}

func TestListBreachesByDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/breaches" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("domain") != "adobe.com" {
			t.Errorf("expected domain=adobe.com, got %s", r.URL.Query().Get("domain"))
		}
		jsonResponse(w, []any{mockBreach})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	breaches, err := c.ListBreaches(context.Background(), "adobe.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(breaches) != 1 {
		t.Fatalf("got %d breaches, want 1", len(breaches))
	}
}

func TestGetBreach(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/breach/Adobe" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		jsonResponse(w, mockBreach)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	b, err := c.GetBreach(context.Background(), "Adobe")
	if err != nil {
		t.Fatal(err)
	}
	if b.Name != "Adobe" {
		t.Errorf("Name = %q, want Adobe", b.Name)
	}
	if b.Title != "Adobe" {
		t.Errorf("Title = %q, want Adobe", b.Title)
	}
	if b.BreachDate != "2013-10-04" {
		t.Errorf("BreachDate = %q, want 2013-10-04", b.BreachDate)
	}
}

func TestGetBreachNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.GetBreach(context.Background(), "NonExistentBreach")
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestListDataClasses(t *testing.T) {
	classes := []string{
		"Academic records",
		"Account balances",
		"Age groups",
		"Email addresses",
		"Passwords",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/dataclasses" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		jsonResponse(w, classes)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	got, err := c.ListDataClasses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(classes) {
		t.Fatalf("got %d classes, want %d", len(got), len(classes))
	}
	for i, dc := range got {
		if dc.Name != classes[i] {
			t.Errorf("classes[%d].Name = %q, want %q", i, dc.Name, classes[i])
		}
	}
}

func TestRetryOn503(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		jsonResponse(w, []any{mockBreach})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.Retries = 5

	breaches, err := c.ListBreaches(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(breaches) == 0 {
		t.Error("expected breaches after retries")
	}
	if hits != 3 {
		t.Errorf("server saw %d hits, want 3", hits)
	}
}

func TestUserAgentHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua == "" {
			t.Error("missing User-Agent header")
		}
		jsonResponse(w, []string{"Email addresses"})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.ListDataClasses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}
