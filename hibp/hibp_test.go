package hibp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tamnd/hibp-cli/hibp"
)

// mockRangeBody is a synthetic /range/5BAA6 response.
// SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
// prefix = 5BAA6, suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
const mockRangeBody = `1E4C9B93F3F0682250B6CF8331B7EE68FD8:10659000
0018A45C4D1DEF81644B54AB7F969B88D65:1
003CD215739D7C1B2218670D26F81408237:2
003D68EB55068C33ACE09247EE4C639306B:29
`

func newTestServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
}

func newClient(baseURL string) *hibp.Client {
	c := hibp.NewClient()
	c.BaseURL = baseURL
	c.Rate = 0
	return c
}

func TestRangeQuery(t *testing.T) {
	srv := newTestServer(mockRangeBody)
	defer srv.Close()

	c := newClient(srv.URL)
	entries, err := c.Range(context.Background(), "5BAA6")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(entries))
	}
	// First entry should be the "password" suffix
	if entries[0].Suffix != "1E4C9B93F3F0682250B6CF8331B7EE68FD8" {
		t.Errorf("first suffix = %q, want 1E4C9B93F3F0682250B6CF8331B7EE68FD8", entries[0].Suffix)
	}
	if entries[0].Count != 10659000 {
		t.Errorf("first count = %d, want 10659000", entries[0].Count)
	}
}

func TestCheckFoundPassword(t *testing.T) {
	// SHA1("password") prefix = 5BAA6
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// verify the prefix is sent in the URL path
		if !strings.HasSuffix(r.URL.Path, "/5BAA6") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(mockRangeBody))
	}))
	defer srv.Close()

	c := newClient(srv.URL)
	result, err := c.Check(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Pwned {
		t.Error("expected Pwned=true for 'password'")
	}
	if result.PwnedCount != 10659000 {
		t.Errorf("PwnedCount = %d, want 10659000", result.PwnedCount)
	}
	if result.SHA1Prefix != "5BAA6" {
		t.Errorf("SHA1Prefix = %q, want 5BAA6", result.SHA1Prefix)
	}
}

func TestCheckNotFoundPassword(t *testing.T) {
	// Use a response that does NOT contain the suffix for "uniquepasswordxyz123"
	srv := newTestServer(mockRangeBody)
	defer srv.Close()

	c := newClient(srv.URL)
	// Use a password whose suffix won't be in mockRangeBody
	result, err := c.Check(context.Background(), "uniquepasswordxyz123notinresponse")
	if err != nil {
		t.Fatal(err)
	}
	if result.Pwned {
		t.Error("expected Pwned=false for unknown password")
	}
	if result.PwnedCount != 0 {
		t.Errorf("PwnedCount = %d, want 0", result.PwnedCount)
	}
}

func TestPasswordMasking(t *testing.T) {
	srv := newTestServer(mockRangeBody)
	defer srv.Close()

	c := newClient(srv.URL)

	cases := []struct {
		password string
		wantMask string
	}{
		{"password", "pa...rd"},
		{"hello", "he...lo"},
		{"abcd", "****"},   // len == 4: all stars
		{"abc", "***"},     // len == 3: all stars
		{"ab", "**"},       // len == 2: all stars
		{"abcde", "ab...de"}, // len == 5: first 2 + ... + last 2
	}

	for _, tc := range cases {
		result, err := c.Check(context.Background(), tc.password)
		if err != nil {
			t.Fatalf("Check(%q): %v", tc.password, err)
		}
		if result.Password != tc.wantMask {
			t.Errorf("Check(%q).Password = %q, want %q", tc.password, result.Password, tc.wantMask)
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
		_, _ = w.Write([]byte(mockRangeBody))
	}))
	defer srv.Close()

	c := newClient(srv.URL)
	c.Retries = 5

	entries, err := c.Range(context.Background(), "5BAA6")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Error("expected entries after retries")
	}
	if hits != 3 {
		t.Errorf("server saw %d hits, want 3", hits)
	}
}

func TestRangeEmptyResponse(t *testing.T) {
	srv := newTestServer("")
	defer srv.Close()

	c := newClient(srv.URL)
	entries, err := c.Range(context.Background(), "AAAAA")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty response, got %d", len(entries))
	}
}
