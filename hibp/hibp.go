// Package hibp is the library behind the hibp command line:
// the HTTP client, request shaping, and the typed data models for the
// HaveIBeenPwned Pwned Passwords API.
//
// The Client uses k-anonymity: only the first 5 characters of a SHA1 hash are
// sent to the API, so the full password is never transmitted.
package hibp

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultUserAgent identifies the client to the API.
const DefaultUserAgent = "hibp-cli/0.1.0 (github.com/tamnd/hibp-cli)"

// Host is the API host.
const Host = "api.pwnedpasswords.com"

// BaseURL is the root every request is built from.
const BaseURL = "https://" + Host

// Config holds the client configuration.
type Config struct {
	BaseURL   string
	UserAgent string
	Rate      time.Duration
	Timeout   time.Duration
	Retries   int
}

// DefaultConfig returns sensible defaults for the HIBP Pwned Passwords API.
func DefaultConfig() Config {
	return Config{
		BaseURL:   BaseURL,
		UserAgent: DefaultUserAgent,
		Rate:      200 * time.Millisecond,
		Timeout:   15 * time.Second,
		Retries:   3,
	}
}

// CheckResult is the output of a password check.
type CheckResult struct {
	Password   string `json:"password"`    // masked: first 2 + "..." + last 2, or all "*"
	SHA1Prefix string `json:"sha1_prefix"` // first 5 chars sent to API
	PwnedCount int    `json:"pwned_count"` // 0 = not found
	Pwned      bool   `json:"pwned"`
}

// HashEntry is one line in a /range response.
type HashEntry struct {
	Suffix string `json:"suffix"`
	Count  int    `json:"count"`
}

// Client talks to the HIBP Pwned Passwords API.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	BaseURL   string
	// Rate is the minimum gap between requests. Zero means no pacing.
	Rate    time.Duration
	Retries int

	last time.Time
}

// NewClient returns a Client with sensible defaults.
func NewClient() *Client {
	cfg := DefaultConfig()
	return &Client{
		HTTP:      &http.Client{Timeout: cfg.Timeout},
		UserAgent: cfg.UserAgent,
		BaseURL:   cfg.BaseURL,
		Rate:      cfg.Rate,
		Retries:   cfg.Retries,
	}
}

// NewClientFromConfig returns a Client configured from a Config.
func NewClientFromConfig(cfg Config) *Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = BaseURL
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		HTTP:      &http.Client{Timeout: timeout},
		UserAgent: cfg.UserAgent,
		BaseURL:   cfg.BaseURL,
		Rate:      cfg.Rate,
		Retries:   cfg.Retries,
	}
}

// Range queries /range/{prefix} and returns all hash suffix entries.
// prefix must be exactly 5 uppercase hex characters.
func (c *Client) Range(ctx context.Context, prefix string) ([]HashEntry, error) {
	prefix = strings.ToUpper(prefix)
	url := c.BaseURL + "/range/" + prefix
	body, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	return parseRange(body), nil
}

// Check hashes the password, queries /range/{prefix} using k-anonymity,
// and returns how many times the password has appeared in known breaches.
func (c *Client) Check(ctx context.Context, password string) (*CheckResult, error) {
	h := sha1.Sum([]byte(password))
	full := fmt.Sprintf("%X", h)
	prefix := full[:5]
	suffix := full[5:]

	entries, err := c.Range(ctx, prefix)
	if err != nil {
		return nil, err
	}

	var count int
	for _, e := range entries {
		if strings.EqualFold(e.Suffix, suffix) {
			count = e.Count
			break
		}
	}

	return &CheckResult{
		Password:   maskPassword(password),
		SHA1Prefix: prefix,
		PwnedCount: count,
		Pwned:      count > 0,
	}, nil
}

// maskPassword masks a password for safe display.
// If len > 4: show first 2 + "..." + last 2.
// Otherwise: all "*".
func maskPassword(p string) string {
	if len(p) > 4 {
		return p[:2] + "..." + p[len(p)-2:]
	}
	return strings.Repeat("*", len(p))
}

// parseRange parses the plain-text /range response.
// Each line: UPPERCASE_HEX_SUFFIX:COUNT
func parseRange(body []byte) []HashEntry {
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	out := make([]HashEntry, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		suffix := strings.TrimSpace(line[:idx])
		countStr := strings.TrimSpace(line[idx+1:])
		count, err := strconv.Atoi(countStr)
		if err != nil {
			continue
		}
		out = append(out, HashEntry{Suffix: suffix, Count: count})
	}
	return out
}

// get fetches a URL with pacing and retries.
func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		body, retry, err := c.do(ctx, url)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retry {
			return nil, err
		}
	}
	return nil, fmt.Errorf("get %s: %w", url, lastErr)
}

func (c *Client) do(ctx context.Context, url string) (body []byte, retry bool, err error) {
	c.pace()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Add-Padding", "true")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return nil, true, fmt.Errorf("http %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("http %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, true, err
	}
	return b, false, nil
}

// pace blocks until at least Rate has passed since the previous request.
func (c *Client) pace() {
	if c.Rate <= 0 {
		return
	}
	if wait := c.Rate - time.Since(c.last); wait > 0 {
		time.Sleep(wait)
	}
	c.last = time.Now()
}

func backoff(attempt int) time.Duration {
	d := time.Duration(attempt) * 500 * time.Millisecond
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}
