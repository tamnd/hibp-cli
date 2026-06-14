// Package hibp is the library behind the hibp command line:
// the HTTP client, request shaping, and the typed data models for the
// HaveIBeenPwned API (haveibeenpwned.com).
//
// No API key is required for the breach and data-class endpoints.
package hibp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Host is the HIBP API host.
const Host = "haveibeenpwned.com"

// BaseURL is the root every request is built from.
const BaseURL = "https://" + Host

// Config holds the client configuration.
type Config struct {
	BaseURL string
	Rate    time.Duration
	Retries int
	Timeout time.Duration
}

// DefaultConfig returns sensible defaults for the HIBP API. HIBP is sensitive
// to rate limits, so the default rate is 1500ms between requests.
func DefaultConfig() Config {
	return Config{
		BaseURL: BaseURL,
		Rate:    1500 * time.Millisecond,
		Retries: 3,
		Timeout: 30 * time.Second,
	}
}

// Breach is a data breach record returned by the HIBP API.
type Breach struct {
	Name         string   `kit:"id" json:"name"`
	Title        string   `json:"title"`
	Domain       string   `json:"domain"`
	BreachDate   string   `json:"breach_date"`
	AddedDate    string   `json:"added_date"`
	PwnCount     int      `json:"pwn_count"`
	Description  string   `json:"description"`
	DataClasses  []string `json:"data_classes"`
	IsVerified   bool     `json:"is_verified"`
	IsFabricated bool     `json:"is_fabricated"`
	IsSensitive  bool     `json:"is_sensitive"`
	IsRetired    bool     `json:"is_retired"`
	IsSpamList   bool     `json:"is_spam_list"`
	IsMalware    bool     `json:"is_malware"`
}

// DataClass is a single data class type string returned by the HIBP API.
type DataClass struct {
	Name string `kit:"id" json:"name"`
}

// wireBreach maps the HIBP API's PascalCase JSON fields to our Breach type.
type wireBreach struct {
	Name         string   `json:"Name"`
	Title        string   `json:"Title"`
	Domain       string   `json:"Domain"`
	BreachDate   string   `json:"BreachDate"`
	AddedDate    string   `json:"AddedDate"`
	PwnCount     int      `json:"PwnCount"`
	Description  string   `json:"Description"`
	DataClasses  []string `json:"DataClasses"`
	IsVerified   bool     `json:"IsVerified"`
	IsFabricated bool     `json:"IsFabricated"`
	IsSensitive  bool     `json:"IsSensitive"`
	IsRetired    bool     `json:"IsRetired"`
	IsSpamList   bool     `json:"IsSpamList"`
	IsMalware    bool     `json:"IsMalware"`
}

func (w wireBreach) toBreach() Breach {
	return Breach{
		Name:         w.Name,
		Title:        w.Title,
		Domain:       w.Domain,
		BreachDate:   w.BreachDate,
		AddedDate:    w.AddedDate,
		PwnCount:     w.PwnCount,
		Description:  w.Description,
		DataClasses:  w.DataClasses,
		IsVerified:   w.IsVerified,
		IsFabricated: w.IsFabricated,
		IsSensitive:  w.IsSensitive,
		IsRetired:    w.IsRetired,
		IsSpamList:   w.IsSpamList,
		IsMalware:    w.IsMalware,
	}
}

// Client talks to the HIBP API.
type Client struct {
	HTTP    *http.Client
	BaseURL string
	Rate    time.Duration
	Retries int

	last time.Time
}

// NewClient returns a Client with sensible defaults.
func NewClient() *Client {
	cfg := DefaultConfig()
	return &Client{
		HTTP:    &http.Client{Timeout: cfg.Timeout},
		BaseURL: cfg.BaseURL,
		Rate:    cfg.Rate,
		Retries: cfg.Retries,
	}
}

// NewClientFromConfig returns a Client configured from a Config.
func NewClientFromConfig(cfg Config) *Client {
	if cfg.BaseURL == "" {
		cfg.BaseURL = BaseURL
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		HTTP:    &http.Client{Timeout: timeout},
		BaseURL: cfg.BaseURL,
		Rate:    cfg.Rate,
		Retries: cfg.Retries,
	}
}

// ListBreaches returns all breaches, optionally filtered by domain.
// domain may be empty to return all breaches.
func (c *Client) ListBreaches(ctx context.Context, domain string) ([]Breach, error) {
	endpoint := c.BaseURL + "/api/v3/breaches"
	if domain != "" {
		endpoint += "?domain=" + url.QueryEscape(domain)
	}
	body, err := c.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	var wire []wireBreach
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("parse breaches: %w", err)
	}
	out := make([]Breach, len(wire))
	for i, w := range wire {
		out[i] = w.toBreach()
	}
	return out, nil
}

// GetBreach returns a single breach by name (e.g. "Adobe").
func (c *Client) GetBreach(ctx context.Context, name string) (*Breach, error) {
	endpoint := c.BaseURL + "/api/v3/breach/" + url.PathEscape(name)
	body, err := c.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	var wire wireBreach
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("parse breach: %w", err)
	}
	b := wire.toBreach()
	return &b, nil
}

// ListDataClasses returns all 165 data class type strings.
func (c *Client) ListDataClasses(ctx context.Context) ([]DataClass, error) {
	endpoint := c.BaseURL + "/api/v3/dataclasses"
	body, err := c.get(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	var names []string
	if err := json.Unmarshal(body, &names); err != nil {
		return nil, fmt.Errorf("parse dataclasses: %w", err)
	}
	out := make([]DataClass, len(names))
	for i, s := range names {
		out[i] = DataClass{Name: s}
	}
	return out, nil
}

// get fetches a URL with pacing and retries.
func (c *Client) get(ctx context.Context, rawURL string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		body, retry, err := c.do(ctx, rawURL)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retry {
			return nil, err
		}
	}
	return nil, fmt.Errorf("get %s: %w", rawURL, lastErr)
}

func (c *Client) do(ctx context.Context, rawURL string) (body []byte, retry bool, err error) {
	c.pace()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "hibp-cli/0.1 (github.com/tamnd/hibp-cli)")

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
