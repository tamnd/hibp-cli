package hibp

import (
	"context"
	"strings"

	"github.com/tamnd/any-cli/kit"
	"github.com/tamnd/any-cli/kit/errs"
)

// domain.go exposes hibp as a kit Domain: a driver that a multi-domain
// host (ant) enables with a single blank import,
//
//	import _ "github.com/tamnd/hibp-cli/hibp"
//
// exactly as a database/sql program enables a driver with `import _
// "github.com/lib/pq"`. The init below registers it; the host then dereferences
// hibp:// URIs by routing to the operations Register installs. The same
// Domain also builds the standalone hibp binary (see cli.NewApp), so the
// binary and a host share one source of truth.
func init() { kit.Register(Domain{}) }

// Domain is the hibp driver. It carries no state; the per-run client is
// built by the factory Register hands kit.
type Domain struct{}

// Info describes the scheme, the hostnames a pasted link is matched against, and
// the identity reused for the binary's help and version.
func (Domain) Info() kit.DomainInfo {
	return kit.DomainInfo{
		Scheme: "hibp",
		Hosts:  []string{Host},
		Identity: kit.Identity{
			Binary: "hibp",
			Short:  "Check passwords against the HaveIBeenPwned Pwned Passwords database.",
			Long: `hibp checks passwords against the HaveIBeenPwned Pwned Passwords database.

Uses k-anonymity: only the first 5 characters of the SHA1 hash are sent to the
API, so your full password is never transmitted. No API key required.`,
			Site: Host,
			Repo: "https://github.com/tamnd/hibp-cli",
		},
	}
}

// Register installs the client factory and every operation onto app.
func (Domain) Register(app *kit.App) {
	app.SetClient(newClient)

	// check op: check if a password has been seen in breaches.
	kit.Handle(app, kit.OpMeta{Name: "check", Group: "read", Single: true,
		Summary: "Check if a password has been seen in breaches",
		Args:    []kit.Arg{{Name: "password", Help: "password to check (never sent to API)"}}}, checkPassword)

	// range op: get all hash suffixes for a 5-char SHA1 prefix.
	kit.Handle(app, kit.OpMeta{Name: "range", Group: "read", List: true,
		Summary: "Get all pwned hash suffixes for a 5-char SHA1 prefix",
		Args:    []kit.Arg{{Name: "prefix", Help: "first 5 hex chars of a SHA1 hash"}}}, rangePrefix)
}

// newClient builds the client from the host-resolved config.
func newClient(_ context.Context, cfg kit.Config) (any, error) {
	c := NewClient()
	if cfg.UserAgent != "" {
		c.UserAgent = cfg.UserAgent
	}
	if cfg.Rate > 0 {
		c.Rate = cfg.Rate
	}
	if cfg.Retries > 0 {
		c.Retries = cfg.Retries
	}
	if cfg.Timeout > 0 {
		c.HTTP.Timeout = cfg.Timeout
	}
	return c, nil
}

// --- inputs ---

type checkInput struct {
	Password string  `kit:"arg" help:"password to check (never sent to API)"`
	Client   *Client `kit:"inject"`
}

type rangeInput struct {
	Prefix string  `kit:"arg" help:"first 5 hex chars of a SHA1 hash"`
	Client *Client `kit:"inject"`
}

// --- handlers ---

func checkPassword(ctx context.Context, in checkInput, emit func(*CheckResult) error) error {
	result, err := in.Client.Check(ctx, in.Password)
	if err != nil {
		return mapErr(err)
	}
	return emit(result)
}

func rangePrefix(ctx context.Context, in rangeInput, emit func(*HashEntry) error) error {
	entries, err := in.Client.Range(ctx, in.Prefix)
	if err != nil {
		return mapErr(err)
	}
	for i := range entries {
		if err := emit(&entries[i]); err != nil {
			return err
		}
	}
	return nil
}

// --- Resolver: the URI-native string functions, pure and network-free ---

// Classify turns any accepted input into the canonical (type, id).
func (Domain) Classify(input string) (uriType, id string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", errs.Usage("unrecognized hibp reference: %q", input)
	}
	// Treat the input as an opaque id for the "check" type.
	return "check", input, nil
}

// Locate is the inverse: the live https URL for a (type, id).
func (Domain) Locate(uriType, id string) (string, error) {
	switch uriType {
	case "check":
		return BaseURL + "/range/" + id, nil
	case "range":
		return BaseURL + "/range/" + strings.ToUpper(id), nil
	default:
		return "", errs.Usage("hibp has no resource type %q", uriType)
	}
}

// mapErr converts a library error into the kit error kind.
func mapErr(err error) error {
	return err
}
