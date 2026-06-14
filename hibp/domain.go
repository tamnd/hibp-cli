package hibp

import (
	"context"
	"strings"

	"github.com/tamnd/any-cli/kit"
	"github.com/tamnd/any-cli/kit/errs"
)

// domain.go exposes hibp as a kit Domain: a driver that a multi-domain host
// (ant) enables with a single blank import,
//
//	import _ "github.com/tamnd/hibp-cli/hibp"
//
// exactly as a database/sql program enables a driver with `import _
// "github.com/lib/pq"`. The init below registers it; the host then dereferences
// hibp:// URIs by routing to the operations Register installs. The same Domain
// also builds the standalone hibp binary (see cli.NewApp), so the binary and a
// host share one source of truth.
func init() { kit.Register(Domain{}) }

// Domain is the hibp driver. It carries no state; the per-run client is built
// by the factory Register hands kit.
type Domain struct{}

// Info describes the scheme, the hostnames a pasted link is matched against, and
// the identity reused for the binary's help and version.
func (Domain) Info() kit.DomainInfo {
	return kit.DomainInfo{
		Scheme: "hibp",
		Hosts:  []string{Host},
		Identity: kit.Identity{
			Binary: "hibp",
			Short:  "Browse the HaveIBeenPwned breach database.",
			Long: `hibp fetches public breach data from haveibeenpwned.com.

List all breaches, filter by domain, look up a single breach by name, or list
all 165 data class types. No API key required.`,
			Site: Host,
			Repo: "https://github.com/tamnd/hibp-cli",
		},
	}
}

// Register installs the client factory and every operation onto app.
func (Domain) Register(app *kit.App) {
	app.SetClient(newClient)

	// breaches op: list all breaches, optionally filtered by domain.
	kit.Handle(app, kit.OpMeta{Name: "breaches", Group: "read", List: true,
		Summary: "List all breaches (optional --domain filter)"}, listBreaches)

	// breach op: get a single breach by name.
	kit.Handle(app, kit.OpMeta{Name: "breach", Group: "read", Single: true,
		Summary:  "Get a single breach by name",
		URIType:  "breach",
		Resolver: true,
		Args:     []kit.Arg{{Name: "name", Help: "breach name (e.g. Adobe)"}}}, getBreach)

	// dataclasses op: list all data class type strings.
	kit.Handle(app, kit.OpMeta{Name: "dataclasses", Group: "read", List: true,
		Summary: "List all 165 data class types"}, listDataClasses)
}

// newClient builds the client from the host-resolved config.
func newClient(_ context.Context, cfg kit.Config) (any, error) {
	c := NewClient()
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

type breachesInput struct {
	Domain string  `kit:"flag" help:"filter by domain (e.g. adobe.com)"`
	Client *Client `kit:"inject"`
}

type breachInput struct {
	Name   string  `kit:"arg" help:"breach name (e.g. Adobe)"`
	Client *Client `kit:"inject"`
}

type dataClassesInput struct {
	Client *Client `kit:"inject"`
}

// --- handlers ---

func listBreaches(ctx context.Context, in breachesInput, emit func(*Breach) error) error {
	breaches, err := in.Client.ListBreaches(ctx, in.Domain)
	if err != nil {
		return mapErr(err)
	}
	for i := range breaches {
		if err := emit(&breaches[i]); err != nil {
			return err
		}
	}
	return nil
}

func getBreach(ctx context.Context, in breachInput, emit func(*Breach) error) error {
	b, err := in.Client.GetBreach(ctx, in.Name)
	if err != nil {
		return mapErr(err)
	}
	return emit(b)
}

func listDataClasses(ctx context.Context, in dataClassesInput, emit func(*DataClass) error) error {
	classes, err := in.Client.ListDataClasses(ctx)
	if err != nil {
		return mapErr(err)
	}
	for i := range classes {
		if err := emit(&classes[i]); err != nil {
			return err
		}
	}
	return nil
}

// --- Resolver: the URI-native string functions, pure and network-free ---

// Classify turns any accepted input into the canonical (type, id). A string
// containing a dot is treated as a domain; a CamelCase or single-word string is
// treated as a breach name.
func (Domain) Classify(input string) (uriType, id string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", errs.Usage("unrecognized hibp reference: %q", input)
	}
	// A string with a dot looks like a domain name (e.g. "adobe.com").
	if strings.Contains(input, ".") {
		return "domain", input, nil
	}
	// Anything else is treated as a breach name.
	return "breach", input, nil
}

// Locate is the inverse: the live API URL for a (type, id).
func (Domain) Locate(uriType, id string) (string, error) {
	switch uriType {
	case "breach":
		return BaseURL + "/api/v3/breach/" + id, nil
	case "domain":
		return BaseURL + "/api/v3/breaches?domain=" + id, nil
	default:
		return "", errs.Usage("hibp has no resource type %q", uriType)
	}
}

// mapErr converts a library error into the kit error kind.
func mapErr(err error) error {
	return err
}
