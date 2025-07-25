package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lstoll/oauth2ext/clitoken"
	"github.com/lstoll/oauth2ext/oidc"
	"github.com/lstoll/oauth2ext/tokencache"
	"golang.org/x/oauth2"
)

type subCommand struct {
	Flags       *flag.FlagSet
	Description string
}

type baseOpts struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	PortLow      int
	PortHigh     int
	Offline      bool
	SkipCache    bool
	Scopes       string
}

type rawOpts struct {
	UseIDToken bool
}

type kubeOpts struct {
	UseIDToken bool
}

type infoOpts struct{}

func main() {
	ctx := context.Background()

	baseFlags := baseOpts{}
	baseFs := flag.NewFlagSet("oidccli", flag.ExitOnError)
	baseFs.StringVar(&baseFlags.Issuer, "issuer", baseFlags.Issuer, "OIDC Issuer URL (required)")
	baseFs.StringVar(&baseFlags.ClientID, "client-id", baseFlags.ClientID, "OIDC Client ID (required)")
	baseFs.StringVar(&baseFlags.ClientSecret, "client-secret", baseFlags.ClientSecret, "OIDC Client Secret")
	baseFs.IntVar(&baseFlags.PortLow, "port-low", 0, "Lowest TCP port to bind on localhost for callbacks. By default, a port will be randomly assigned by the operating system.")
	baseFs.IntVar(&baseFlags.PortHigh, "port-high", 0, "Highest TCP port to bind on localhost for callbacks. By default, a port will be randomly assigned by the operating system.")
	baseFs.BoolVar(&baseFlags.Offline, "offline", baseFlags.Offline, "Offline use (request refresh token). This token will be cached locally, can be used to avoid re-launching the auth flow when the token expires")
	baseFs.BoolVar(&baseFlags.SkipCache, "skip-cache", baseFlags.SkipCache, "Do not perform any local caching on token")
	baseFs.StringVar(&baseFlags.Scopes, "scopes", baseFlags.Scopes, "Comma separated list of extra scopes to request")

	var subcommands []*subCommand

	rawFlags := rawOpts{}
	rawFs := flag.NewFlagSet("raw", flag.ExitOnError)
	rawFs.BoolVar(&rawFlags.UseIDToken, "use-id-token", rawFlags.UseIDToken, "Use ID token, rather than access token")
	subcommands = append(subcommands, &subCommand{
		Flags:       rawFs,
		Description: "Output a raw JWT for this client",
	})

	kubeFlags := kubeOpts{}
	kubeFs := flag.NewFlagSet("kubernetes", flag.ExitOnError)
	kubeFs.BoolVar(&kubeFlags.UseIDToken, "use-id-token", kubeFlags.UseIDToken, "Use ID token, rather than access token")
	subcommands = append(subcommands, &subCommand{
		Flags:       kubeFs,
		Description: "Output credentials in a format that can be consumed by kubectl/client-go",
	})

	infoFlags := infoOpts{}
	infoFs := flag.NewFlagSet("info", flag.ExitOnError)
	subcommands = append(subcommands, &subCommand{
		Flags:       infoFs,
		Description: "Output information about the auth response in human-readable format",
	})

	if err := baseFs.Parse(os.Args[1:]); err != nil {
		fmt.Printf("failed parsing args: %v", err)
		os.Exit(1)
	}

	if len(baseFs.Args()) < 1 {
		fmt.Print("error: subcommand required\n\n")
		printFullUsage(baseFs, subcommands)
		os.Exit(1)
	}

	var missingFlags []string
	if baseFlags.Issuer == "" {
		missingFlags = append(missingFlags, "issuer")
	}
	if baseFlags.ClientID == "" {
		missingFlags = append(missingFlags, "client-id")
	}

	var execFn func(context.Context, *oidc.Provider, oauth2.TokenSource) error

	switch baseFs.Arg(0) {
	case "raw":
		if err := rawFs.Parse(baseFs.Args()[1:]); err != nil {
			fmt.Printf("failed parsing raw args: %v", err)
			os.Exit(1)
		}
		execFn = func(ctx context.Context, _ *oidc.Provider, ts oauth2.TokenSource) error {
			return raw(ts, rawFlags)
		}
	case "kubernetes":
		if err := kubeFs.Parse(baseFs.Args()[1:]); err != nil {
			fmt.Printf("failed parsing kube args: %v", err)
			os.Exit(1)
		}
		execFn = func(ctx context.Context, _ *oidc.Provider, ts oauth2.TokenSource) error {
			return kubernetes(ts, kubeFlags)
		}
	case "info":
		if err := infoFs.Parse(baseFs.Args()[1:]); err != nil {
			fmt.Printf("failed parsing info args: %v", err)
			os.Exit(1)
		}
		execFn = func(ctx context.Context, provider *oidc.Provider, ts oauth2.TokenSource) error {
			return info(ctx, provider, ts, infoFlags)
		}
	default:
		fmt.Printf("error: invalid subcommand %s\n\n", baseFs.Arg(0))
		printFullUsage(baseFs, subcommands)
		os.Exit(1)
	}

	if len(missingFlags) > 0 {
		fmt.Printf("error: %s are required flags\n\n", strings.Join(missingFlags, ", "))
		printFullUsage(baseFs, subcommands)
		os.Exit(1)
	}

	provider, err := oidc.DiscoverProvider(ctx, baseFlags.Issuer, nil)
	if err != nil {
		fmt.Printf("discovering issuer %s: %v", baseFlags.Issuer, err)
		os.Exit(1)
	}

	scopes := []string{oidc.ScopeOpenID}
	if baseFlags.Offline {
		scopes = append(scopes, "offline")
	}
	if baseFlags.Scopes != "" {
		scopes = append(scopes, strings.Split(baseFlags.Scopes, ",")...)
	}

	oa2Cfg := oauth2.Config{
		ClientID:     baseFlags.ClientID,
		ClientSecret: baseFlags.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}
	clitokCfg := clitoken.Config{
		OAuth2Config: oa2Cfg,
		PortLow:      uint16(baseFlags.PortLow),
		PortHigh:     uint16(baseFlags.PortHigh),
	}

	var ts oauth2.TokenSource
	ts, err = clitokCfg.TokenSource(ctx)
	if err != nil {
		fmt.Printf("getting cli token source: %v", err)
		os.Exit(1)
	}

	if !baseFlags.SkipCache {
		ccfg := tokencache.Config{
			Issuer: baseFlags.Issuer,
			CacheKey: (tokencache.IDTokenCacheKey{
				ClientID: baseFlags.ClientID,
				Scopes:   scopes,
			}).Key(),
			WrappedSource: ts,
			Cache:         clitoken.BestCredentialCache(),
		}
		if baseFlags.Offline {
			ccfg.OAuth2Config = &oa2Cfg
		}

		ts, err = ccfg.TokenSource(ctx)
		if err != nil {
			fmt.Printf("error creating token cache: %+v", err)
			os.Exit(1)
		}
	}

	if err := execFn(ctx, provider, ts); err != nil {
		fmt.Printf("error: %+v", err)
		os.Exit(1)
	}
}

func printFullUsage(baseFs *flag.FlagSet, subcommands []*subCommand) {
	fmt.Printf("Usage: %s <base flags> <subcommand> <subcommand flags>\n", os.Args[0])
	fmt.Print("\n")
	fmt.Print("Base Flags:\n")
	fmt.Print("\n")
	baseFs.PrintDefaults()
	fmt.Print("\n")
	fmt.Print("Subcommands:\n")
	fmt.Print("\n")
	for _, sc := range subcommands {
		fmt.Printf("%s\n", sc.Flags.Name())
		fmt.Print("\n")
		fmt.Printf("  %s\n", sc.Description)
		fmt.Print("\n")
		sc.Flags.PrintDefaults()
		fmt.Print("\n")
	}
}

func raw(ts oauth2.TokenSource, opts rawOpts) error {
	// TODO(lstoll) might want to default to access token, and make id_token an
	// option.
	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}
	raw := tok.AccessToken
	if opts.UseIDToken {
		idt, ok := oidc.GetIDToken(tok)
		if !ok {
			return fmt.Errorf("response has no id_token")
		}
		raw = idt
	}
	fmt.Print(raw)
	return nil
}

// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins

type kubeToken struct {
	Token               string     `json:"token,omitempty"`
	ExpirationTimestamp *time.Time `json:"expirationTimestamp,omitempty"`
}

const (
	apiVersion   = "client.authentication.k8s.io/v1beta1"
	execCredKind = "ExecCredential"
)

type kubeExecCred struct {
	APIVersion string    `json:"apiVersion,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Status     kubeToken `json:"status"`
}

func kubernetes(ts oauth2.TokenSource, opts kubeOpts) error {
	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}
	var raw = tok.AccessToken
	if opts.UseIDToken {
		idt, ok := oidc.GetIDToken(tok)
		if !ok {
			return fmt.Errorf("response has no id_token")
		}
		raw = idt
	}
	creds := kubeExecCred{
		APIVersion: apiVersion,
		Kind:       execCredKind,
		Status: kubeToken{
			Token:               raw,
			ExpirationTimestamp: &tok.Expiry,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(&creds)
}

func info(ctx context.Context, provider *oidc.Provider, ts oauth2.TokenSource, _ infoOpts) error {
	tok, err := ts.Token()
	if err != nil {
		return fmt.Errorf("fetching token: %v", err)
	}

	fmt.Printf("Access Token: %s\n", tok.AccessToken)
	fmt.Printf("Access Token expires: %s\n", tok.Expiry.String())
	if isJWT(tok.AccessToken) {
		jwt, err := provider.VerifyAccessToken(ctx, tok, oidc.AccessTokenValidationOpts{IgnoreAudience: true})
		if err != nil {
			return fmt.Errorf("access token verification: %w", err)
		}
		exp, err := jwt.ExpiresAt()
		if err != nil {
			return fmt.Errorf("getting expires at: %w", err)
		}
		clJSON, err := jwt.JSONPayload()
		if err != nil {
			return fmt.Errorf("getting json payload: %w", err)
		}
		fmt.Printf("Access token claims expires: %s\n", exp.String())
		fmt.Printf("Access token claims: %s\n", string(clJSON))
		jb, err := jwt.JSONPayload()
		if err != nil {
			return fmt.Errorf("getting json payload: %w", err)
		}
		fmt.Printf("Access token full claims: %v\n", string(jb))
	}
	fmt.Printf("Refresh Token: %s\n", tok.RefreshToken)
	idt, ok := oidc.GetIDToken(tok)
	if ok {
		jwt, err := provider.VerifyIDToken(ctx, tok, oidc.IDTokenValidationOpts{IgnoreAudience: true})
		if err != nil {
			return fmt.Errorf("ID token verification: %w", err)
		}
		exp, err := jwt.ExpiresAt()
		if err != nil {
			return fmt.Errorf("getting expires at: %w", err)
		}
		clJSON, err := jwt.JSONPayload()
		if err != nil {
			return fmt.Errorf("getting json payload: %w", err)
		}
		fmt.Printf("ID token: %s\n", idt)
		fmt.Printf("ID token claims expires: %s\n", exp.String())
		fmt.Printf("ID token standard claims: %s\n", string(clJSON))
		jb, err := jwt.JSONPayload()
		if err != nil {
			return fmt.Errorf("getting json payload: %w", err)
		}
		fmt.Printf("ID token full claims: %v\n", string(jb))
	}

	return nil
}

// isJWT guesses is something is a JWT
func isJWT(s string) bool {
	return strings.Count(s, ".") == 2
}
