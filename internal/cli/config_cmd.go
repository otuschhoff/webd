package cli

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"webd/internal/server"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type configRouteAddOptions struct {
	Path                 string
	Handler              string
	Redirect             string
	AllowedIPv4          []string
	Websocket            string
	Browse               bool
	Insecure             bool
	RewriteBaseHref      bool
	RewriteBaseHrefSet   bool
	RewriteLocationMatch string
	RewriteLocationRepl  string
	TrustedCAName        string
	TrustedCACertPath    string
}

type configRouteModifyOptions struct {
	Path                 string
	Index                int
	NewPath              string
	Handler              string
	Redirect             string
	AllowedIPv4          []string
	SetAllowedIPv4       bool
	ClearAllowedIPv4     bool
	Websocket            string
	SetWebsocket         bool
	ClearWebsocket       bool
	Browse               bool
	SetBrowse            bool
	Insecure             bool
	SetInsecure          bool
	RewriteBaseHref      bool
	SetRewriteBaseHref   bool
	ClearRewriteBaseHref bool
	RewriteLocationMatch string
	RewriteLocationRepl  string
	SetRewriteLocation   bool
	ClearRewriteLocation bool
	TrustedCAName        string
	TrustedCACertPath    string
	SetTrustedCA         bool
	ClearTrustedCA       bool
}

type configRouteDeleteOptions struct {
	Path  string
	Index int
}

func newConfigCommand(runOpts *server.RunOptions) *cobra.Command {
	cfgCmd := &cobra.Command{
		Use:           "config",
		Short:         "Inspect and modify source YAML configuration",
		SilenceUsage:  true,
		SilenceErrors: true,
		GroupID:       "ops",
	}

	cfgListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all config entries (normalized YAML)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigList(runOpts.ConfigPath)
		},
	}

	routeCmd := &cobra.Command{
		Use:   "route",
		Short: "Manage configured routes",
	}

	routeListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all configured routes",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigRouteList(runOpts.ConfigPath)
		},
	}

	addOpts := configRouteAddOptions{}
	routeAddCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new route to source config",
		RunE: func(cmd *cobra.Command, args []string) error {
			addOpts.RewriteBaseHrefSet = cmd.Flags().Changed("rewrite-base-href")
			return runConfigRouteAdd(runOpts.ConfigPath, addOpts)
		},
	}
	bindConfigRouteAddFlags(routeAddCmd, &addOpts)

	modOpts := configRouteModifyOptions{Index: -1}
	routeModifyCmd := &cobra.Command{
		Use:   "modify",
		Short: "Modify an existing route in source config",
		RunE: func(cmd *cobra.Command, args []string) error {
			modOpts.SetAllowedIPv4 = cmd.Flags().Changed("allowed-ipv4")
			modOpts.SetWebsocket = cmd.Flags().Changed("websocket")
			modOpts.SetBrowse = cmd.Flags().Changed("browse")
			modOpts.SetInsecure = cmd.Flags().Changed("insecure")
			modOpts.SetRewriteBaseHref = cmd.Flags().Changed("rewrite-base-href")
			modOpts.SetRewriteLocation = cmd.Flags().Changed("rewrite-location-match") || cmd.Flags().Changed("rewrite-location-replace")
			modOpts.SetTrustedCA = cmd.Flags().Changed("trusted-ca-name") || cmd.Flags().Changed("trusted-ca-cert-path")
			return runConfigRouteModify(runOpts.ConfigPath, modOpts)
		},
	}
	bindConfigRouteModifyFlags(routeModifyCmd, &modOpts)

	delOpts := configRouteDeleteOptions{Index: -1}
	routeDeleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete an existing route from source config",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigRouteDelete(runOpts.ConfigPath, delOpts)
		},
	}
	routeDeleteCmd.Flags().StringVar(&delOpts.Path, "path", delOpts.Path, "Route path to delete")
	routeDeleteCmd.Flags().IntVar(&delOpts.Index, "index", delOpts.Index, "Absolute zero-based route index for disambiguation (optional)")

	routeCmd.AddCommand(routeListCmd, routeAddCmd, routeModifyCmd, routeDeleteCmd)
	cfgCmd.AddCommand(cfgListCmd, routeCmd)
	return cfgCmd
}

func bindConfigRouteAddFlags(cmd *cobra.Command, opts *configRouteAddOptions) {
	cmd.Flags().StringVar(&opts.Path, "path", opts.Path, "Route path prefix (required)")
	cmd.Flags().StringVar(&opts.Handler, "handler", opts.Handler, "Handler URL")
	cmd.Flags().StringVar(&opts.Redirect, "redirect", opts.Redirect, "Redirect URL")
	cmd.Flags().StringSliceVar(&opts.AllowedIPv4, "allowed-ipv4", opts.AllowedIPv4, "Allowed IPv4 entries (repeatable)")
	cmd.Flags().StringVar(&opts.Websocket, "websocket", opts.Websocket, "WebSocket mode: auto | false | <url>")
	cmd.Flags().BoolVar(&opts.Browse, "browse", opts.Browse, "Enable directory listing for file handlers")
	cmd.Flags().BoolVar(&opts.Insecure, "insecure", opts.Insecure, "Enable endpoint certificate pinning for https/wss handlers")
	cmd.Flags().BoolVar(&opts.RewriteBaseHref, "rewrite-base-href", opts.RewriteBaseHref, "Enable HTML <base href> rewrite for this route")
	cmd.Flags().StringVar(&opts.RewriteLocationMatch, "rewrite-location-match", opts.RewriteLocationMatch, "Regex for rewrite_location.match")
	cmd.Flags().StringVar(&opts.RewriteLocationRepl, "rewrite-location-replace", opts.RewriteLocationRepl, "Replacement for rewrite_location.replace")
	cmd.Flags().StringVar(&opts.TrustedCAName, "trusted-ca-name", opts.TrustedCAName, "trusted_ca.name")
	cmd.Flags().StringVar(&opts.TrustedCACertPath, "trusted-ca-cert-path", opts.TrustedCACertPath, "trusted_ca.cert_path")
}

func bindConfigRouteModifyFlags(cmd *cobra.Command, opts *configRouteModifyOptions) {
	cmd.Flags().StringVar(&opts.Path, "path", opts.Path, "Route path to modify (required)")
	cmd.Flags().IntVar(&opts.Index, "index", opts.Index, "Absolute zero-based route index for disambiguation (optional)")
	cmd.Flags().StringVar(&opts.NewPath, "new-path", opts.NewPath, "Replace route path")
	cmd.Flags().StringVar(&opts.Handler, "handler", opts.Handler, "Replace handler URL")
	cmd.Flags().StringVar(&opts.Redirect, "redirect", opts.Redirect, "Replace redirect URL")
	cmd.Flags().StringSliceVar(&opts.AllowedIPv4, "allowed-ipv4", opts.AllowedIPv4, "Replace allowed IPv4 entries (repeatable)")
	cmd.Flags().BoolVar(&opts.ClearAllowedIPv4, "clear-allowed-ipv4", opts.ClearAllowedIPv4, "Clear allowed_ipv4 list")
	cmd.Flags().StringVar(&opts.Websocket, "websocket", opts.Websocket, "Set websocket to auto | false | <url>")
	cmd.Flags().BoolVar(&opts.ClearWebsocket, "clear-websocket", opts.ClearWebsocket, "Clear websocket setting (auto derive)")
	cmd.Flags().BoolVar(&opts.Browse, "browse", opts.Browse, "Set browse")
	cmd.Flags().BoolVar(&opts.Insecure, "insecure", opts.Insecure, "Set insecure")
	cmd.Flags().BoolVar(&opts.RewriteBaseHref, "rewrite-base-href", opts.RewriteBaseHref, "Set rewrite_base_href")
	cmd.Flags().BoolVar(&opts.ClearRewriteBaseHref, "clear-rewrite-base-href", opts.ClearRewriteBaseHref, "Clear rewrite_base_href")
	cmd.Flags().StringVar(&opts.RewriteLocationMatch, "rewrite-location-match", opts.RewriteLocationMatch, "Set rewrite_location.match")
	cmd.Flags().StringVar(&opts.RewriteLocationRepl, "rewrite-location-replace", opts.RewriteLocationRepl, "Set rewrite_location.replace")
	cmd.Flags().BoolVar(&opts.ClearRewriteLocation, "clear-rewrite-location", opts.ClearRewriteLocation, "Clear rewrite_location")
	cmd.Flags().StringVar(&opts.TrustedCAName, "trusted-ca-name", opts.TrustedCAName, "Set trusted_ca.name")
	cmd.Flags().StringVar(&opts.TrustedCACertPath, "trusted-ca-cert-path", opts.TrustedCACertPath, "Set trusted_ca.cert_path")
	cmd.Flags().BoolVar(&opts.ClearTrustedCA, "clear-trusted-ca", opts.ClearTrustedCA, "Clear trusted_ca")
}

func runConfigList(path string) error {
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	pretty, err := PrettyYAML(cfg)
	if err != nil {
		return err
	}
	fmt.Print(ColorizeYAML(pretty, os.Getenv("NO_COLOR") == ""))
	return nil
}

func runConfigRouteList(path string) error {
	cfg, err := Load(path)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "INDEX\tPATH\tTYPE\tTARGET\tWS\tALLOWED_IPV4")
	for i, r := range cfg.Routes {
		typeName := "handler"
		target := strings.TrimSpace(r.Handler)
		if strings.TrimSpace(r.Redirect) != "" {
			typeName = "redirect"
			target = strings.TrimSpace(r.Redirect)
		}
		ws := "auto"
		if r.Websocket != nil {
			if r.Websocket.IsDisabled() {
				ws = "false"
			} else if strings.TrimSpace(r.Websocket.URL()) != "" {
				ws = strings.TrimSpace(r.Websocket.URL())
			}
		}
		allowed := strconv.Itoa(len(r.AllowedIPv4))
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", i, strings.TrimSpace(r.Path), typeName, target, ws, allowed)
	}
	return tw.Flush()
}

func runConfigRouteAdd(path string, opts configRouteAddOptions) error {
	cfg, err := Load(path)
	if err != nil {
		return err
	}

	r, err := buildRouteFromAddOptions(opts)
	if err != nil {
		return err
	}
	cfg.Routes = append(cfg.Routes, r)

	if err := Validate(cfg); err != nil {
		return err
	}
	if err := writeConfigYAML(path, cfg); err != nil {
		return err
	}
	fmt.Printf("added route path=%q\n", r.Path)
	return nil
}

func runConfigRouteDelete(path string, opts configRouteDeleteOptions) error {
	cfg, err := Load(path)
	if err != nil {
		return err
	}

	targetIdx, err := selectRouteIndex(cfg.Routes, opts.Path, opts.Index)
	if err != nil {
		return err
	}
	removed := cfg.Routes[targetIdx]
	cfg.Routes = append(cfg.Routes[:targetIdx], cfg.Routes[targetIdx+1:]...)

	if len(cfg.Routes) == 0 {
		return fmt.Errorf("cannot delete last route: config must contain at least one route")
	}
	if err := Validate(cfg); err != nil {
		return err
	}
	if err := writeConfigYAML(path, cfg); err != nil {
		return err
	}
	fmt.Printf("deleted route index=%d path=%q\n", targetIdx, removed.Path)
	return nil
}

func runConfigRouteModify(path string, opts configRouteModifyOptions) error {
	cfg, err := Load(path)
	if err != nil {
		return err
	}

	targetIdx, err := selectRouteIndex(cfg.Routes, opts.Path, opts.Index)
	if err != nil {
		return err
	}
	r := cfg.Routes[targetIdx]

	if strings.TrimSpace(opts.NewPath) != "" {
		r.Path = strings.TrimSpace(opts.NewPath)
	}
	if strings.TrimSpace(opts.Handler) != "" {
		r.Handler = strings.TrimSpace(opts.Handler)
	}
	if strings.TrimSpace(opts.Redirect) != "" {
		r.Redirect = strings.TrimSpace(opts.Redirect)
	}
	if opts.SetAllowedIPv4 {
		r.AllowedIPv4 = cloneStringSlice(opts.AllowedIPv4)
	}
	if opts.ClearAllowedIPv4 {
		r.AllowedIPv4 = nil
	}
	if opts.ClearWebsocket {
		r.Websocket = nil
	}
	if opts.SetWebsocket {
		parsedWS, parseErr := parseWebsocketFlag(opts.Websocket)
		if parseErr != nil {
			return parseErr
		}
		r.Websocket = parsedWS
	}
	if opts.SetBrowse {
		r.Browse = opts.Browse
	}
	if opts.SetInsecure {
		r.Insecure = opts.Insecure
	}
	if opts.ClearRewriteBaseHref {
		r.RewriteBaseHref = nil
	}
	if opts.SetRewriteBaseHref {
		v := opts.RewriteBaseHref
		r.RewriteBaseHref = &v
	}
	if opts.ClearRewriteLocation {
		r.RewriteLocation = nil
	}
	if opts.SetRewriteLocation {
		if strings.TrimSpace(opts.RewriteLocationMatch) == "" || strings.TrimSpace(opts.RewriteLocationRepl) == "" {
			return fmt.Errorf("both --rewrite-location-match and --rewrite-location-replace are required when setting rewrite_location")
		}
		r.RewriteLocation = &RewriteLocation{
			Match:   strings.TrimSpace(opts.RewriteLocationMatch),
			Replace: strings.TrimSpace(opts.RewriteLocationRepl),
		}
	}
	if opts.ClearTrustedCA {
		r.TrustedCA = nil
	}
	if opts.SetTrustedCA {
		if strings.TrimSpace(opts.TrustedCAName) == "" || strings.TrimSpace(opts.TrustedCACertPath) == "" {
			return fmt.Errorf("both --trusted-ca-name and --trusted-ca-cert-path are required when setting trusted_ca")
		}
		r.TrustedCA = &TrustedCA{Name: strings.TrimSpace(opts.TrustedCAName), CertPath: strings.TrimSpace(opts.TrustedCACertPath)}
	}

	cfg.Routes[targetIdx] = r
	if err := Validate(cfg); err != nil {
		return err
	}
	if err := writeConfigYAML(path, cfg); err != nil {
		return err
	}
	fmt.Printf("modified route index=%d path=%q\n", targetIdx, r.Path)
	return nil
}

func buildRouteFromAddOptions(opts configRouteAddOptions) (Route, error) {
	path := strings.TrimSpace(opts.Path)
	if path == "" {
		return Route{}, fmt.Errorf("--path is required")
	}
	handler := strings.TrimSpace(opts.Handler)
	redirect := strings.TrimSpace(opts.Redirect)
	if (handler == "" && redirect == "") || (handler != "" && redirect != "") {
		return Route{}, fmt.Errorf("exactly one of --handler or --redirect is required")
	}

	r := Route{
		Path:        path,
		Handler:     handler,
		Redirect:    redirect,
		AllowedIPv4: cloneStringSlice(opts.AllowedIPv4),
		Browse:      opts.Browse,
		Insecure:    opts.Insecure,
	}

	if opts.RewriteBaseHrefSet {
		v := opts.RewriteBaseHref
		r.RewriteBaseHref = &v
	}
	if strings.TrimSpace(opts.RewriteLocationMatch) != "" || strings.TrimSpace(opts.RewriteLocationRepl) != "" {
		if strings.TrimSpace(opts.RewriteLocationMatch) == "" || strings.TrimSpace(opts.RewriteLocationRepl) == "" {
			return Route{}, fmt.Errorf("both --rewrite-location-match and --rewrite-location-replace are required when setting rewrite_location")
		}
		r.RewriteLocation = &RewriteLocation{
			Match:   strings.TrimSpace(opts.RewriteLocationMatch),
			Replace: strings.TrimSpace(opts.RewriteLocationRepl),
		}
	}
	if strings.TrimSpace(opts.TrustedCAName) != "" || strings.TrimSpace(opts.TrustedCACertPath) != "" {
		if strings.TrimSpace(opts.TrustedCAName) == "" || strings.TrimSpace(opts.TrustedCACertPath) == "" {
			return Route{}, fmt.Errorf("both --trusted-ca-name and --trusted-ca-cert-path are required when setting trusted_ca")
		}
		r.TrustedCA = &TrustedCA{
			Name:     strings.TrimSpace(opts.TrustedCAName),
			CertPath: strings.TrimSpace(opts.TrustedCACertPath),
		}
	}

	if strings.TrimSpace(opts.Websocket) != "" {
		ws, err := parseWebsocketFlag(opts.Websocket)
		if err != nil {
			return Route{}, err
		}
		r.Websocket = ws
	}

	return r, nil
}

func parseWebsocketFlag(raw string) (*WebsocketValue, error) {
	v := strings.TrimSpace(raw)
	switch strings.ToLower(v) {
	case "", "auto":
		return nil, nil
	case "false":
		return &WebsocketValue{disabled: true}, nil
	default:
		return &WebsocketValue{url: v}, nil
	}
}

func selectRouteIndex(routes []Route, path string, idx int) (int, error) {
	needle := strings.TrimSpace(path)
	if needle == "" {
		return -1, fmt.Errorf("--path is required")
	}

	matches := make([]int, 0)
	for i, r := range routes {
		if strings.TrimSpace(r.Path) == needle {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		return -1, fmt.Errorf("no route found for path %q", needle)
	}

	if idx < 0 {
		if len(matches) > 1 {
			indices := make([]string, 0, len(matches))
			for _, m := range matches {
				indices = append(indices, strconv.Itoa(m))
			}
			sort.Strings(indices)
			return -1, fmt.Errorf("multiple routes found for path %q; use --index with one of: %s", needle, strings.Join(indices, ", "))
		}
		return matches[0], nil
	}
	if idx < 0 || idx >= len(routes) {
		return -1, fmt.Errorf("--index %d out of range (routes=%d)", idx, len(routes))
	}
	if strings.TrimSpace(routes[idx].Path) != needle {
		return -1, fmt.Errorf("route at --index %d has path %q (expected %q)", idx, strings.TrimSpace(routes[idx].Path), needle)
	}
	return idx, nil
}

func writeConfigYAML(path string, cfg *Config) error {
	body, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal yaml config: %w", err)
	}
	changed, err := writeFileAtomic(path, body, 0o640)
	if err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	if !changed {
		fmt.Println("config unchanged")
	}
	return nil
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
