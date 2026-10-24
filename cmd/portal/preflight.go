package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/preflight"
)

// runPreflight checks a configuration against its environment without
// changing anything. Exit status: 0 no failures, 1 failures, 2 invalid
// configuration.
func runPreflight(args []string) int {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	configPath := fs.String("config", envOr("PORTAL_CONFIG", "/etc/mongo-portal/config.yaml"), "path to the configuration file")
	format := fs.String("format", "text", "output format: text or json")
	profiles := fs.String("profile", "", "comma-separated profiles to check (default: all)")
	oidcUser := fs.String("oidc-user", "", "principal name hint for MONGODB-OIDC servers with several identity providers")
	timeout := fs.Duration("timeout", 10*time.Second, "timeout of each network check")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	raw, err := os.ReadFile(*configPath) // #nosec G304 -- operator supplied path
	if err != nil {
		fmt.Fprintln(os.Stderr, "read config:", err)
		return 2
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid configuration:", err)
		return 2
	}
	o := preflight.Options{OIDCUser: *oidcUser, Timeout: *timeout}
	if *profiles != "" {
		o.Profiles = strings.Split(*profiles, ",")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rep := preflight.Run(ctx, cfg, o)
	rep.Version = version
	vars := config.Placeholders(raw)
	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"report": rep, "environmentVariables": vars})
	} else {
		printReport(os.Stdout, rep, vars)
	}
	if rep.Failed() {
		return 1
	}
	return 0
}

func printReport(w io.Writer, rep preflight.Report, vars []string) {
	fmt.Fprintf(w, "mongo-portal %s preflight (read-only)\n", version)
	if len(vars) > 0 {
		fmt.Fprintf(w, "configuration placeholders: %s\n", strings.Join(vars, ", "))
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tAREA\tCHECK\tTARGET\tDETAIL")
	for _, r := range rep.Results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", strings.ToUpper(r.Status), r.Area, r.Check, r.Target, r.Detail)
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\n%d passed, %d warnings, %d failed, %d skipped in %s\n",
		rep.Summary[preflight.Pass], rep.Summary[preflight.Warn], rep.Summary[preflight.Fail], rep.Summary[preflight.Skip], rep.Duration)
}
