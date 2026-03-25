package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/tedsluis/nmap/internal/demo"
	"github.com/tedsluis/nmap/internal/discovery"
	"github.com/tedsluis/nmap/internal/mikrotik"
	"github.com/tedsluis/nmap/internal/model"
	"github.com/tedsluis/nmap/internal/server"
	"github.com/tedsluis/nmap/internal/system"
	"github.com/tedsluis/nmap/internal/topology"
)

func main() {
	var (
		listen           = flag.String("listen", ":8080", "HTTP listen address")
		subnetsRaw       = flag.String("subnets", "", "Comma separated CIDRs to scan")
		nmapXMLRaw       = flag.String("nmap-xml", "", "Comma separated nmap XML files to import instead of running nmap")
		nmapPath         = flag.String("nmap-path", "nmap", "Path to nmap binary")
		profile          = flag.String("profile", "discovery", "Scan profile: discovery, balanced, deep")
		mikrotikURL      = flag.String("mikrotik-url", "", "MikroTik router URL or /rest endpoint")
		mikrotikUser     = flag.String("mikrotik-user", "", "MikroTik username")
		mikrotikPassword = flag.String("mikrotik-password", "", "MikroTik password")
		mikrotikInsecure = flag.Bool("mikrotik-insecure", false, "Skip TLS verification for MikroTik REST calls")
		demoMode         = flag.Bool("demo", false, "Start with demo data instead of scanning")
	)
	flag.Parse()

	topo, err := loadTopology(context.Background(), options{
		Subnets:          *subnetsRaw,
		NmapXML:          *nmapXMLRaw,
		NmapPath:         *nmapPath,
		Profile:          *profile,
		MikroTikURL:      *mikrotikURL,
		MikroTikUser:     *mikrotikUser,
		MikroTikPassword: *mikrotikPassword,
		MikroTikInsecure: *mikrotikInsecure,
		Demo:             *demoMode,
	})
	if err != nil {
		log.Fatalf("load topology: %v", err)
	}

	addr := strings.TrimSpace(*listen)
	if addr == "" {
		addr = ":8080"
	}

	log.Printf("serving %d hosts across %d subnets on %s", topo.Summary.Hosts, topo.Summary.Subnets, addr)
	if err := server.ListenAndServe(addr, topo); err != nil {
		log.Fatal(err)
	}
}

type options struct {
	Subnets          string
	NmapXML          string
	NmapPath         string
	Profile          string
	MikroTikURL      string
	MikroTikUser     string
	MikroTikPassword string
	MikroTikInsecure bool
	Demo             bool
}

func loadTopology(ctx context.Context, opts options) (*model.Topology, error) {
	if opts.Demo {
		return demo.Topology(), nil
	}

	inventory, _ := system.Discover(ctx)
	prefixes, err := parsePrefixes(opts.Subnets, inventory.Prefixes())
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 && strings.TrimSpace(opts.NmapXML) == "" {
		return nil, errors.New("no scan scope found: pass --subnets, --nmap-xml, or use --demo")
	}

	var hosts []model.Host
	if xmlFiles := splitCSV(opts.NmapXML); len(xmlFiles) > 0 {
		hosts, err = discovery.ParseFiles(xmlFiles)
		if err != nil {
			return nil, err
		}
	} else {
		scanCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		hosts, err = discovery.Run(scanCtx, opts.NmapPath, prefixes, opts.Profile)
		if err != nil {
			return nil, err
		}
	}

	var snapshot *model.MikroTikSnapshot
	if strings.TrimSpace(opts.MikroTikURL) != "" {
		client := mikrotik.NewClient(opts.MikroTikURL, opts.MikroTikUser, opts.MikroTikPassword, opts.MikroTikInsecure)
		snapshot, err = client.Collect(ctx)
		if err != nil {
			return nil, fmt.Errorf("collect mikrotik data: %w", err)
		}
	}

	build, err := topology.Build(topology.BuildOptions{
		GeneratedAt: time.Now(),
		Profile:     opts.Profile,
		Prefixes:    prefixes,
		Inventory:   inventory,
		Hosts:       hosts,
		MikroTik:    snapshot,
	})
	if err != nil {
		return nil, err
	}
	return build, nil
}

func parsePrefixes(raw string, fallback []netip.Prefix) ([]netip.Prefix, error) {
	var parsed []netip.Prefix
	for _, item := range splitCSV(raw) {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			return nil, fmt.Errorf("parse subnet %q: %w", item, err)
		}
		parsed = append(parsed, prefix.Masked())
	}
	if len(parsed) == 0 {
		parsed = append(parsed, fallback...)
	}
	return uniquePrefixes(parsed), nil
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func uniquePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	seen := make(map[string]struct{}, len(prefixes))
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		key := prefix.Masked().String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, prefix.Masked())
	}
	return out
}

func init() {
	log.SetOutput(os.Stdout)
}
