package topology

import (
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/tedsluis/nmap/internal/mikrotik"
	"github.com/tedsluis/nmap/internal/model"
	"github.com/tedsluis/nmap/internal/system"
)

type BuildOptions struct {
	GeneratedAt time.Time
	Profile     string
	Prefixes    []netip.Prefix
	Inventory   system.Inventory
	Hosts       []model.Host
	MikroTik    *model.MikroTikSnapshot
}

func Build(opts BuildOptions) (*model.Topology, error) {
	if len(opts.Prefixes) == 0 && len(opts.Hosts) == 0 && opts.MikroTik == nil {
		return nil, errors.New("nothing to build")
	}

	prefixes := uniquePrefixes(opts.Prefixes)
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].String() < prefixes[j].String()
	})

	subnets := make([]model.Subnet, 0, len(prefixes))
	subnetIndex := map[string]int{}
	graph := model.Graph{}
	for _, prefix := range prefixes {
		subnet := model.Subnet{
			ID:      "subnet:" + prefix.String(),
			CIDR:    prefix.String(),
			Gateway: gatewayForPrefix(prefix, opts.Inventory.DefaultGateway),
		}
		subnetIndex[subnet.CIDR] = len(subnets)
		subnets = append(subnets, subnet)
		graph.Nodes = append(graph.Nodes, model.GraphNode{
			ID:    subnet.ID,
			Label: subnet.CIDR,
			Type:  "subnet",
		})
	}

	hostCount := 0
	portCount := 0
	neighborCount := 0
	hostByName := make(map[string]string) // Map hostname/system name to host ID
	hostByMAC := make(map[string]string)  // Map MAC to host ID
	
	for _, host := range sortHosts(opts.Hosts) {
		hostCount++
		portCount += len(host.Ports)
		neighborCount += len(host.Neighbors)
		prefix, ok := prefixForIP(host.IP, prefixes)
		if !ok {
			continue
		}
		idx := subnetIndex[prefix.String()]
		subnets[idx].Hosts = append(subnets[idx].Hosts, host)
		graph.Nodes = append(graph.Nodes, model.GraphNode{
			ID:    host.ID,
			Label: host.Label,
			Type:  "host",
		})
		graph.Links = append(graph.Links, model.GraphLink{
			Source: host.ID,
			Target: subnets[idx].ID,
			Kind:   "member-of",
		})
		
		// Build lookup maps for neighbor resolution
		if host.Hostname != "" {
			hostByName[host.Hostname] = host.ID
		}
		if host.MAC != "" {
			hostByMAC[host.MAC] = host.ID
		}
	}
	
	// Create neighbor links after all hosts are processed
	for _, host := range opts.Hosts {
		for _, neighbor := range host.Neighbors {
			targetID := resolveNeighborID(neighbor, hostByName, hostByMAC)
			if targetID != "" {
				graph.Links = append(graph.Links, model.GraphLink{
					Source: host.ID,
					Target: targetID,
					Kind:   neighbor.Protocol + "-neighbor",
				})
			}
		}
	}

	if opts.Inventory.DefaultGateway != "" {
		graph.Nodes = append(graph.Nodes, model.GraphNode{
			ID:    "gateway:" + opts.Inventory.DefaultGateway,
			Label: "Gateway\n" + opts.Inventory.DefaultGateway,
			Type:  "gateway",
		})
		for i := range subnets {
			if subnets[i].Gateway == "" {
				continue
			}
			graph.Links = append(graph.Links, model.GraphLink{
				Source: subnets[i].ID,
				Target: "gateway:" + subnets[i].Gateway,
				Kind:   "routes-via",
			})
		}
	}

	findings := mikrotik.Analyze(opts.MikroTik)
	topo := &model.Topology{
		GeneratedAt: opts.GeneratedAt,
		Profile:     normalizedProfile(opts.Profile),
		Summary: model.Summary{
			Hosts:         hostCount,
			Subnets:       len(subnets),
			OpenPorts:     portCount,
			Neighbors:     neighborCount,
			Findings:      len(findings),
			MikroTikPorts: lenPorts(opts.MikroTik),
		},
		Subnets:  subnets,
		Graph:    graph,
		Findings: findings,
		MikroTik: opts.MikroTik,
	}
	topo.Notes = buildNotes(opts, subnets)
	return topo, nil
}

func prefixForIP(raw string, prefixes []netip.Prefix) (netip.Prefix, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

func gatewayForPrefix(prefix netip.Prefix, gateway string) string {
	if gateway == "" {
		return ""
	}
	addr, err := netip.ParseAddr(gateway)
	if err != nil {
		return ""
	}
	if prefix.Contains(addr) {
		return gateway
	}
	return ""
}

func uniquePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	seen := map[string]struct{}{}
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

func sortHosts(hosts []model.Host) []model.Host {
	out := append([]model.Host(nil), hosts...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].IP < out[j].IP
	})
	return out
}

func normalizedProfile(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "balanced", "deep":
		return strings.ToLower(strings.TrimSpace(profile))
	default:
		return "discovery"
	}
}

func lenPorts(snapshot *model.MikroTikSnapshot) int {
	if snapshot == nil {
		return 0
	}
	return len(snapshot.Ports)
}

func buildNotes(opts BuildOptions, subnets []model.Subnet) []string {
	var notes []string
	notes = append(notes, "This rewrite uses nmap XML output instead of parsing human-readable CLI output.")
	notes = append(notes, "Topology is grouped by subnets first; gateway relationships are inferred from the local route table when available.")
	if opts.MikroTik != nil {
		notes = append(notes, "MikroTik analysis is based on bridge, bridge port, bridge VLAN, and IP address data collected through RouterOS REST.")
	}
	if len(subnets) == 0 {
		notes = append(notes, "No subnets were inferred for discovered hosts; pass explicit --subnets to tighten the scan scope.")
	}
	neighborCount := 0
	for _, host := range opts.Hosts {
		neighborCount += len(host.Neighbors)
	}
	if neighborCount > 0 {
		notes = append(notes, "LLDP/CDP neighbor relationships discovered and included in the topology graph.")
	}
	return notes
}

func resolveNeighborID(neighbor model.Neighbor, hostByName, hostByMAC map[string]string) string {
	// Try to resolve by system name or device ID
	if neighbor.SystemName != "" {
		if id, ok := hostByName[neighbor.SystemName]; ok {
			return id
		}
	}
	if neighbor.DeviceID != "" {
		if id, ok := hostByName[neighbor.DeviceID]; ok {
			return id
		}
	}
	
	// Try to resolve by chassis ID (MAC address)
	if neighbor.ChassisID != "" {
		// Normalize MAC address format
		normalized := strings.ToLower(strings.ReplaceAll(neighbor.ChassisID, "-", ":"))
		if id, ok := hostByMAC[normalized]; ok {
			return id
		}
		// Try original format
		if id, ok := hostByMAC[neighbor.ChassisID]; ok {
			return id
		}
	}
	
	// Try to resolve by management address
	if neighbor.ManagementAddress != "" {
		return "host:" + neighbor.ManagementAddress
	}
	
	return ""
}
