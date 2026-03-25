package mikrotik

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tedsluis/nmap/internal/model"
)

func Analyze(snapshot *model.MikroTikSnapshot) []model.Finding {
	if snapshot == nil {
		return nil
	}

	var findings []model.Finding
	trunks := trunkPorts(snapshot)
	bridgeByName := map[string]model.MikroTikBridge{}
	for _, bridge := range snapshot.Bridges {
		bridgeByName[bridge.Name] = bridge
	}

	for _, vlan := range snapshot.VLANs {
		if len(vlan.VLANIDs) > 1 && len(vlan.Untagged) > 0 {
			findings = append(findings, model.Finding{
				ID:             "mikrotik-access-multivlan-" + vlan.Bridge + "-" + strings.Join(vlan.VLANIDs, "-"),
				Severity:       "high",
				Title:          "Access ports share a multi-VLAN bridge entry",
				Summary:        fmt.Sprintf("Bridge %s has VLAN entry %s with untagged ports %s.", vlan.Bridge, strings.Join(vlan.VLANIDs, ","), strings.Join(vlan.Untagged, ",")),
				Recommendation: "Create one bridge VLAN entry per VLAN when untagged access ports are involved. Do not combine multiple VLAN IDs in a single access-port entry.",
				Source:         "mikrotik-bridge-vlan-table",
				Evidence:       []string{fmt.Sprintf("vlan-ids=%s untagged=%s", strings.Join(vlan.VLANIDs, ","), strings.Join(vlan.Untagged, ","))},
			})
		}

		if vlan.Dynamic && contains(vlan.VLANIDs, "1") && contains(vlan.CurrentUntagged, vlan.Bridge) {
			var exposed []string
			for _, port := range vlan.CurrentUntagged {
				if port != vlan.Bridge && trunks[port] {
					exposed = append(exposed, port)
				}
			}
			if len(exposed) > 0 {
				findings = append(findings, model.Finding{
					ID:             "mikrotik-cpu-port-vlan1-" + vlan.Bridge,
					Severity:       "high",
					Title:          "CPU port appears reachable via untagged VLAN 1",
					Summary:        fmt.Sprintf("Bridge %s is dynamically untagged on VLAN 1 together with trunk-like ports %s.", vlan.Bridge, strings.Join(exposed, ",")),
					Recommendation: "Separate bridge and trunk PVIDs or enforce tagged-only ingress on the trunk with ingress-filtering and frame-types=admit-only-vlan-tagged.",
					Source:         "mikrotik-bridge-vlan-table",
					Evidence:       []string{fmt.Sprintf("current-untagged=%s", strings.Join(vlan.CurrentUntagged, ","))},
				})
			}
		}
	}

	for _, port := range snapshot.Ports {
		if !trunks[port.Interface] {
			continue
		}
		bridge := bridgeByName[port.Bridge]
		if !port.IngressFiltering || !strings.EqualFold(port.FrameTypes, "admit-only-vlan-tagged") {
			findings = append(findings, model.Finding{
				ID:             "mikrotik-trunk-hardening-" + port.Interface,
				Severity:       "medium",
				Title:          "Tagged trunk is not hardened against untagged ingress",
				Summary:        fmt.Sprintf("Port %s carries tagged VLANs but ingress-filtering=%t and frame-types=%q.", port.Interface, port.IngressFiltering, port.FrameTypes),
				Recommendation: "For tagged-only trunks, enable ingress filtering and set frame-types=admit-only-vlan-tagged.",
				Source:         "mikrotik-bridge-vlan-table",
				Evidence:       []string{fmt.Sprintf("bridge=%s pvid=%s", port.Bridge, port.PVID)},
			})
		}
		if bridge.Name != "" && bridge.PVID != "" && port.PVID == bridge.PVID {
			findings = append(findings, model.Finding{
				ID:             "mikrotik-pvid-match-" + port.Interface,
				Severity:       "medium",
				Title:          "Trunk port PVID matches the bridge CPU-port PVID",
				Summary:        fmt.Sprintf("Bridge %s and port %s both use PVID %s.", bridge.Name, port.Interface, port.PVID),
				Recommendation: "Use a different PVID on the trunk or the bridge, or lock the trunk to tagged-only ingress to avoid accidental management exposure.",
				Source:         "mikrotik-bridge-vlan-table",
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func trunkPorts(snapshot *model.MikroTikSnapshot) map[string]bool {
	trunks := map[string]bool{}
	untaggedCount := map[string]int{}
	for _, vlan := range snapshot.VLANs {
		for _, port := range vlan.Untagged {
			untaggedCount[port]++
		}
		for _, port := range vlan.Tagged {
			trunks[port] = true
		}
		for _, port := range vlan.CurrentTagged {
			trunks[port] = true
		}
	}
	for port, count := range untaggedCount {
		if count > 0 && trunks[port] {
			trunks[port] = true
		}
	}
	return trunks
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
