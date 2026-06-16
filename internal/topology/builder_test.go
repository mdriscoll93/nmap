package topology

import (
	"net/netip"
	"testing"

	"github.com/tedsluis/nmap/internal/model"
)

func TestResolveNeighborIDManagementAddressMustMatchKnownHost(t *testing.T) {
	hostByName := map[string]string{"switch1": "host:10.0.0.2"}
	hostByMAC := map[string]string{"aa:bb:cc:dd:ee:ff": "host:10.0.0.2"}
	hostByIP := map[string]string{"10.0.0.2": "host:10.0.0.2"}

	if got := resolveNeighborID(model.Neighbor{ManagementAddress: "10.0.0.200"}, hostByName, hostByMAC, hostByIP); got != "" {
		t.Fatalf("expected unknown management address to return empty target, got %q", got)
	}

	if got := resolveNeighborID(model.Neighbor{ManagementAddress: "10.0.0.2"}, hostByName, hostByMAC, hostByIP); got != "host:10.0.0.2" {
		t.Fatalf("expected known management address to resolve host ID, got %q", got)
	}
}

func TestResolveNeighborIDNormalizesHostAndMACKeys(t *testing.T) {
	hostByName := map[string]string{"switch1": "host:10.0.0.2"}
	hostByMAC := map[string]string{"aa:bb:cc:dd:ee:ff": "host:10.0.0.2"}
	hostByIP := map[string]string{}

	if got := resolveNeighborID(model.Neighbor{SystemName: "Switch1.example.com."}, hostByName, hostByMAC, hostByIP); got != "host:10.0.0.2" {
		t.Fatalf("expected normalized system name to resolve host ID, got %q", got)
	}

	if got := resolveNeighborID(model.Neighbor{ChassisID: "AA-BB-CC-DD-EE-FF"}, hostByName, hostByMAC, hostByIP); got != "host:10.0.0.2" {
		t.Fatalf("expected normalized chassis ID to resolve host ID, got %q", got)
	}
}

func TestBuildSkipsNeighborLinksForHostsOutsideGraph(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	hosts := []model.Host{
		{
			ID:       "host:10.0.0.2",
			IP:       "10.0.0.2",
			Label:    "10.0.0.2",
			Hostname: "switch1",
		},
		{
			ID:    "host:10.0.1.10",
			IP:    "10.0.1.10",
			Label: "10.0.1.10",
			Neighbors: []model.Neighbor{
				{
					Protocol:   "lldp",
					SystemName: "switch1",
				},
			},
		},
	}

	topo, err := Build(BuildOptions{
		Prefixes: []netip.Prefix{prefix},
		Hosts:    hosts,
	})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	for _, link := range topo.Graph.Links {
		if link.Source == "host:10.0.1.10" {
			t.Fatalf("unexpected neighbor link from host outside graph: %+v", link)
		}
	}
}
