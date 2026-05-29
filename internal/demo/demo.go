package demo

import (
	"net/netip"
	"time"

	"github.com/tedsluis/nmap/internal/model"
	"github.com/tedsluis/nmap/internal/system"
	"github.com/tedsluis/nmap/internal/topology"
)

func Topology() *model.Topology {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.10.10.0/24"),
		netip.MustParsePrefix("10.10.20.0/24"),
	}

	hosts := []model.Host{
		{
			ID:         "host:10.10.10.1",
			Label:      "core-router\n10.10.10.1",
			IP:         "10.10.10.1",
			Hostname:   "core-router",
			MAC:        "00:11:22:33:44:55",
			Status:     "up",
			DeviceType: "router",
			OSFamily:   "RouterOS",
			Ports: []model.Port{
				{Protocol: "tcp", Number: 80, State: "open", Service: "www"},
				{Protocol: "tcp", Number: 8729, State: "open", Service: "api-ssl"},
			},
			Neighbors: []model.Neighbor{
				{
					Protocol:     "lldp",
					ChassisID:    "aa:bb:cc:dd:ee:ff",
					PortID:       "eth1",
					SystemName:   "hypervisor-1",
					Capabilities: "Bridge",
				},
			},
		},
		{
			ID:         "host:10.10.10.50",
			Label:      "hypervisor-1\n10.10.10.50",
			IP:         "10.10.10.50",
			Hostname:   "hypervisor-1",
			MAC:        "aa:bb:cc:dd:ee:ff",
			Status:     "up",
			DeviceType: "hypervisor",
			OSFamily:   "Linux",
			Ports: []model.Port{
				{Protocol: "tcp", Number: 22, State: "open", Service: "ssh"},
				{Protocol: "tcp", Number: 443, State: "open", Service: "https"},
			},
			Neighbors: []model.Neighbor{
				{
					Protocol:          "lldp",
					ChassisID:         "00:11:22:33:44:55",
					PortID:            "ether1",
					SystemName:        "core-router",
					SystemDescription: "MikroTik RouterOS",
					Capabilities:      "Router",
				},
			},
		},
		{
			ID:         "host:10.10.20.20",
			Label:      "camera-20\n10.10.20.20",
			IP:         "10.10.20.20",
			Hostname:   "camera-20",
			Status:     "up",
			DeviceType: "camera",
			OSFamily:   "Linux",
			Ports: []model.Port{
				{Protocol: "tcp", Number: 80, State: "open", Service: "http"},
			},
		},
	}

	snapshot := &model.MikroTikSnapshot{
		Endpoint: "https://router.example/rest",
		Identity: "lab-router",
		Bridges: []model.MikroTikBridge{
			{Name: "bridge1", PVID: "1", VLANFiltering: true},
		},
		Ports: []model.MikroTikPort{
			{Bridge: "bridge1", Interface: "sfp-sfpplus1", PVID: "1", IngressFiltering: false, FrameTypes: "admit-all", HardwareOffload: true},
			{Bridge: "bridge1", Interface: "ether2", PVID: "20", IngressFiltering: true, FrameTypes: "admit-only-untagged-and-priority-tagged"},
			{Bridge: "bridge1", Interface: "ether3", PVID: "30", IngressFiltering: true, FrameTypes: "admit-only-untagged-and-priority-tagged"},
		},
		VLANs: []model.MikroTikVLAN{
			{Bridge: "bridge1", VLANIDs: []string{"20", "30"}, Tagged: []string{"sfp-sfpplus1"}, Untagged: []string{"ether2", "ether3"}},
			{Bridge: "bridge1", VLANIDs: []string{"1"}, CurrentTagged: []string{"sfp-sfpplus1"}, CurrentUntagged: []string{"bridge1", "sfp-sfpplus1"}, Dynamic: true},
		},
		Addresses: []model.MikroTikAddress{
			{Address: "10.10.10.1/24", Interface: "bridge1", Network: "10.10.10.0"},
			{Address: "10.10.20.1/24", Interface: "vlan20", Network: "10.10.20.0"},
		},
	}

	topo, err := topology.Build(topology.BuildOptions{
		GeneratedAt: time.Now(),
		Profile:     "balanced",
		Prefixes:    prefixes,
		Inventory: system.Inventory{
			DefaultGateway: "10.10.10.1",
		},
		Hosts:    hosts,
		MikroTik: snapshot,
	})
	if err != nil {
		panic(err)
	}
	return topo
}
