package discovery

import (
	"testing"

	"github.com/tedsluis/nmap/internal/model"
)

func TestParseLLDPNeighbors(t *testing.T) {
	tests := []struct {
		name     string
		script   nmapScript
		expected []model.Neighbor
	}{
		{
			name: "LLDP with basic fields",
			script: nmapScript{
				ID: "broadcast-lldp-discovery",
				Tables: []nmapScriptTable{
					{
						Elems: []nmapScriptElem{
							{Key: "chassis-id", Value: "00:11:22:33:44:55"},
							{Key: "port-id", Value: "eth1"},
							{Key: "system-name", Value: "switch1.local"},
							{Key: "system-description", Value: "Cisco Switch"},
							{Key: "capabilities", Value: "Bridge, Router"},
						},
					},
				},
			},
			expected: []model.Neighbor{
				{
					Protocol:          "lldp",
					ChassisID:         "00:11:22:33:44:55",
					PortID:            "eth1",
					SystemName:        "switch1.local",
					SystemDescription: "Cisco Switch",
					Capabilities:      "Bridge, Router",
				},
			},
		},
		{
			name: "LLDP with nested tables",
			script: nmapScript{
				ID: "lldp-discovery",
				Tables: []nmapScriptTable{
					{
						Table: []nmapScriptTable{
							{
								Elems: []nmapScriptElem{
									{Key: "chassis id", Value: "aa:bb:cc:dd:ee:ff"},
									{Key: "port id", Value: "GigabitEthernet1/0/1"},
									{Key: "system name", Value: "core-switch"},
									{Key: "management address", Value: "192.168.1.1"},
								},
							},
						},
					},
				},
			},
			expected: []model.Neighbor{
				{
					Protocol:          "lldp",
					ChassisID:         "aa:bb:cc:dd:ee:ff",
					PortID:            "GigabitEthernet1/0/1",
					SystemName:        "core-switch",
					ManagementAddress: "192.168.1.1",
				},
			},
		},
		{
			name: "LLDP with minimal data",
			script: nmapScript{
				ID: "broadcast-lldp-discovery",
				Tables: []nmapScriptTable{
					{
						Elems: []nmapScriptElem{
							{Key: "chassis-id", Value: "11:22:33:44:55:66"},
						},
					},
				},
			},
			expected: []model.Neighbor{
				{
					Protocol:  "lldp",
					ChassisID: "11:22:33:44:55:66",
				},
			},
		},
		{
			name: "LLDP with no data",
			script: nmapScript{
				ID:     "broadcast-lldp-discovery",
				Tables: []nmapScriptTable{},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLLDPNeighbors(tt.script)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d neighbors, got %d", len(tt.expected), len(result))
				return
			}
			for i := range result {
				if result[i].Protocol != tt.expected[i].Protocol {
					t.Errorf("neighbor %d: expected protocol %q, got %q", i, tt.expected[i].Protocol, result[i].Protocol)
				}
				if result[i].ChassisID != tt.expected[i].ChassisID {
					t.Errorf("neighbor %d: expected chassis ID %q, got %q", i, tt.expected[i].ChassisID, result[i].ChassisID)
				}
				if result[i].PortID != tt.expected[i].PortID {
					t.Errorf("neighbor %d: expected port ID %q, got %q", i, tt.expected[i].PortID, result[i].PortID)
				}
				if result[i].SystemName != tt.expected[i].SystemName {
					t.Errorf("neighbor %d: expected system name %q, got %q", i, tt.expected[i].SystemName, result[i].SystemName)
				}
			}
		})
	}
}

func TestParseCDPNeighbors(t *testing.T) {
	tests := []struct {
		name     string
		script   nmapScript
		expected []model.Neighbor
	}{
		{
			name: "CDP with basic fields",
			script: nmapScript{
				ID: "broadcast-cdp-discovery",
				Tables: []nmapScriptTable{
					{
						Elems: []nmapScriptElem{
							{Key: "device-id", Value: "router1.example.com"},
							{Key: "port-id", Value: "FastEthernet0/1"},
							{Key: "platform", Value: "Cisco 2960"},
							{Key: "capabilities", Value: "Switch IGMP"},
							{Key: "ip-address", Value: "10.0.0.1"},
						},
					},
				},
			},
			expected: []model.Neighbor{
				{
					Protocol:          "cdp",
					DeviceID:          "router1.example.com",
					PortID:            "FastEthernet0/1",
					Platform:          "Cisco 2960",
					Capabilities:      "Switch IGMP",
					ManagementAddress: "10.0.0.1",
				},
			},
		},
		{
			name: "CDP with nested tables",
			script: nmapScript{
				ID: "cdp-discovery",
				Tables: []nmapScriptTable{
					{
						Table: []nmapScriptTable{
							{
								Elems: []nmapScriptElem{
									{Key: "device id", Value: "switch2"},
									{Key: "port id", Value: "Gi0/0/1"},
									{Key: "platform", Value: "Catalyst 3850"},
								},
							},
						},
					},
				},
			},
			expected: []model.Neighbor{
				{
					Protocol: "cdp",
					DeviceID: "switch2",
					PortID:   "Gi0/0/1",
					Platform: "Catalyst 3850",
				},
			},
		},
		{
			name: "CDP with no data",
			script: nmapScript{
				ID:     "broadcast-cdp-discovery",
				Tables: []nmapScriptTable{},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCDPNeighbors(tt.script)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d neighbors, got %d", len(tt.expected), len(result))
				return
			}
			for i := range result {
				if result[i].Protocol != tt.expected[i].Protocol {
					t.Errorf("neighbor %d: expected protocol %q, got %q", i, tt.expected[i].Protocol, result[i].Protocol)
				}
				if result[i].DeviceID != tt.expected[i].DeviceID {
					t.Errorf("neighbor %d: expected device ID %q, got %q", i, tt.expected[i].DeviceID, result[i].DeviceID)
				}
				if result[i].PortID != tt.expected[i].PortID {
					t.Errorf("neighbor %d: expected port ID %q, got %q", i, tt.expected[i].PortID, result[i].PortID)
				}
				if result[i].Platform != tt.expected[i].Platform {
					t.Errorf("neighbor %d: expected platform %q, got %q", i, tt.expected[i].Platform, result[i].Platform)
				}
			}
		})
	}
}

func TestParseNeighborsFromXML(t *testing.T) {
	xmlData := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostscript>
      <script id="broadcast-lldp-discovery" output="">
        <table>
          <elem key="chassis-id">00:11:22:33:44:55</elem>
          <elem key="port-id">eth1</elem>
          <elem key="system-name">switch1</elem>
        </table>
      </script>
    </hostscript>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.1.20" addrtype="ipv4"/>
    <hostscript>
      <script id="broadcast-cdp-discovery" output="">
        <table>
          <elem key="device-id">router1</elem>
          <elem key="port-id">Gi0/1</elem>
          <elem key="platform">Cisco ISR</elem>
        </table>
      </script>
    </hostscript>
  </host>
</nmaprun>`)

	hosts, err := Parse(xmlData)
	if err != nil {
		t.Fatalf("failed to parse XML: %v", err)
	}

	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}

	// Check first host (LLDP)
	if len(hosts[0].Neighbors) != 1 {
		t.Errorf("host 1: expected 1 neighbor, got %d", len(hosts[0].Neighbors))
	} else {
		n := hosts[0].Neighbors[0]
		if n.Protocol != "lldp" {
			t.Errorf("host 1: expected LLDP protocol, got %q", n.Protocol)
		}
		if n.ChassisID != "00:11:22:33:44:55" {
			t.Errorf("host 1: expected chassis ID 00:11:22:33:44:55, got %q", n.ChassisID)
		}
		if n.SystemName != "switch1" {
			t.Errorf("host 1: expected system name switch1, got %q", n.SystemName)
		}
	}

	// Check second host (CDP)
	if len(hosts[1].Neighbors) != 1 {
		t.Errorf("host 2: expected 1 neighbor, got %d", len(hosts[1].Neighbors))
	} else {
		n := hosts[1].Neighbors[0]
		if n.Protocol != "cdp" {
			t.Errorf("host 2: expected CDP protocol, got %q", n.Protocol)
		}
		if n.DeviceID != "router1" {
			t.Errorf("host 2: expected device ID router1, got %q", n.DeviceID)
		}
		if n.Platform != "Cisco ISR" {
			t.Errorf("host 2: expected platform Cisco ISR, got %q", n.Platform)
		}
	}
}
