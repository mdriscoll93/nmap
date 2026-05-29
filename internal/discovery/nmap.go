package discovery

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/tedsluis/nmap/internal/model"
)

func Run(ctx context.Context, binary string, prefixes []netip.Prefix, profile string) ([]model.Host, error) {
	args := profileArgs(profile)
	for _, prefix := range prefixes {
		args = append(args, prefix.String())
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("run nmap %q: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return Parse(output)
}

func ParseFiles(paths []string) ([]model.Host, error) {
	var all []model.Host
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		hosts, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		all = append(all, hosts...)
	}
	return dedupeHosts(all), nil
}

func Parse(data []byte) ([]model.Host, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}

	var hosts []model.Host
	for _, raw := range run.Hosts {
		host := toHost(raw)
		if host.IP == "" {
			continue
		}
		hosts = append(hosts, host)
	}
	return dedupeHosts(hosts), nil
}

func profileArgs(profile string) []string {
	base := []string{"-n", "-oX", "-"}
	scripts := []string{"--script", "broadcast-lldp-discovery,broadcast-cdp-discovery"}
	
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "discovery":
		return append(append(base, "-sn"), scripts...)
	case "balanced":
		return append(append(base, "-sS", "-sV", "--top-ports", "50", "-O"), scripts...)
	case "deep":
		return append(append(base, "-A"), scripts...)
	default:
		return append(append(base, "-sn"), scripts...)
	}
}

func toHost(raw nmapHost) model.Host {
	host := model.Host{
		Status: strings.TrimSpace(raw.Status.State),
		Meta:   map[string]string{},
	}

	for _, address := range raw.Addresses {
		switch address.AddrType {
		case "ipv4":
			host.IP = address.Addr
			host.ID = "host:" + address.Addr
		case "mac":
			host.MAC = address.Addr
			host.Vendor = address.Vendor
		}
	}
	for _, hostname := range raw.Hostnames.Hostnames {
		if hostname.Name != "" {
			host.Hostname = hostname.Name
			break
		}
	}
	if host.Hostname != "" {
		host.Label = host.Hostname + "\n" + host.IP
	} else {
		host.Label = host.IP
	}
	if raw.Times.SRTT != "" {
		host.Latency = raw.Times.SRTT
	}
	if raw.Distance.Value > 0 {
		host.Distance = raw.Distance.Value
	}
	if len(raw.OS.Matches) > 0 {
		host.OSDetail = raw.OS.Matches[0].Name
		if len(raw.OS.Matches[0].Classes) > 0 {
			host.OSFamily = raw.OS.Matches[0].Classes[0].OSFamily
			host.DeviceType = raw.OS.Matches[0].Classes[0].DeviceType
		}
	}
	for _, port := range raw.Ports.Ports {
		host.Ports = append(host.Ports, model.Port{
			Protocol: string(port.Protocol),
			Number:   port.PortID,
			State:    port.State.State,
			Service:  port.Service.Name,
			Product:  port.Service.Product,
			Version:  port.Service.Version,
		})
	}
	sort.Slice(host.Ports, func(i, j int) bool {
		if host.Ports[i].Number == host.Ports[j].Number {
			return host.Ports[i].Protocol < host.Ports[j].Protocol
		}
		return host.Ports[i].Number < host.Ports[j].Number
	})
	
	// Parse LLDP/CDP neighbors from hostscripts
	for _, script := range raw.HostScripts.Scripts {
		if script.ID == "broadcast-lldp-discovery" || script.ID == "lldp-discovery" {
			host.Neighbors = append(host.Neighbors, parseLLDPNeighbors(script)...)
		} else if script.ID == "broadcast-cdp-discovery" || script.ID == "cdp-discovery" {
			host.Neighbors = append(host.Neighbors, parseCDPNeighbors(script)...)
		}
	}
	
	return host
}

func dedupeHosts(hosts []model.Host) []model.Host {
	merged := make(map[string]model.Host, len(hosts))
	for _, host := range hosts {
		if host.IP == "" {
			continue
		}
		current, ok := merged[host.IP]
		if !ok || len(host.Ports) > len(current.Ports) {
			merged[host.IP] = host
			continue
		}
		if current.Hostname == "" && host.Hostname != "" {
			current.Hostname = host.Hostname
			current.Label = host.Label
		}
		if current.MAC == "" && host.MAC != "" {
			current.MAC = host.MAC
			current.Vendor = host.Vendor
		}
		if current.OSDetail == "" && host.OSDetail != "" {
			current.OSDetail = host.OSDetail
			current.OSFamily = host.OSFamily
			current.DeviceType = host.DeviceType
		}
		// Merge neighbors without duplicates
		if len(host.Neighbors) > 0 {
			neighborMap := make(map[string]model.Neighbor)
			for _, n := range current.Neighbors {
				key := n.Protocol + ":" + n.ChassisID + n.DeviceID + n.PortID
				neighborMap[key] = n
			}
			for _, n := range host.Neighbors {
				key := n.Protocol + ":" + n.ChassisID + n.DeviceID + n.PortID
				if _, exists := neighborMap[key]; !exists {
					neighborMap[key] = n
				}
			}
			current.Neighbors = make([]model.Neighbor, 0, len(neighborMap))
			for _, n := range neighborMap {
				current.Neighbors = append(current.Neighbors, n)
			}
		}
		merged[host.IP] = current
	}

	out := make([]model.Host, 0, len(merged))
	for _, host := range merged {
		out = append(out, host)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].IP < out[j].IP
	})
	return out
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status      nmapStatus      `xml:"status"`
	Addresses   []nmapAddress   `xml:"address"`
	Hostnames   nmapHostnames   `xml:"hostnames"`
	Ports       nmapPorts       `xml:"ports"`
	OS          nmapOS          `xml:"os"`
	Times       nmapTimes       `xml:"times"`
	Distance    nmapDistance    `xml:"distance"`
	HostScripts nmapHostScripts `xml:"hostscript"`
}

type nmapHostScripts struct {
	Scripts []nmapScript `xml:"script"`
}

type nmapScript struct {
	ID     string            `xml:"id,attr"`
	Output string            `xml:"output,attr"`
	Tables []nmapScriptTable `xml:"table"`
}

type nmapScriptTable struct {
	Key   string             `xml:"key,attr"`
	Elems []nmapScriptElem   `xml:"elem"`
	Table []nmapScriptTable  `xml:"table"`
}

type nmapScriptElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol intAsString `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
}

type nmapOS struct {
	Matches []struct {
		Name    string `xml:"name,attr"`
		Classes []struct {
			OSFamily   string `xml:"osfamily,attr"`
			DeviceType string `xml:"type,attr"`
		} `xml:"osclass"`
	} `xml:"osmatch"`
}

type nmapTimes struct {
	SRTT string `xml:"srtt,attr"`
}

type nmapDistance struct {
	Value int `xml:"value,attr"`
}

type intAsString string

func (s intAsString) String() string { return string(s) }

func parseLLDPNeighbors(script nmapScript) []model.Neighbor {
	var neighbors []model.Neighbor
	
	// LLDP data is typically in nested tables
	for _, table := range script.Tables {
		neighbor := model.Neighbor{
			Protocol: "lldp",
		}
		
		// Parse both direct elems and nested table elems
		for _, elem := range table.Elems {
			switch strings.ToLower(elem.Key) {
			case "chassis-id", "chassis id":
				neighbor.ChassisID = strings.TrimSpace(elem.Value)
			case "port-id", "port id":
				neighbor.PortID = strings.TrimSpace(elem.Value)
			case "system-name", "system name":
				neighbor.SystemName = strings.TrimSpace(elem.Value)
			case "system-description", "system description":
				neighbor.SystemDescription = strings.TrimSpace(elem.Value)
			case "capabilities":
				neighbor.Capabilities = strings.TrimSpace(elem.Value)
			case "management-address", "management address":
				neighbor.ManagementAddress = strings.TrimSpace(elem.Value)
			}
		}
		
		// Parse nested tables
		for _, nestedTable := range table.Table {
			for _, elem := range nestedTable.Elems {
				switch strings.ToLower(elem.Key) {
				case "chassis-id", "chassis id":
					neighbor.ChassisID = strings.TrimSpace(elem.Value)
				case "port-id", "port id":
					neighbor.PortID = strings.TrimSpace(elem.Value)
				case "system-name", "system name":
					neighbor.SystemName = strings.TrimSpace(elem.Value)
				case "system-description", "system description":
					neighbor.SystemDescription = strings.TrimSpace(elem.Value)
				case "capabilities":
					neighbor.Capabilities = strings.TrimSpace(elem.Value)
				case "management-address", "management address":
					neighbor.ManagementAddress = strings.TrimSpace(elem.Value)
				}
			}
		}
		
		// Only add if we have meaningful data
		if neighbor.ChassisID != "" || neighbor.SystemName != "" || neighbor.PortID != "" {
			neighbors = append(neighbors, neighbor)
		}
	}
	
	return neighbors
}

func parseCDPNeighbors(script nmapScript) []model.Neighbor {
	var neighbors []model.Neighbor
	
	// CDP data is typically in nested tables
	for _, table := range script.Tables {
		neighbor := model.Neighbor{
			Protocol: "cdp",
		}
		
		// Parse both direct elems and nested table elems
		for _, elem := range table.Elems {
			switch strings.ToLower(elem.Key) {
			case "device-id", "device id":
				neighbor.DeviceID = strings.TrimSpace(elem.Value)
			case "port-id", "port id":
				neighbor.PortID = strings.TrimSpace(elem.Value)
			case "platform":
				neighbor.Platform = strings.TrimSpace(elem.Value)
			case "capabilities":
				neighbor.Capabilities = strings.TrimSpace(elem.Value)
			case "ip-address", "ip address":
				neighbor.ManagementAddress = strings.TrimSpace(elem.Value)
			}
		}
		
		// Parse nested tables
		for _, nestedTable := range table.Table {
			for _, elem := range nestedTable.Elems {
				switch strings.ToLower(elem.Key) {
				case "device-id", "device id":
					neighbor.DeviceID = strings.TrimSpace(elem.Value)
				case "port-id", "port id":
					neighbor.PortID = strings.TrimSpace(elem.Value)
				case "platform":
					neighbor.Platform = strings.TrimSpace(elem.Value)
				case "capabilities":
					neighbor.Capabilities = strings.TrimSpace(elem.Value)
				case "ip-address", "ip address":
					neighbor.ManagementAddress = strings.TrimSpace(elem.Value)
				}
			}
		}
		
		// Only add if we have meaningful data
		if neighbor.DeviceID != "" || neighbor.PortID != "" || neighbor.Platform != "" {
			neighbors = append(neighbors, neighbor)
		}
	}
	
	return neighbors
}
