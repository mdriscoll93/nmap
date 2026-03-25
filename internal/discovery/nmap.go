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
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "discovery":
		return append(base, "-sn")
	case "balanced":
		return append(base, "-sS", "-sV", "--top-ports", "50", "-O")
	case "deep":
		return append(base, "-A")
	default:
		return append(base, "-sn")
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
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts     `xml:"ports"`
	OS        nmapOS        `xml:"os"`
	Times     nmapTimes     `xml:"times"`
	Distance  nmapDistance  `xml:"distance"`
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
