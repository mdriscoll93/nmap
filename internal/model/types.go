package model

import "time"

type Topology struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	Profile     string            `json:"profile"`
	Summary     Summary           `json:"summary"`
	Subnets     []Subnet          `json:"subnets"`
	Graph       Graph             `json:"graph"`
	Findings    []Finding         `json:"findings,omitempty"`
	MikroTik    *MikroTikSnapshot `json:"mikrotik,omitempty"`
	Notes       []string          `json:"notes,omitempty"`
}

type Summary struct {
	Hosts         int `json:"hosts"`
	Subnets       int `json:"subnets"`
	OpenPorts     int `json:"openPorts"`
	Findings      int `json:"findings"`
	MikroTikPorts int `json:"mikroTikPorts"`
}

type Subnet struct {
	ID      string `json:"id"`
	CIDR    string `json:"cidr"`
	Gateway string `json:"gateway,omitempty"`
	Hosts   []Host `json:"hosts"`
}

type Host struct {
	ID         string            `json:"id"`
	Label      string            `json:"label"`
	IP         string            `json:"ip"`
	Hostname   string            `json:"hostname,omitempty"`
	MAC        string            `json:"mac,omitempty"`
	Vendor     string            `json:"vendor,omitempty"`
	Status     string            `json:"status,omitempty"`
	DeviceType string            `json:"deviceType,omitempty"`
	OSFamily   string            `json:"osFamily,omitempty"`
	OSDetail   string            `json:"osDetail,omitempty"`
	Latency    string            `json:"latency,omitempty"`
	Distance   int               `json:"distance,omitempty"`
	Ports      []Port            `json:"ports,omitempty"`
	Neighbors  []Neighbor        `json:"neighbors,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
}

type Port struct {
	Protocol string `json:"protocol"`
	Number   int    `json:"number"`
	State    string `json:"state"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

type Neighbor struct {
	Protocol          string `json:"protocol"`
	ChassisID         string `json:"chassisId,omitempty"`
	PortID            string `json:"portId,omitempty"`
	SystemName        string `json:"systemName,omitempty"`
	SystemDescription string `json:"systemDescription,omitempty"`
	Capabilities      string `json:"capabilities,omitempty"`
	ManagementAddress string `json:"managementAddress,omitempty"`
	Platform          string `json:"platform,omitempty"`
	DeviceID          string `json:"deviceId,omitempty"`
}

type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Links []GraphLink `json:"links"`
}

type GraphNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
}

type GraphLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

type Finding struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Title          string   `json:"title"`
	Summary        string   `json:"summary"`
	Recommendation string   `json:"recommendation,omitempty"`
	Source         string   `json:"source,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
}

type MikroTikSnapshot struct {
	Endpoint  string            `json:"endpoint"`
	Bridges   []MikroTikBridge  `json:"bridges"`
	Ports     []MikroTikPort    `json:"ports"`
	VLANs     []MikroTikVLAN    `json:"vlans"`
	Addresses []MikroTikAddress `json:"addresses,omitempty"`
	Identity  string            `json:"identity,omitempty"`
}

type MikroTikBridge struct {
	Name          string `json:"name"`
	PVID          string `json:"pvid,omitempty"`
	VLANFiltering bool   `json:"vlanFiltering"`
}

type MikroTikPort struct {
	Bridge           string `json:"bridge"`
	Interface        string `json:"interface"`
	PVID             string `json:"pvid,omitempty"`
	IngressFiltering bool   `json:"ingressFiltering"`
	FrameTypes       string `json:"frameTypes,omitempty"`
	HardwareOffload  bool   `json:"hardwareOffload"`
	Trusted          bool   `json:"trusted"`
}

type MikroTikVLAN struct {
	Bridge          string   `json:"bridge"`
	VLANIDs         []string `json:"vlanIds"`
	Tagged          []string `json:"tagged,omitempty"`
	Untagged        []string `json:"untagged,omitempty"`
	CurrentTagged   []string `json:"currentTagged,omitempty"`
	CurrentUntagged []string `json:"currentUntagged,omitempty"`
	Dynamic         bool     `json:"dynamic"`
	Comment         string   `json:"comment,omitempty"`
}

type MikroTikAddress struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Network   string `json:"network,omitempty"`
}
