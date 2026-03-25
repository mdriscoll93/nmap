package system

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"sort"
)

type Inventory struct {
	Interfaces     []InterfaceAddress
	DefaultGateway string
}

type InterfaceAddress struct {
	Name   string
	Prefix netip.Prefix
}

func (i Inventory) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(i.Interfaces))
	seen := map[string]struct{}{}
	for _, iface := range i.Interfaces {
		key := iface.Prefix.Masked().String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, iface.Prefix.Masked())
	}
	sort.Slice(out, func(a, b int) bool {
		return out[a].String() < out[b].String()
	})
	return out
}

func Discover(ctx context.Context) (Inventory, error) {
	if _, err := exec.LookPath("ip"); err != nil {
		return Inventory{}, errors.New("ip command not found")
	}

	var inv Inventory
	ifaces, err := discoverInterfaces(ctx)
	if err == nil {
		inv.Interfaces = ifaces
	}
	if gateway, err := discoverDefaultGateway(ctx); err == nil {
		inv.DefaultGateway = gateway
	}
	return inv, nil
}

func discoverInterfaces(ctx context.Context) ([]InterfaceAddress, error) {
	cmd := exec.CommandContext(ctx, "ip", "-j", "address", "show")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var rows []struct {
		IfName   string `json:"ifname"`
		AddrInfo []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		return nil, err
	}

	var out []InterfaceAddress
	for _, row := range rows {
		for _, addr := range row.AddrInfo {
			if addr.Family != "inet" {
				continue
			}
			prefix, err := netip.ParsePrefix(addr.Local + "/" + itoa(addr.PrefixLen))
			if err != nil || prefix.Addr().IsLoopback() {
				continue
			}
			out = append(out, InterfaceAddress{Name: row.IfName, Prefix: prefix.Masked()})
		}
	}
	return out, nil
}

func discoverDefaultGateway(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "ip", "-j", "route", "show")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	var rows []struct {
		Dst     string `json:"dst"`
		Gateway string `json:"gateway"`
	}
	if err := json.Unmarshal(output, &rows); err != nil {
		return "", err
	}
	for _, row := range rows {
		if row.Dst == "default" && row.Gateway != "" {
			return row.Gateway, nil
		}
	}
	return "", errors.New("default gateway not found")
}

func itoa(v int) string {
	switch {
	case v == 0:
		return "0"
	case v < 10:
		return string(rune('0' + v))
	default:
		var buf [3]byte
		i := len(buf)
		for v > 0 {
			i--
			buf[i] = byte('0' + (v % 10))
			v /= 10
		}
		return string(buf[i:])
	}
}
