package mikrotik

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tedsluis/nmap/internal/model"
)

type Client struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

func NewClient(endpoint, username, password string, insecure bool) *Client {
	baseURL := normalizeBaseURL(endpoint)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec
	return &Client{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		},
	}
}

func (c *Client) Collect(ctx context.Context) (*model.MikroTikSnapshot, error) {
	snapshot := &model.MikroTikSnapshot{Endpoint: c.baseURL}

	var identity struct {
		Name string `json:"name"`
	}
	if err := c.get(ctx, "/system/identity", &identity); err == nil {
		snapshot.Identity = identity.Name
	}

	var bridges []struct {
		Name          string `json:"name"`
		PVID          string `json:"pvid"`
		VLANFiltering string `json:"vlan-filtering"`
	}
	if err := c.get(ctx, "/interface/bridge", &bridges); err != nil {
		return nil, err
	}
	for _, bridge := range bridges {
		snapshot.Bridges = append(snapshot.Bridges, model.MikroTikBridge{
			Name:          bridge.Name,
			PVID:          bridge.PVID,
			VLANFiltering: parseBool(bridge.VLANFiltering),
		})
	}

	var ports []struct {
		Bridge           string `json:"bridge"`
		Interface        string `json:"interface"`
		PVID             string `json:"pvid"`
		IngressFiltering string `json:"ingress-filtering"`
		FrameTypes       string `json:"frame-types"`
		HW               string `json:"hw"`
		Trusted          string `json:"trusted"`
	}
	if err := c.get(ctx, "/interface/bridge/port", &ports); err != nil {
		return nil, err
	}
	for _, port := range ports {
		snapshot.Ports = append(snapshot.Ports, model.MikroTikPort{
			Bridge:           port.Bridge,
			Interface:        port.Interface,
			PVID:             port.PVID,
			IngressFiltering: parseBool(port.IngressFiltering),
			FrameTypes:       port.FrameTypes,
			HardwareOffload:  parseBool(port.HW),
			Trusted:          parseBool(port.Trusted),
		})
	}

	var vlans []struct {
		Bridge          string `json:"bridge"`
		VLANIDs         string `json:"vlan-ids"`
		Tagged          string `json:"tagged"`
		Untagged        string `json:"untagged"`
		CurrentTagged   string `json:"current-tagged"`
		CurrentUntagged string `json:"current-untagged"`
		Dynamic         string `json:"dynamic"`
		Comment         string `json:"comment"`
	}
	if err := c.get(ctx, "/interface/bridge/vlan", &vlans); err != nil {
		return nil, err
	}
	for _, vlan := range vlans {
		snapshot.VLANs = append(snapshot.VLANs, model.MikroTikVLAN{
			Bridge:          vlan.Bridge,
			VLANIDs:         splitList(vlan.VLANIDs),
			Tagged:          splitList(vlan.Tagged),
			Untagged:        splitList(vlan.Untagged),
			CurrentTagged:   splitList(vlan.CurrentTagged),
			CurrentUntagged: splitList(vlan.CurrentUntagged),
			Dynamic:         parseBool(vlan.Dynamic),
			Comment:         vlan.Comment,
		})
	}

	var addresses []struct {
		Address   string `json:"address"`
		Interface string `json:"interface"`
		Network   string `json:"network"`
	}
	if err := c.get(ctx, "/ip/address", &addresses); err == nil {
		for _, address := range addresses {
			snapshot.Addresses = append(snapshot.Addresses, model.MikroTikAddress{
				Address:   address.Address,
				Interface: address.Interface,
				Network:   address.Network,
			})
		}
	}

	return snapshot, nil
}

func (c *Client) get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

func normalizeBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return strings.TrimRight(raw, "/")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.Path = "/rest"
	} else if !strings.HasSuffix(u.Path, "/rest") {
		u.Path += "/rest"
	}
	return strings.TrimRight(u.String(), "/")
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseBool(raw string) bool {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "true", "yes", "on":
		return true
	default:
		return false
	}
}
