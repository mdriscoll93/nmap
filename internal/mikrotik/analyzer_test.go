package mikrotik

import (
	"testing"

	"github.com/tedsluis/nmap/internal/model"
)

func TestAnalyzeFlagsMultiVLANAccessEntry(t *testing.T) {
	snapshot := &model.MikroTikSnapshot{
		VLANs: []model.MikroTikVLAN{
			{
				Bridge:   "bridge1",
				VLANIDs:  []string{"20", "30"},
				Tagged:   []string{"ether1"},
				Untagged: []string{"ether2", "ether3"},
			},
		},
	}

	findings := Analyze(snapshot)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
}

func TestAnalyzeFlagsCPUExposureAndWeakTrunk(t *testing.T) {
	snapshot := &model.MikroTikSnapshot{
		Bridges: []model.MikroTikBridge{
			{Name: "bridge1", PVID: "1", VLANFiltering: true},
		},
		Ports: []model.MikroTikPort{
			{Bridge: "bridge1", Interface: "ether1", PVID: "1", IngressFiltering: false, FrameTypes: "admit-all"},
		},
		VLANs: []model.MikroTikVLAN{
			{
				Bridge:          "bridge1",
				VLANIDs:         []string{"1"},
				CurrentTagged:   []string{"ether1"},
				CurrentUntagged: []string{"bridge1", "ether1"},
				Dynamic:         true,
			},
		},
	}

	findings := Analyze(snapshot)
	if len(findings) < 2 {
		t.Fatalf("expected multiple findings, got %d", len(findings))
	}
}
