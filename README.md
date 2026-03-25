# nmap

This repository now has two tracks:

1. The original Perl implementation in [`nmapscan.pl`](./nmapscan.pl), which shells out heavily, parses human-readable command output, and generates a static [`map.html`](./map.html) that depends on GoJS.
2. A new Go rewrite prototype under [`cmd/netmap`](./cmd/netmap), built around structured `nmap` XML ingestion, a lightweight web UI, and MikroTik-aware bridge/VLAN analysis.

The rewrite target is not a line-by-line port. The goal is to replace the slowest and hardest-to-maintain parts of the old tool with a cleaner pipeline:

* discover with `nmap` using XML output instead of fragile text parsing
* model topology as explicit Go structs
* expose topology over JSON and render it in the browser without GoJS
* enrich the model with RouterOS REST data when a MikroTik device is available
* surface bridge/VLAN mistakes, especially the MikroTik-specific cases that are easy to miss

## Why rewrite

The current Perl app works, but it has structural issues that make it expensive to evolve:

* one 1000+ line script owns discovery, parsing, inference, caching, and presentation
* the browser output is generated as a single static HTML artifact
* it depends on a proprietary diagramming library
* it relies on slow scan defaults such as `nmap -A`, plus repeated traceroutes
* extending it for vendor-specific logic such as MikroTik bridge/VLAN analysis is awkward

## Go Prototype

The new prototype currently provides:

* a Go HTTP server that serves topology JSON and a browser UI
* `nmap` scan profiles:
  * `discovery` uses host discovery only
  * `balanced` adds service and OS fingerprinting
  * `deep` uses `-A`
* import of existing `nmap` XML files through `--nmap-xml`
* optional MikroTik RouterOS REST collection for:
  * `/interface/bridge`
  * `/interface/bridge/port`
  * `/interface/bridge/vlan`
  * `/ip/address`
* MikroTik bridge/VLAN findings for:
  * multiple VLAN IDs mixed into one access-port VLAN entry
  * likely CPU-port exposure via dynamic untagged VLAN 1
  * trunk ports that are carrying tagged traffic without ingress filtering and tagged-only frame admission
  * trunk PVID matching the bridge PVID

## Quick Start

Run the demo dataset:

```bash
go run ./cmd/netmap --demo
```

Then open `http://localhost:8080`.

Run against live subnets with a faster default profile:

```bash
go run ./cmd/netmap --subnets 192.168.1.0/24,192.168.10.0/24 --profile discovery
```

Import existing `nmap` XML instead of scanning live:

```bash
go run ./cmd/netmap --nmap-xml ./scan.xml
```

Attach a MikroTik router through REST:

```bash
go run ./cmd/netmap \
  --subnets 192.168.88.0/24 \
  --mikrotik-url https://192.168.88.1/rest \
  --mikrotik-user admin \
  --mikrotik-password 'secret' \
  --mikrotik-insecure
```

## Prerequisites

For the Go rewrite:

* Go 1.22+
* `nmap`
* `iproute2` if you want the app to infer local interface subnets and the default gateway automatically

For MikroTik REST integration:

* RouterOS v7 REST API enabled
* a user with the permissions needed to read bridge and addressing data
* HTTPS preferred; `--mikrotik-insecure` is there for self-signed lab setups

## Development Notes

The first pass intentionally avoids overfitting to the old implementation:

* no Perl dependency
* no `traceroute` dependency
* no GoJS dependency
* no generated single-file HTML artifact

The topology UI is still an MVP. The next logical steps are:

* persist scan snapshots
* diff scans over time
* correlate MikroTik bridge ports with discovered hosts by MAC and ARP data
* add LLDP/CDP neighbor ingestion where available
* replace the current simple renderer with a richer client-side graph layout while keeping the JSON API stable

## Legacy Perl Tool

The legacy entrypoint is still present:

```bash
./nmapscan.pl -subnet 192.168.1.0/24
```

That path still requires:

* Perl
* `nmap`
* `traceroute`
* `iproute`
* `go.js`

and it still emits the original static [`map.html`](./map.html).
