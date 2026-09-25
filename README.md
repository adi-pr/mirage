# MIRAGE

**Adaptive network deception for Linux.**

MIRAGE is a Linux network security project that builds deceptive network environments in response to suspicious network behavior.

Instead of just blocking or logging reconnaissance, MIRAGE changes what a remote host perceives. A host scanning the network may find services, machines, and relationships that do not exist, and different remote hosts can be shown entirely different topologies, while the real infrastructure stays hidden behind the deception layer.

MIRAGE does not use AI or machine learning. Detection and adaptation are driven by deterministic rules, behavioral scoring, state machines, and network telemetry.

> **One real network. Multiple perceived networks.**

---

## The Idea

Traditional defensive systems respond to suspicious traffic by logging it, alerting an administrator, blocking the source, or redirecting it to a static honeypot. They all try to answer:

> **"What is this host doing?"**

MIRAGE explores a second question:

> **"What should this host be allowed to believe exists?"**

Instead of treating the network topology as fixed, MIRAGE treats each observer's view of the network as something that can be constructed on the fly.

---

## Status

> **Early development / research phase.** The architecture will change substantially.

MIRAGE is in **Phase 1: Observe**. It currently:

- captures inbound TCP connection attempts (SYN without ACK) on one network interface
- decodes each into a connection event with source, destination, ports, flags, and a timestamp
- classifies each event's direction relative to this host (inbound, outbound, local, or transit)
- groups inbound events into **sessions**, one per remote host, closed after 5 minutes of inactivity
- logs events and session open/close as structured `slog` lines

There is no detection or deception yet.

---

## Roadmap

| Phase | Goal | Status |
|---|---|---|
| 1 — Observe | Capture connections, group them into sessions, identify basic reconnaissance | In progress |
| 2 — Detect | Score session behavior (e.g. port scans) with deterministic rules | Planned |
| 3 — Deceive | Present fake services and hosts to flagged sessions | Planned |
| 4 — Mutate | Give different observers different, evolving topologies | Planned |
| 5 — Visualize | Show sessions and perceived networks | Planned |

Dynamic deception comes only after the telemetry and behavioral foundations are stable.

---

## Getting Started

### Requirements

- Linux
- Go 1.27+
- libpcap headers (`pacman -S libpcap` on Arch, `apt install libpcap-dev` on Debian/Ubuntu)
- Root, or the `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities, to capture packets

### Build and run

```bash
go build -o mirage ./cmd/mirage

# either run as root...
sudo ./mirage

# ...or grant capture capabilities once per build, then run as your user
sudo setcap cap_net_raw,cap_net_admin=eip ./mirage
./mirage
```

`go build` produces a new file, so re-run `setcap` after every rebuild.

The capture interface is currently hard-coded to `wlo1` in [`cmd/mirage/main.go`](cmd/mirage/main.go). Change `device` there to match your interface (see `ip link`).

### Example output

```
INFO MIRAGE starting
INFO local_addresses addresses="map[192.168.100.9:{} ...]"
INFO connection_event source_ip=192.168.100.202 source_port=58886 dest_ip=192.168.100.9 dest_port=443 protocol=tcp tcp_flags=2 direction=inbound remote_ip=192.168.100.202
INFO session_opened session_id=1 remote_addr=192.168.100.202
...
INFO session_closed session_id=1 remote_ip=192.168.100.202 first_seen=... duration=12.4s events=1000 distinct_ports=1000
```

---

## Testing

### Unit tests

```bash
go test ./...
```

### Live test with a port scan

**Scan from a different machine.** On Linux, traffic from a host to its own IP goes through the loopback interface (`lo`), not the network card, so MIRAGE never sees it. Even if it did, both ends would be local addresses, so the traffic is classified as `local` and never becomes a session.

Use a second device on the same network, or a VM with **bridged** networking (NAT won't work):

```bash
# on the MIRAGE host
./mirage

# on another machine
nmap -sS -p 1-1000 <mirage-host-ip>
```

You should see one `session_opened` for the scanning host. `session_closed` appears after 5 minutes without further traffic from that host.

---

## Known Limitations

- **Ctrl+C loses open sessions.** There is no signal handling yet, so stopping MIRAGE kills the process before `session_closed` and `capture_stats` are logged.
- The interface name is hard-coded (see above).
- Only TCP SYN packets are captured. UDP, ICMP, and other scan types are not observed.
- Session timeout (5 min), sweep interval (10 s), and session cap (10,000) are constants in `main.go`.

---

## Project Layout

```
cmd/mirage/         entry point: packet capture, decoding, logging
internal/event/     NetworkEvent, TCP flags, direction classification
internal/session/   session manager: groups inbound events per remote host
internal/observer/  (placeholder)
```

---

## Non-Goals

MIRAGE is not intended to be:

- an autonomous offensive security system
- a vulnerability exploitation framework
- malware
- an AI-based intrusion detection system
- a replacement for a firewall
- a production-ready security appliance

The project is primarily an exploration of **Linux networking, cyber deception, behavioral detection, isolation, and dynamic network architecture**.

---

## Security

MIRAGE works directly with Linux networking and needs elevated privileges for packet capture, and later for network namespaces and firewall configuration.

Develop and test it in an isolated environment. Virtual machines or a dedicated lab network are strongly recommended. Do not expose experimental MIRAGE deployments directly to untrusted networks.
