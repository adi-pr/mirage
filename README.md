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

**Phase 1: Observe is complete.** MIRAGE currently:

- captures inbound TCP connection attempts (SYN without ACK) over IPv4 and IPv6, live from an interface or replayed from a pcap file
- decodes each into a connection event with source, destination, ports, flags, and a timestamp
- classifies each event's direction relative to this host (inbound, outbound, local, or transit)
- groups inbound events into **sessions**, one per remote host, recording which ports were hit, how often, and in what order
- writes events and session open/close records as JSON lines to a telemetry file
- serves the live sessions over a local, read-only HTTP API
- shuts down cleanly on Ctrl+C, closing and logging every open session

There is no detection or deception yet.

---

## Roadmap

| Phase | Goal | Status |
|---|---|---|
| 1 — Observe | Capture connections, group them into sessions, make reconnaissance visible | Done |
| 2 — Detect | Score session behavior (e.g. port scans) with deterministic rules | Next |
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
- Root, or the `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities, for live capture (replaying a pcap file needs neither)

### Build and run

```bash
go build -o mirage ./cmd/mirage

# either run as root...
sudo ./mirage -i eth0

# ...or grant capture capabilities once per build, then run as your user
sudo setcap cap_net_raw,cap_net_admin=eip ./mirage
./mirage -i eth0
```

`go build` produces a new file, so re-run `setcap` after every rebuild. Find your interface name with `ip link`.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-i` | `wlo1` | Network interface to capture on |
| `-r` | | Read packets from a pcap file instead of the interface |
| `-local` | the interface's addresses | Comma-separated IPs that count as "this host". Required with `-r` |
| `-o` | `mirage.jsonl` | Telemetry output file (appended to, created with mode `0640`) |
| `-timeout` | `5m` | Close a session after this long without traffic from its host |
| `-listen` | `127.0.0.1:8787` | Inspection API address. Loopback IPs only; `""` disables it |

### Telemetry

Telemetry goes to the `-o` file as one JSON object per line. Operational messages (startup, errors) go to stderr. Record types, by `msg`:

| `msg` | When |
|---|---|
| `connection_event` | Every captured connection attempt, with its `session_id` (0 if it has no session, e.g. outbound) |
| `session_opened` | First connection attempt from a new remote host |
| `session_closed` | Session idle past `-timeout`, or MIRAGE stopping. Includes `duration_ms`, `events`, `distinct_ports` |
| `sessions_rejected` | At shutdown: how many new hosts were turned away because the session cap was reached |
| `capture_stats` | At shutdown: packets `captured`, `skipped` (not IP/TCP), `filtered` (not SYN-only), `dropped` (buffer full) |

```json
{"time":"…","level":"INFO","msg":"session_closed","session_id":1,"remote_ip":"203.0.113.5","first_seen":"2026-09-25T06:00:00-04:00","duration_ms":1990,"events":200,"distinct_ports":200}
```

Query it with `jq`:

```bash
jq -c 'select(.msg == "session_closed")' mirage.jsonl       # all finished sessions
jq -c 'select(.session_id == 1)' mirage.jsonl               # everything from one session
```

### Inspection API

While MIRAGE runs, the live sessions are available on the `-listen` address:

| Endpoint | Returns |
|---|---|
| `GET /healthz` | `ok` |
| `GET /sessions` | Summary of every active session: `id`, `remote_ip`, `first_seen`, `last_seen`, `duration_ms`, `events`, `distinct_ports` |
| `GET /sessions/{ip}` | One session in full: the summary plus `ports` (with hit counts, sorted), `port_order` (first-touch order), and `local_addrs`. 400 for an invalid IP, 404 if there is no active session |

```bash
curl -s localhost:8787/sessions | jq
curl -s localhost:8787/sessions/203.0.113.5 | jq '.ports[:5]'
```

The API only binds to loopback addresses: session data shows who is scanning this host, so it is never served on a public interface.

---

## Testing

### Unit tests

```bash
go test -race ./...
```

### Replay a capture

`tools/genpcap` writes a small synthetic capture (a 200-port scanner, an SSH retry, a web visitor, an IPv6 scanner, one outbound connection, and a SYN-ACK that should be filtered out). Replaying it needs no root, and the output is the same on every run apart from each line's `time` field:

```bash
go run ./tools/genpcap testdata/scan.pcap
go run ./cmd/mirage -r testdata/scan.pcap -local 192.168.1.10,2001:db8::10 -listen "" -o replay.jsonl
```

Expect 4 sessions and `"captured":209,"filtered":1` in `capture_stats`.

Any real capture works too, e.g. one recorded with `sudo tcpdump -i eth0 -w scan.pcap`. Pass the recording host's IPs with `-local`.

### Live test with a port scan

**Scan from a different machine.** On Linux, traffic from a host to its own IP goes through the loopback interface (`lo`), not the network card, so MIRAGE never sees it. Even if it did, both ends would be local addresses, so the traffic is classified as `local` and never becomes a session.

Use a second device on the same network, or a VM with **bridged** networking (NAT won't work):

```bash
# on the MIRAGE host
sudo ./mirage -i eth0 -timeout 1m

# on another machine
nmap -sS -p 1-1000 <mirage-host-ip>

# back on the MIRAGE host, while the session is open
curl -s localhost:8787/sessions | jq
```

You should see one session for the scanning host with about 1,000 distinct ports. It closes after the `-timeout` passes with no further traffic from that host, or when you press Ctrl+C.

---

## Known Limitations

- Only TCP SYN packets are observed. UDP, ICMP, and other scan types (FIN, NULL, Xmas) are not.
- Only inbound traffic forms sessions. Outbound, local, and transit events are logged but not grouped.
- Local addresses are read once at startup. If the interface's IP changes (DHCP, reconnecting to Wi-Fi), restart MIRAGE or use `-local`.
- The session cap (10,000) and sweep interval (10 s) are constants in [`cmd/mirage/main.go`](cmd/mirage/main.go).
- In replay mode, sessions close when the file ends rather than by timeout, because the idle timer runs on wall-clock time.

---

## Project Layout

```
cmd/mirage/         entry point: flags, packet capture and decoding, the session goroutine, shutdown
internal/event/     NetworkEvent, TCP flags, direction classification
internal/session/   session manager: groups inbound events per remote host
internal/inspect/   local HTTP inspection API
tools/genpcap/      writes the synthetic capture used for replay tests
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
