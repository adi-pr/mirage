# MIRAGE

**Adaptive network deception for Linux.**

MIRAGE is a Linux network security project that dynamically constructs deceptive network environments in response to suspicious network behavior.

Instead of simply blocking or logging reconnaissance, MIRAGE changes what a remote host perceives.

A host performing reconnaissance may discover services, machines, and relationships that do not actually exist. Different remote hosts can be presented with entirely different network topologies while the real infrastructure remains hidden behind the deception layer.

MIRAGE does not use AI or machine learning. Detection and adaptation are driven by deterministic rules, behavioral scoring, state machines, and network telemetry.

> **One real network. Multiple perceived networks.**

---

## The Idea

Traditional defensive systems generally respond to suspicious traffic by:

* logging it,
* alerting an administrator,
* blocking the source, or
* redirecting traffic to a static honeypot.

MIRAGE explores a different approach.

**What if the network itself became deceptive?**

---

## Roadmap

* Phase 1 — Observe
* Phase 2 — Detect
* Phase 3 — Deceive
* Phase 4 — Mutate
* Phase 5 — Visualize

---

## Non-Goals

MIRAGE is not intended to be:

* an autonomous offensive security system
* a vulnerability exploitation framework
* malware
* an AI-based intrusion detection system
* a replacement for a firewall
* a production-ready security appliance

The project is primarily an exploration of **Linux networking, cyber deception, behavioral detection, isolation, and dynamic network architecture**.

---

## Development Status

> **Early development / research phase**

The architecture and implementation are expected to change substantially as the project develops.

The first milestone is intentionally small:

**Observe network connections, group them into sessions, and reliably identify basic reconnaissance behavior.**

Dynamic deception comes after the telemetry and behavioral foundations are stable.

---

## Security

MIRAGE interacts directly with Linux networking and may eventually require elevated privileges for functionality such as network namespace creation, packet inspection, and firewall configuration.

Development should therefore be performed in an isolated environment.

Virtual machines or a dedicated lab network are strongly recommended.

Do not expose experimental MIRAGE deployments directly to untrusted networks.

---

## Why MIRAGE?

Most defensive tools attempt to determine:

> **"What is this host doing?"**

MIRAGE explores a second question:

> **"What should this host be allowed to believe exists?"**

Instead of treating the network topology as static, MIRAGE treats an observer's view of the network as something that can be dynamically constructed.
