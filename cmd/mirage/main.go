package main

import (
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/adi-pr/mirage/internal/event"
	"github.com/adi-pr/mirage/internal/session"
)

const (
	sessionTimeout = 5 * time.Minute  // close a session after this long without events
	sweepInterval  = 10 * time.Second // how often to check for idle sessions
	maxSessions    = 10000            // cap on concurrent sessions
)

// localAddrs returns the set of IP addresses assigned to the named interface.
func localAddrs(device string) (map[netip.Addr]struct{}, error) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	locals := make(map[netip.Addr]struct{})
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		localIP, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}
		localIP = localIP.Unmap()
		locals[localIP] = struct{}{}
	}

	return locals, nil
}

// decodePacket turns a raw packet into a NetworkEvent.
// It returns false if the packet lacks a usable IP or TCP layer.
func decodePacket(packet gopacket.Packet) (event.NetworkEvent, bool) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return event.NetworkEvent{}, false
	}

	srcEndpoint, dstEndpoint := netLayer.NetworkFlow().Endpoints()
	srcIP, ok := netip.AddrFromSlice(srcEndpoint.Raw())
	if !ok {
		return event.NetworkEvent{}, false
	}

	dstIP, ok := netip.AddrFromSlice(dstEndpoint.Raw())
	if !ok {
		return event.NetworkEvent{}, false
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return event.NetworkEvent{}, false
	}
	tcp := tcpLayer.(*layers.TCP)

	var flags uint8

	if tcp.FIN {
		flags |= event.FlagFIN
	}
	if tcp.SYN {
		flags |= event.FlagSYN
	}
	if tcp.RST {
		flags |= event.FlagRST
	}
	if tcp.PSH {
		flags |= event.FlagPSH
	}
	if tcp.ACK {
		flags |= event.FlagACK
	}
	if tcp.URG {
		flags |= event.FlagURG
	}
	if tcp.ECE {
		flags |= event.FlagECE
	}
	if tcp.CWR {
		flags |= event.FlagCWR
	}

	return event.NetworkEvent{
		Timestamp:  packet.Metadata().Timestamp,
		SourceIP:   srcIP.Unmap(),
		SourcePort: uint16(tcp.SrcPort),
		DestIP:     dstIP.Unmap(),
		DestPort:   uint16(tcp.DstPort),
		Protocol:   "tcp",
		TCPFlags:   flags,
	}, true
}

// capture reads packets, decodes them, and sends events on the channel.
// It closes the channel when the packet source ends.
func capture(source *gopacket.PacketSource, locals map[netip.Addr]struct{}, events chan<- event.NetworkEvent) {
	defer close(events)

	var captured, skipped, dropped int

	for packet := range source.Packets() {
		ev, ok := decodePacket(packet)
		if !ok {
			skipped++
			continue
		}

		ev.Direction = event.ClassifyDirection(ev.SourceIP, ev.DestIP, locals)

		select {
		case events <- ev:
			captured++
		default:
			// channel buffer is full: consumer is too slow
			dropped++
		}
	}

	slog.Info("capture_stats",
		"captured", captured,
		"skipped", skipped,
		"dropped", dropped,
	)
}

// runSessions owns the session manager. It logs every event, feeds inbound
// events into sessions, and expires idle sessions on a timer.
// It returns when the events channel is closed.
func runSessions(events <-chan event.NetworkEvent, manager *session.Manager) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				closed := manager.CloseAll()
				for _, s := range closed {
					logSessionClosed(s)
				}

				slog.Info("sessions_rejected", "count", manager.Rejected())
				return
			}

			logEvent(ev)

			res, id := manager.Observe(ev)
			if res == session.Created {
				slog.Info("session_opened",
					"session_id", id,
					"remote_ip", ev.RemoteAddr(),
				)
			}

		case now := <-ticker.C:
			expSessions := manager.Expire(now)
			for _, s := range expSessions {
				logSessionClosed(s)
			}
		}
	}
}

func logEvent(ev event.NetworkEvent) {
	slog.Info("connection_event",
		"timestamp", ev.Timestamp,
		"source_ip", ev.SourceIP,
		"source_port", ev.SourcePort,
		"dest_ip", ev.DestIP,
		"dest_port", ev.DestPort,
		"protocol", ev.Protocol,
		"tcp_flags", ev.TCPFlags,
		"direction", ev.Direction,
		"remote_ip", ev.RemoteAddr(),
	)
}

func logSessionClosed(s session.Session) {
	slog.Info("session_closed",
		"session_id", s.ID,
		"remote_ip", s.RemoteAddr,
		"first_seen", s.FirstSeen,
		"duration", s.Duration(),
		"events", s.EventCount,
		"distinct_ports", len(s.Ports),
	)
}

func main() {
	slog.Info("MIRAGE starting")

	const (
		device         = "wlo1"
		snapshotLength = 1600
		promiscuous    = false
	)

	handle, err := pcap.OpenLive(
		device,
		snapshotLength,
		promiscuous,
		pcap.BlockForever,
	)

	if err != nil {
		slog.Error("failed to open device", "device", device, "error", err)
		return
	}
	defer handle.Close()

	err = handle.SetBPFFilter("tcp[tcpflags] & (tcp-syn | tcp-ack) == tcp-syn")

	if err != nil {
		slog.Error("failed to set BPF filter", "error", err)
		os.Exit(1)
	}

	locals, err := localAddrs(device)
	if err != nil {
		slog.Error("failed to get local address", "error", err)
		os.Exit(1)
	}

	if len(locals) == 0 {
		slog.Error("no IP address on interface", "device", device)
		os.Exit(1)
	}

	slog.Info("local_addresses", "addresses", locals)

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	events := make(chan event.NetworkEvent, 4096)

	manager := session.NewManager(sessionTimeout, maxSessions)

	var wg sync.WaitGroup
	wg.Go(func() {
		runSessions(events, manager)
	})

	capture(source, locals, events) // runs on the main goroutine; closes events when done
	wg.Wait()                       // wait for consume to drain the channel and exit
}
