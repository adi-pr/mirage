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
)

type Direction uint8

const (
	DirectionUnknown  Direction = iota
	DirectionInbound            // remote -> local
	DirectionOutbound           // local -> remote
	DirectionLocal              // local -> local
	DirectionTransit            // remote -> remote (bridged/gateway traffic)
)

func (d Direction) String() string {
	switch d {
	case DirectionInbound:
		return "inbound"
	case DirectionOutbound:
		return "outbound"
	case DirectionLocal:
		return "local"
	case DirectionTransit:
		return "transit"
	default:
		return "unknown"
	}
}

type NetworkEvent struct {
	Timestamp  time.Time
	SourceIP   netip.Addr
	SourcePort uint16
	DestIP     netip.Addr
	DestPort   uint16
	Protocol   string
	TCPFlags   uint8
	Direction  Direction
}

// RemoteAddr returns the address of the remote host for this event.
// It returns an invalid netip.Addr{} when there is no single remote side.
func (e NetworkEvent) RemoteAddr() netip.Addr {

	switch e.Direction {
	case DirectionInbound:
		return e.SourceIP
	case DirectionOutbound:
		return e.DestIP
	}

	return netip.Addr{}
}

const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
	FlagECE uint8 = 1 << 6
	FlagCWR uint8 = 1 << 7
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

// classifyDirection decides which way a connection goes relative to this host.
func classifyDirection(src, dst netip.Addr, locals map[netip.Addr]struct{}) Direction {

	_, srcLocal := locals[src]
	_, dstLocal := locals[dst]

	switch {
	case !srcLocal && dstLocal:
		return DirectionInbound
	case srcLocal && !dstLocal:
		return DirectionOutbound
	case srcLocal && dstLocal:
		return DirectionLocal
	case !srcLocal && !dstLocal:
		return DirectionTransit

	}

	return DirectionUnknown
}

// decodePacket turns a raw packet into a NetworkEvent.
// It returns false if the packet lacks a usable IP or TCP layer.
func decodePacket(packet gopacket.Packet) (NetworkEvent, bool) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return NetworkEvent{}, false
	}

	srcEndpoint, dstEndpoint := netLayer.NetworkFlow().Endpoints()
	srcIP, ok := netip.AddrFromSlice(srcEndpoint.Raw())
	if !ok {
		return NetworkEvent{}, false
	}

	dstIP, ok := netip.AddrFromSlice(dstEndpoint.Raw())
	if !ok {
		return NetworkEvent{}, false
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return NetworkEvent{}, false
	}
	tcp := tcpLayer.(*layers.TCP)

	var flags uint8

	if tcp.FIN {
		flags |= FlagFIN
	}
	if tcp.SYN {
		flags |= FlagSYN
	}
	if tcp.RST {
		flags |= FlagRST
	}
	if tcp.PSH {
		flags |= FlagPSH
	}
	if tcp.ACK {
		flags |= FlagACK
	}
	if tcp.URG {
		flags |= FlagURG
	}
	if tcp.ECE {
		flags |= FlagECE
	}
	if tcp.CWR {
		flags |= FlagCWR
	}

	return NetworkEvent{
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
func capture(source *gopacket.PacketSource, locals map[netip.Addr]struct{}, events chan<- NetworkEvent) {
	defer close(events)

	var captured, skipped, dropped int

	for packet := range source.Packets() {
		event, ok := decodePacket(packet)
		if !ok {
			skipped++
			continue
		}

		event.Direction = classifyDirection(event.SourceIP, event.DestIP, locals)

		select {
		case events <- event:
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

// consume receives events and logs them. It returns when the channel is closed.
func consume(events <-chan NetworkEvent) {
	for event := range events {
		slog.Info("connection_event",
			"timestamp", event.Timestamp,
			"source_ip", event.SourceIP,
			"source_port", event.SourcePort,
			"dest_ip", event.DestIP,
			"dest_port", event.DestPort,
			"protocol", event.Protocol,
			"tcp_flags", event.TCPFlags,
			"direction", event.Direction,
			"remote_ip", event.RemoteAddr(),
		)
	}
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
	events := make(chan NetworkEvent, 4096)

	var wg sync.WaitGroup
	wg.Go(func() {
		consume(events)
	})

	capture(source, locals, events) // runs on the main goroutine; closes events when done
	wg.Wait()                       // wait for consume to drain the channel and exit
}
