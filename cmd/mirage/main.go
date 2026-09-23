package main

import (
	"log/slog"
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
	DirectionUnknown Direction = iota
	DirectionInbound
	DirectionOutbound
)

type NetworkEvent struct {
	Timestamp  time.Time
	SourceIP   netip.Addr
	SourcePort uint16
	DestIP     netip.Addr
	DestPort   uint16
	Protocol   string
	TCPFlags   uint8
	Direction  Direction // stays DirectionUnknown until Step 3
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
func capture(source *gopacket.PacketSource, events chan<- NetworkEvent) {
	defer close(events)

	var captured, skipped, dropped int

	for packet := range source.Packets() {
		event, ok := decodePacket(packet)
		if !ok {
			skipped++
			continue
		}

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
		return
	}


	source := gopacket.NewPacketSource(handle, handle.LinkType())
	events := make(chan NetworkEvent, 4096)

	var wg sync.WaitGroup
	wg.Go(func() {
		consume(events)
	})

	capture(source, events) // runs on the main goroutine; closes events when done
	wg.Wait()               // wait for consume to drain the channel and exit
}

func (d Direction) String() string {
	switch d {
	case DirectionInbound:
		return "inbound"
	case DirectionOutbound:
		return "outbound"
	default:
		return "unknown"
	}
}
