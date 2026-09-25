// Command genpcap writes a small synthetic capture for replay tests:
//
//	go run ./tools/genpcap testdata/scan.pcap
//	go run ./cmd/mirage -r testdata/scan.pcap -local 192.168.1.10,2001:db8::10 -o out.jsonl
//
// All addresses are from documentation ranges. The local host is 192.168.1.10
// (IPv4) and 2001:db8::10 (IPv6).
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	local4 = "192.168.1.10"
	local6 = "2001:db8::10"
)

type writer struct {
	w *pcapgo.Writer
	t time.Time
}

// syn writes one TCP packet from src:sport to dst:dport, then advances the clock by gap.
func (w *writer) syn(src, dst string, sport, dport uint16, ack bool, gap time.Duration) error {
	srcIP, dstIP := net.ParseIP(src), net.ParseIP(dst)

	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01},
		DstMAC: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02},
	}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: true, ACK: ack, Window: 1024}

	var ip gopacket.SerializableLayer
	if srcIP.To4() != nil {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
		tcp.SetNetworkLayerForChecksum(ip4)
		ip = ip4
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
		tcp.SetNetworkLayerForChecksum(ip6)
		ip = ip6
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		return err
	}

	data := buf.Bytes()
	ci := gopacket.CaptureInfo{Timestamp: w.t, CaptureLength: len(data), Length: len(data)}
	w.t = w.t.Add(gap)
	return w.w.WritePacket(ci, data)
}

func run(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		return err
	}
	w := &writer{w: pw, t: time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)}

	// Scanner: sequential SYN scan of ports 1-200, 10ms apart.
	for port := uint16(1); port <= 200; port++ {
		if err := w.syn("203.0.113.5", local4, 45000, port, false, 10*time.Millisecond); err != nil {
			return err
		}
	}

	// A client retrying SSH three times (one port, three hits).
	for range 3 {
		if err := w.syn("198.51.100.7", local4, 50000, 22, false, time.Second); err != nil {
			return err
		}
	}

	// A normal web visitor: one connection.
	if err := w.syn("198.51.100.20", local4, 51000, 443, false, 100*time.Millisecond); err != nil {
		return err
	}

	// An IPv6 scanner hitting a few common ports.
	for _, port := range []uint16{22, 80, 443, 8080} {
		if err := w.syn("2001:db8::bad", local6, 52000, port, false, 50*time.Millisecond); err != nil {
			return err
		}
	}

	// Outbound: this host connecting out (logged, but no session).
	if err := w.syn(local4, "93.184.216.34", 53000, 443, false, 100*time.Millisecond); err != nil {
		return err
	}

	// SYN-ACK reply: the BPF filter should drop it entirely.
	return w.syn(local4, "203.0.113.5", 22, 45000, true, 0)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: genpcap <output.pcap>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "genpcap:", err)
		os.Exit(1)
	}
}
