package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/adi-pr/mirage/internal/event"
	"github.com/adi-pr/mirage/internal/inspect"
	"github.com/adi-pr/mirage/internal/session"
)

const (
	sweepInterval  = 10 * time.Second       // how often to check for idle sessions
	maxSessions    = 10000                  // cap on concurrent sessions
	snapshotLength = 1600                   // bytes captured per packet
	shutdownGrace  = 3 * time.Second        // how long in-flight API requests get on shutdown
	readTimeout    = 500 * time.Millisecond // live capture wakes up at least this often
	// bpfFilter only narrows to TCP: libpcap's tcp[tcpflags] syntax does not
	// work for IPv6, so the SYN-only check happens in capture instead.
	bpfFilter = "tcp"
)

// config holds the command-line settings.
type config struct {
	device         string        // -i: live capture interface
	pcapFile       string        // -r: replay this pcap file instead of capturing live
	outPath        string        // -o: telemetry output file (JSON lines)
	localIPs       string        // -local: comma-separated local addresses (required with -r)
	sessionTimeout time.Duration // -timeout: close a session after this long idle
	listen         string        // -listen: inspection API address (loopback only, "" disables)
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.device, "i", "wlo1", "network interface to capture on")
	flag.StringVar(&cfg.pcapFile, "r", "", "read packets from a pcap file instead of the interface")
	flag.StringVar(&cfg.outPath, "o", "mirage.jsonl", "telemetry output file (JSON lines)")
	flag.StringVar(&cfg.localIPs, "local", "", "comma-separated local IP addresses (default: the interface's addresses)")
	flag.DurationVar(&cfg.sessionTimeout, "timeout", 5*time.Minute, "close a session after this long without events")
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:8787", `inspection API address, loopback only ("" disables)`)
	flag.Parse()
	return cfg
}

// openHandle opens a pcap file when -r is given, otherwise the live interface.
func openHandle(cfg config) (*pcap.Handle, error) {
	if cfg.pcapFile != "" {
		handle, err := pcap.OpenOffline(cfg.pcapFile)
		if err != nil {
			return nil, fmt.Errorf("open pcap file: %w", err)
		}

		return handle, nil
	}

	handle, err := pcap.OpenLive(cfg.device, snapshotLength, false, readTimeout)
	if err != nil {
		return nil, fmt.Errorf("open device %s: %w", cfg.device, err)
	}
	return handle, nil
}

// resolveLocals decides which addresses count as "this host".
func resolveLocals(cfg config) (map[netip.Addr]struct{}, error) {
	var locals map[netip.Addr]struct{}
	var err error

	switch {
	case cfg.localIPs != "":
		locals, err = parseLocalList(cfg.localIPs)
	case cfg.pcapFile != "":
		return nil, errors.New("-local is required with -r (a pcap file has no interface to ask)")
	default:
		locals, err = localAddrs(cfg.device)
	}
	if err != nil {
		return nil, err
	}

	if len(locals) == 0 {
		return nil, fmt.Errorf("no local IP addresses (interface %s)", cfg.device)
	}
	return locals, nil
}

// parseLocalList parses a comma-separated list like "192.168.1.10,fe80::1".
func parseLocalList(list string) (map[netip.Addr]struct{}, error) {
	locals := make(map[netip.Addr]struct{})
	addrs := strings.Split(list, ",")

	for _, addr := range addrs {
		parsed, err := netip.ParseAddr(strings.TrimSpace(addr))
		if err != nil {
			return nil, err
		}
		locals[parsed.Unmap()] = struct{}{}
	}

	return locals, nil
}

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

// captureStats counts what capture did with each packet.
type captureStats struct {
	captured int // events sent to the session goroutine
	skipped  int // packets that did not decode as IP + TCP
	filtered int // TCP packets that were not connection attempts (SYN without ACK)
	dropped  int // events lost because the channel buffer was full
}

// capture reads packets, decodes them, and sends connection attempts on the channel.
// It stops when ctx is cancelled or the packet source ends (end of a pcap file),
// and closes the channel on the way out.
func capture(ctx context.Context, source *gopacket.PacketSource, locals map[netip.Addr]struct{}, events chan<- event.NetworkEvent) captureStats {
	defer close(events)

	var stats captureStats
	packets := source.Packets()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop // Ctrl-C / SIGTERM

		case packet, ok := <-packets:
			if !ok {
				break loop // packet source finished (end of pcap file)
			}

			ev, ok := decodePacket(packet)
			if !ok {
				stats.skipped++
				continue
			}

			if ev.TCPFlags&(event.FlagSYN|event.FlagACK) != event.FlagSYN {
				stats.filtered++
				continue
			}

			ev.Direction = event.ClassifyDirection(ev.SourceIP, ev.DestIP, locals)

			select {
			case events <- ev:
				stats.captured++
			default:
				// channel buffer is full: consumer is too slow
				stats.dropped++
			}
		}
	}

	return stats
}

// runSessions owns the session manager. It logs every event, feeds inbound
// events into sessions, and expires idle sessions on a timer.
// It returns when the events channel is closed.
func runSessions(events <-chan event.NetworkEvent, manager *session.Manager, tel *slog.Logger) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				closed := manager.CloseAll()
				for _, s := range closed {
					logSessionClosed(tel, s)
				}

				tel.Info("sessions_rejected", "count", manager.Rejected())
				return
			}

			res, id := manager.Observe(ev)
			if res == session.Created {
				tel.Info("session_opened",
					"session_id", id,
					"remote_ip", ev.RemoteAddr(),
				)
			}

			logEvent(tel, ev, id)

		case now := <-ticker.C:
			expSessions := manager.Expire(now)
			for _, s := range expSessions {
				logSessionClosed(tel, s)
			}
		}
	}
}

func logEvent(tel *slog.Logger, ev event.NetworkEvent, sID uint64) {
	tel.Info("connection_event",
		"session_id", sID,
		"packet_time", ev.Timestamp,
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

func logSessionClosed(tel *slog.Logger, s session.Session) {
	tel.Info("session_closed",
		"session_id", s.ID,
		"remote_ip", s.RemoteAddr,
		"first_seen", s.FirstSeen,
		"duration_ms", s.Duration().Milliseconds(),
		"events", s.EventCount,
		"distinct_ports", len(s.Ports),
	)
}

func main() {
	cfg := parseFlags()

	if err := run(cfg); err != nil {
		slog.Error("mirage failed", "error", err)
		os.Exit(1)
	}
}

// run does all the work. Returning an error (instead of calling os.Exit)
// lets every defer run, so the handle and telemetry file are closed properly.
func run(cfg config) error {
	slog.Info("MIRAGE starting")

	// Check the flag before opening anything, so a bad address fails fast.
	if cfg.listen != "" {
		if err := inspect.ValidateListenAddr(cfg.listen); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	handle, err := openHandle(cfg)
	if err != nil {
		return err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return fmt.Errorf("set BPF filter: %w", err)
	}

	locals, err := resolveLocals(cfg)
	if err != nil {
		return err
	}
	slog.Info("local_addresses", "addresses", slices.Collect(maps.Keys(locals)))

	file, err := os.OpenFile(cfg.outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open telemetry file: %w", err)
	}
	defer file.Close()

	tel := slog.New(slog.NewJSONHandler(file, nil))

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	events := make(chan event.NetworkEvent, 4096)

	manager := session.NewManager(cfg.sessionTimeout, maxSessions)

	var server *inspect.Server
	if cfg.listen != "" {
		server, err = inspect.Start(cfg.listen)
		if err != nil {
			return err
		}
		slog.Info("inspect_listening", "addr", server.Addr())
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		runSessions(events, manager, tel)
	})

	stats := capture(ctx, source, locals, events) // returns on Ctrl-C or end of file; closes events

	// Stop the API before the session goroutine exits: from 6.2 on, handlers
	// ask runSessions for data, so no request may be in flight after it's gone.
	if server != nil {
		err := server.Shutdown(shutdownGrace)
		if err != nil {
			slog.Error("shutdown_error", "error", err)
		}
	}

	wg.Wait() // runSessions closes all sessions, then returns

	// Logged only after runSessions has finished, so a single goroutine writes
	// telemetry at a time and replays produce the same line order every run.
	tel.Info("capture_stats",
		"captured", stats.captured,
		"skipped", stats.skipped,
		"filtered", stats.filtered,
		"dropped", stats.dropped,
	)

	slog.Info("MIRAGE stopped")
	return nil
}
