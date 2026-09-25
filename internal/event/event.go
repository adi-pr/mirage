// Package event defines the connection events MIRAGE produces from captured packets.
package event

import (
	"net/netip"
	"time"
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

func (d Direction) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
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

// ClassifyDirection decides which way a connection goes relative to this host.
func ClassifyDirection(src, dst netip.Addr, locals map[netip.Addr]struct{}) Direction {

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
