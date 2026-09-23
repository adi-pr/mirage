package main

import (
	"net/netip"
	"testing"
)

func TestClassifyDirection(t *testing.T) {
	locals := map[netip.Addr]struct{}{
		netip.MustParseAddr("192.168.1.10"): {},
		netip.MustParseAddr("192.168.1.20"): {},
		netip.MustParseAddr("2001:db8::1"): {},
	}

	tests := []struct {
		name string
		src  string
		dst  string
		want Direction
	}{
		{name: "inbound", src: "203.0.113.5", dst: "192.168.1.10", want: DirectionInbound},
		{name: "outbound", src: "192.168.1.10", dst: "203.0.113.5", want: DirectionOutbound},
		{name: "local", src: "192.168.1.10", dst: "192.168.1.20", want: DirectionLocal},
		{name: "transit", src: "203.0.113.5", dst: "198.51.100.5", want: DirectionTransit},
		{name: "ipv6-inbound", src: "2001:db8::2", dst: "2001:db8::1", want: DirectionInbound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyDirection(netip.MustParseAddr(tt.src), netip.MustParseAddr(tt.dst), locals)
			if got != tt.want {
				t.Errorf("classifyDirection(%s, %s) = %v, want %v", tt.src, tt.dst, got, tt.want)
			}
		})
	}
}
