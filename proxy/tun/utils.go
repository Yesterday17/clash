package tun

import (
	"fmt"
	"github.com/google/netstack/tcpip"
	"github.com/google/netstack/tcpip/buffer"
	"github.com/google/netstack/tcpip/header"
	"github.com/google/netstack/tcpip/stack"
	"github.com/google/netstack/tcpip/transport/udp"
	"net"
)

type fakeConn struct {
	id      stack.TransportEndpointID
	r       *stack.Route
	payload []byte
}

func (c *fakeConn) Data() []byte {
	return c.payload
}

func (c *fakeConn) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	v := buffer.View(b)
	data := v.ToVectorisedView()
	// if addr is not provided, write back use original dst Addr as src Addr
	if addr == nil {
		return writeUDP(c.r, data, uint16(c.id.LocalPort), c.id.RemotePort)
	}

	var ip net.IP
	var port int
	if udpaddr, ok := addr.(*net.UDPAddr); ok {
		ip = udpaddr.IP
		port = udpaddr.Port
	} else if tcpaddr, ok := addr.(*net.TCPAddr); ok {
		ip = tcpaddr.IP
		port = tcpaddr.Port
	} else {
		return
	}

	r := c.r.Clone()
	if ipv4 := ip.To4(); ipv4 != nil {
		r.LocalAddress = tcpip.Address(ipv4)
	} else {
		r.LocalAddress = tcpip.Address(ip)
	}
	return writeUDP(&r, data, uint16(port), c.id.RemotePort)
}

func (c *fakeConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(c.id.RemoteAddress), Port: int(c.id.RemotePort)}
}

func (c *fakeConn) Close() error {
	return nil
}

func writeUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16) (int, error) {
	const protocol = udp.ProtocolNumber
	// Allocate a buffer for the UDP header.
	hdr := buffer.NewPrependable(header.UDPMinimumSize + int(r.MaxHeaderLength()))

	// Initialize the header.
	udp := header.UDP(hdr.Prepend(header.UDPMinimumSize))

	length := uint16(hdr.UsedLength() + data.Size())
	udp.Encode(&header.UDPFields{
		SrcPort: localPort,
		DstPort: remotePort,
		Length:  length,
	})

	// Only calculate the checksum if offloading isn't supported.
	if r.Capabilities()&stack.CapabilityTXChecksumOffload == 0 {
		xsum := r.PseudoHeaderChecksum(protocol, length)
		for _, v := range data.Views() {
			xsum = header.Checksum(v, xsum)
		}
		udp.SetChecksum(^udp.CalculateChecksum(xsum))
	}

	ttl := r.DefaultTTL()

	if err := r.WritePacket(nil /* gso */, stack.NetworkHeaderParams{Protocol: protocol, TTL: ttl, TOS: 0 /* default */}, tcpip.PacketBuffer{
		Header: hdr,
		Data:   data,
	}); err != nil {
		r.Stats().UDP.PacketSendErrors.Increment()
		return 0, fmt.Errorf("%v", err)
	}

	// Track count of packets sent.
	r.Stats().UDP.PacketsSent.Increment()
	return data.Size(), nil
}
