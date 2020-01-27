package monitor

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
)

func Monitor(iface string) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	packetsource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetsource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			log.Printf("S: %d - D: %d\n", tcpLayer)
		}
	}
}
