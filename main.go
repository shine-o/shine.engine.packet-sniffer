package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/**
	2016 files packet sniffer
	Services:
		- Login
			- Client port: 9010
		- World Manager
			- Client port: 9110, 9120
		- Zone 1

 */
func main() {
	if handle, err := pcap.OpenLive("lo", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp and port 1337"); err != nil {  // optional
		panic(err)
	} else if err := handle.SetBPFFilter("udp and port 1338"); err != nil {  // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Println(packet)
			//// Find all packets coming from UDP port 1000 to UDP port 500

			interestingFlow, err := gopacket.FlowFromEndpoints(layers.NewUDPPortEndpoint(1337), layers.NewUDPPortEndpoint(1338))
			fmt.Println(err)
			if t := packet.TransportLayer(); t != nil && t.TransportFlow() == interestingFlow {
				fmt.Println("Found that UDP flow I was looking for!")
			}
		}
	}
}

