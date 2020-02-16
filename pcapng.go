package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"os"
	"strconv"
)

// asses the package flow, either Client-Service or Service-Client
func (pf *PacketFlow) add(p gopacket.Packet) {

	src, _ := strconv.Atoi(p.TransportLayer().TransportFlow().Src().String())
	dst, _ := strconv.Atoi(p.TransportLayer().TransportFlow().Dst().String())

	var fkey string

	if src >= 9000 && src <= 9600 {
		// server - client
		fkey = fmt.Sprintf("%v-Client.pcapng", knownServices[src].name)
	} else {
		fkey = fmt.Sprintf("Client-%v.pcapng", knownServices[dst].name)
	}

	pf.m.Lock()
	pf.pfm[fkey] = append(pf.pfm[fkey], p)
	pf.m.Unlock()
}

// write to disk pcapng files for each flow in the map
func (pf *PacketFlow) persist() {
	for k, v := range pf.pfm {
		f, err := os.Create(k)
		if err != nil {
			fmt.Println(err)
		}

		r, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)

		if err != nil {
			fmt.Println(err)
		}

		for _, p := range v {
			err = r.WritePacket(p.Metadata().CaptureInfo, p.Data())
		}
		r.Flush()
		f.Close()
	}
}
