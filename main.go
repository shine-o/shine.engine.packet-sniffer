package main

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"os"
	"os/signal"
	"strconv"
	"sync"
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

var knownServices = make(map[int]string) // port => serviceName

func init() {

	knownServices[9000] = "Account"
	knownServices[9311] = "AccountLog"
	knownServices[9411] = "Character"
	knownServices[9511] = "GameLog"
	knownServices[9010] = "Login"
	knownServices[9110] = "WorldManager"
	knownServices[9210] = "Zone0"
	knownServices[9212] = "Zone1"
	knownServices[9214] = "Zone2"
	knownServices[9216] = "Zone3"
	knownServices[9218] = "Zone4"
}

type PacketFlow struct {
	pfm map[string][]gopacket.Packet
	m   sync.Mutex
}

func main() {
	pf := &PacketFlow{
		pfm: make(map[string][]gopacket.Packet),
	}

	ctx := context.Background()

	// trap Ctrl+C and call cancel on the context
	ctx, cancel := context.WithCancel(ctx)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer func() {
		signal.Stop(c)
		cancel()
	}()
	go func() {
		select {
		case <-c:
			pf.persist()
			cancel()
		case <-ctx.Done():
			pf.persist()
		}
	}()

	listen(ctx, pf)
}

func listen(ctx context.Context, pf *PacketFlow) {
	if handle, err := pcap.OpenLive("\\Device\\NPF_{3904F81A-F9DE-4578-B4C6-8626CE9B78CE}", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
		//} else if err := handle.SetBPFFilter("(src net 192.168.1.184 or dst net 192.168.1.250) and (dst portrange 9000-9600 or src portrange 9000-9600)"); err != nil {  //
	} else if err := handle.SetBPFFilter("dst portrange 9000-9600 or src portrange 9000-9600"); err != nil { //
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			go pf.add(packet)
		}
	}
}

// asses the package flow, either Client-Service or Service-Client
func (pf *PacketFlow) add(p gopacket.Packet) {
	src, _ := strconv.Atoi(p.TransportLayer().TransportFlow().Src().String())
	dst, _ := strconv.Atoi(p.TransportLayer().TransportFlow().Dst().String())

	var fkey string

	if src >= 9000 && src <= 9600 {
		// server - client
		fkey = fmt.Sprintf("%v-Client.pcapng", knownServices[src])
	} else {
		fkey = fmt.Sprintf("Client-%v.pcapng", knownServices[dst])
	}
	//if src  >= 9000 && src <= 9600 {
	//	fkey = fmt.Sprintf("Client-%v.pcapng", knownServices[src])
	//} else {
	//	fkey = fmt.Sprintf("Client-%v.pcapng", knownServices[dst])
	//}

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
