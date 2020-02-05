package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
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

var iface = flag.String("i", "\\Device\\NPF_{3904F81A-F9DE-4578-B4C6-8626CE9B78CE}", "Interface to get packets from")
var snaplen = flag.Int("s", 65536, "SnapLen for pcap packet capture")

//var filter = flag.String("f", "dst portrange 9000-9600 or src portrange 9000-9600", "BPF filter for pcap")
var filter = flag.String("f", "(dst net 192.168.1.248 or src net 192.168.1.248) and (dst portrange 9000-9600 or src portrange 9000-9600)", "BPF filter for pcap")

var knownServices = make(map[int]*service) // port => serviceName

func init() {

	knownServices[9000] = &service{name: "Account"}
	knownServices[9311] = &service{name: "AccountLog"}
	knownServices[9411] = &service{name: "Character"}
	knownServices[9511] = &service{name: "GameLog"}
	knownServices[9010] = &service{name: "Login"}
	knownServices[9110] = &service{name: "WorldManager"}
	knownServices[9210] = &service{name: "Zone0"}
	knownServices[9212] = &service{name: "Zone1"}
	knownServices[9214] = &service{name: "Zone2"}
	knownServices[9216] = &service{name: "Zone3"}
	knownServices[9218] = &service{name: "Zone4"}
}

type PacketFlow struct {
	pfm map[string][]gopacket.Packet
	m   sync.Mutex
}

type service struct {
	name   string
	xorKey uint16
}

type fiestaStreamFactory struct{}

type fiestaStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	fkey           string
	data           chan<- []byte
}

func (fsf *fiestaStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {

	src, _ := strconv.Atoi(transport.Src().String())
	dst, _ := strconv.Atoi(transport.Dst().String())

	var fkey string

	if src >= 9000 && src <= 9600 {
		// server - client
		fkey = fmt.Sprintf("%v-Client", knownServices[src].name)
	} else {
		fkey = fmt.Sprintf("Client-%v", knownServices[dst].name)
	}

	log.Printf("new stream %v:%v started", net, transport)
	data := make(chan []byte, 32768)
	s := &fiestaStream{
		net:       net,
		transport: transport,
		fkey:      fkey,
		data:      data,
	}

	go s.decode(data)
	//go s.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return s
}

func (fs *fiestaStream) decode(data <-chan []byte) {
	//var data []byte
	var splen uint8
	var bplen uint16
	var missingData bool
	var d []byte

	for datum := range data {
		//d = append(d, datum...)
		if len(datum) == 0 {
			//log.Println("0 bytes packet")
			continue
		}

		log.Printf("Count of %v bytes going through flow %v \n", len(d), fs.fkey)

		// if missingData
		//		append data
		//		if done
		//			if done; protocol goroutine
		//			continue
		//		missingData = false

		// if small packet or big packet

		// if packet length equals available datum

		d = append(d, datum...)

		if missingData {
			d = append(d, datum...)
			if bplen != 0 {
				if bplen == (uint16(len(d)) - 3) {
					missingData = false
					d = []byte{}
					log.Printf("Completed big package reconstruction with indicated length %v and datum lenght %v in flow %v", bplen, len(d)-3, fs.fkey)

					//
				}
			} else {
				if splen == (uint8(len(d)) - 1) {
					missingData = false
					d = []byte{}
					log.Printf("Completed big package reconstruction with indicated length %v and datum lenght %v in flow %v", splen, len(d)-1, fs.fkey)

					//
				}
			}
			continue
		}

		br := bytes.NewReader(d)
		err := binary.Read(br, binary.LittleEndian, &splen)

		if err != nil {
			log.Printf(err.Error())
		}

		if splen > 0 {
			// read until splen matches packet length
			// packet type big
			if splen < (uint8(len(d) - 1)) {
				log.Printf("\n%v\n", hex.EncodeToString(datum))
			}

			if splen == (uint8(len(d)) - 1) {
				log.Printf("Done processing small package with length %v", splen)
				d = []byte{}
				missingData = false
			} else {
				missingData = true
				log.Printf("Segmented small package with length %v in flow %v", splen, fs.fkey)
				continue
			}
		} else {
			br.Reset(d)
			_, err = br.ReadAt(d, 1)

			if err != nil {
				log.Printf(err.Error())
			}
			err := binary.Read(br, binary.LittleEndian, &bplen)
			if err != nil {
				log.Printf(err.Error())
			}

			if bplen == (uint16(len(d)) - 3) {
				log.Printf("Done processing big package with length %v", splen)
				d = []byte{}
				missingData = false

				// wait for more packets
				// new decoded packet go routine
			} else {
				missingData = true
				log.Printf("Segmented big package with length %v in flow %v", splen, fs.fkey)
				continue
			}
		}
	}
}

func (fs *fiestaStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		fs.data <- reassembly.Bytes
	}
}

func (fs *fiestaStream) ReassemblyComplete() {

}

func (h *fiestaStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		var b bytes.Buffer

		_, err := buf.WriteTo(&b)

		if err == io.EOF {
			fmt.Println(err)
			return
		}
		if len(b.Bytes()) > 0 {
			fmt.Println(len(b.Bytes()))
		}
	}
}

// for each service, start a goroutine with listener
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
	//streamFactory := &statsStreamFactory{}
	//streamPool := tcpassembly.NewStreamPool(streamFactory)
	//assembler := tcpassembly.NewAssembler(streamPool)
	//
	//var tcp layers.TCP
	//var netFlow gopacket.Flow

	sf := &fiestaStreamFactory{}
	sp := tcpassembly.NewStreamPool(sf)
	a := tcpassembly.NewAssembler(sp)

	if handle, err := pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(*filter); err != nil { //
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			go pf.add(packet)
			tcp := packet.TransportLayer().(*layers.TCP)
			a.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
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
