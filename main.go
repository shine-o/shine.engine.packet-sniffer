package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"
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
var filter = flag.String("f", "(dst net 192.168.1.248 or src net 192.168.1.248) and (dst portrange 9000-9600 or src portrange 9000-9600)", "BPF filter for pcap")

var knownServices = make(map[int]*service) // port => serviceName

var xorKey = [499]byte{
	0x07, 0x59, 0x69, 0x4A, 0x94, 0x11, 0x94, 0x85, 0x8C, 0x88, 0x05, 0xCB, 0xA0, 0x9E, 0xCD, 0x58,
	0x3A, 0x36, 0x5B, 0x1A, 0x6A, 0x16, 0xFE, 0xBD, 0xDF, 0x94, 0x02, 0xF8, 0x21, 0x96, 0xC8, 0xE9,
	0x9E, 0xF7, 0xBF, 0xBD, 0xCF, 0xCD, 0xB2, 0x7A, 0x00, 0x9F, 0x40, 0x22, 0xFC, 0x11, 0xF9, 0x0C,
	0x2E, 0x12, 0xFB, 0xA7, 0x74, 0x0A, 0x7D, 0x78, 0x40, 0x1E, 0x2C, 0xA0, 0x2D, 0x06, 0xCB, 0xA8,
	0xB9, 0x7E, 0xEF, 0xDE, 0x49, 0xEA, 0x4E, 0x13, 0x16, 0x16, 0x80, 0xF4, 0x3D, 0xC2, 0x9A, 0xD4,
	0x86, 0xD7, 0x94, 0x24, 0x17, 0xF4, 0xD6, 0x65, 0xBD, 0x3F, 0xDB, 0xE4, 0xE1, 0x0F, 0x50, 0xF6,
	0xEC, 0x7A, 0x9A, 0x0C, 0x27, 0x3D, 0x24, 0x66, 0xD3, 0x22, 0x68, 0x9C, 0x9A, 0x52, 0x0B, 0xE0,
	0xF9, 0xA5, 0x0B, 0x25, 0xDA, 0x80, 0x49, 0x0D, 0xFD, 0x3E, 0x77, 0xD1, 0x56, 0xA8, 0xB7, 0xF4,
	0x0F, 0x9B, 0xE8, 0x0F, 0x52, 0x47, 0xF5, 0x6F, 0x83, 0x20, 0x22, 0xDB, 0x0F, 0x0B, 0xB1, 0x43,
	0x85, 0xC1, 0xCB, 0xA4, 0x0B, 0x02, 0x19, 0xDF, 0xF0, 0x8B, 0xEC, 0xDB, 0x6C, 0x6D, 0x66, 0xAD,
	0x45, 0xBE, 0x89, 0x14, 0x7E, 0x2F, 0x89, 0x10, 0xB8, 0x93, 0x60, 0xD8, 0x60, 0xDE, 0xF6, 0xFE,
	0x6E, 0x9B, 0xCA, 0x06, 0xC1, 0x75, 0x95, 0x33, 0xCF, 0xC0, 0xB2, 0xE0, 0xCC, 0xA5, 0xCE, 0x12,
	0xF6, 0xE5, 0xB5, 0xB4, 0x26, 0xC5, 0xB2, 0x18, 0x4F, 0x2A, 0x5D, 0x26, 0x1B, 0x65, 0x4D, 0xF5,
	0x45, 0xC9, 0x84, 0x14, 0xDC, 0x7C, 0x12, 0x4B, 0x18, 0x9C, 0xC7, 0x24, 0xE7, 0x3C, 0x64, 0xFF,
	0xD6, 0x3A, 0x2C, 0xEE, 0x8C, 0x81, 0x49, 0x39, 0x6C, 0xB7, 0xDC, 0xBD, 0x94, 0xE2, 0x32, 0xF7,
	0xDD, 0x0A, 0xFC, 0x02, 0x01, 0x64, 0xEC, 0x4C, 0x94, 0x0A, 0xB1, 0x56, 0xF5, 0xC9, 0xA9, 0x34,
	0xDE, 0x0F, 0x38, 0x27, 0xBC, 0x81, 0x30, 0x0F, 0x7B, 0x38, 0x25, 0xFE, 0xE8, 0x3E, 0x29, 0xBA,
	0x55, 0x43, 0xBF, 0x6B, 0x9F, 0x1F, 0x8A, 0x49, 0x52, 0x18, 0x7F, 0x8A, 0xF8, 0x88, 0x24, 0x5C,
	0x4F, 0xE1, 0xA8, 0x30, 0x87, 0x8E, 0x50, 0x1F, 0x2F, 0xD1, 0x0C, 0xB4, 0xFD, 0x0A, 0xBC, 0xDC,
	0x12, 0x85, 0xE2, 0x52, 0xEE, 0x4A, 0x58, 0x38, 0xAB, 0xFF, 0xC6, 0x3D, 0xB9, 0x60, 0x64, 0x0A,
	0xB4, 0x50, 0xD5, 0x40, 0x89, 0x17, 0x9A, 0xD5, 0x85, 0xCF, 0xEC, 0x0D, 0x7E, 0x81, 0x7F, 0xE3,
	0xC3, 0x04, 0x01, 0x22, 0xEC, 0x27, 0xCC, 0xFA, 0x3E, 0x21, 0xA6, 0x54, 0xC8, 0xDE, 0x00, 0xB6,
	0xDF, 0x27, 0x9F, 0xF6, 0x25, 0x34, 0x07, 0x85, 0xBF, 0xA7, 0xA5, 0xA5, 0xE0, 0x83, 0x0C, 0x3D,
	0x5D, 0x20, 0x40, 0xAF, 0x60, 0xA3, 0x64, 0x56, 0xF3, 0x05, 0xC4, 0x1C, 0x7D, 0x37, 0x98, 0xC3,
	0xE8, 0x5A, 0x6E, 0x58, 0x85, 0xA4, 0x9A, 0x6B, 0x6A, 0xF4, 0xA3, 0x7B, 0x61, 0x9B, 0x09, 0x40,
	0x1E, 0x60, 0x4B, 0x32, 0xD9, 0x51, 0xA4, 0xFE, 0xF9, 0x5D, 0x4E, 0x4A, 0xFB, 0x4A, 0xD4, 0x7C,
	0x33, 0x02, 0x33, 0xD5, 0x9D, 0xCE, 0x5B, 0xAA, 0x5A, 0x7C, 0xD8, 0xF8, 0x05, 0xFA, 0x1F, 0x2B,
	0x8C, 0x72, 0x57, 0x50, 0xAE, 0x6C, 0x19, 0x89, 0xCA, 0x01, 0xFC, 0xFC, 0x29, 0x9B, 0x61, 0x12,
	0x68, 0x63, 0x65, 0x46, 0x26, 0xC4, 0x5B, 0x50, 0xAA, 0x2B, 0xBE, 0xEF, 0x9A, 0x79, 0x02, 0x23,
	0x75, 0x2C, 0x20, 0x13, 0xFD, 0xD9, 0x5A, 0x76, 0x23, 0xF1, 0x0B, 0xB5, 0xB8, 0x59, 0xF9, 0x9F,
	0x7A, 0xE6, 0x06, 0xE9, 0xA5, 0x3A, 0xB4, 0x50, 0xBF, 0x16, 0x58, 0x98, 0xB3, 0x9A, 0x6E, 0x36,
	0xEE, 0x8D, 0xEB}

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
	xorKey *uint16
}

type fiestaStreamFactory struct{}

type fiestaStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	fkey           string
	target         string
	segment        chan<- fiestaSegment
	xorKey         uint16
}

type fiestaSegment struct {
	data []byte
	seen time.Time
}

func (fsf *fiestaStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {

	src, _ := strconv.Atoi(transport.Src().String())
	dst, _ := strconv.Atoi(transport.Dst().String())

	var fkey string
	var target string

	if src >= 9000 && src <= 9600 {
		// server - client
		fkey = fmt.Sprintf("%v-Client", knownServices[src].name)
		target = "client"
	} else {
		fkey = fmt.Sprintf("Client-%v", knownServices[dst].name)
		target = "server"
	}

	log.Printf("new stream %v:%v started", net, transport)
	segments := make(chan fiestaSegment, 512)
	s := &fiestaStream{
		net:       net,
		transport: transport,
		fkey:      fkey,
		target:    target,
		segment:   segments,
	}

	go s.decode(segments)

	return s
}

//func (fs *fiestaStream) decode(segments <-chan fiestaSegment, xorKey <-chan uint16) {
func (fs *fiestaStream) decode(segments <-chan fiestaSegment) {
	var d []byte
	var offset int
	offset = 0

nextSegment:
	for segment := range segments {
		d = append(d, segment.data...)

		if offset > len(d) {
			continue nextSegment
		}

		if fs.target == "server" {
			dst, _ := strconv.Atoi(fs.transport.Dst().String())
			if knownServices[dst].xorKey == nil {
				fmt.Printf("\nMissing xorKey for service %v, waiting...", knownServices[dst].name)
				continue
			}
		}
		for offset != len(d) {
			//offset, from = nextFiestaPacket(offset, d)
			var skipBytes int
			var pLen int
			var pType string
			var rs []byte

			pLen, pType = rawSlice(offset, d)

			if pType == "small" {
				skipBytes = 1
			} else {
				skipBytes = 3
			}

			nextOffset := offset + skipBytes + pLen
			if nextOffset > len(d) {
				continue nextSegment
			}

			rs = append(rs, d[offset+skipBytes:nextOffset]...)

			go fs.readPacket(segment.seen, pLen, pType, rs)

			offset += skipBytes + pLen
		}
	}
}

func rawSlice(offset int, b []byte) (int, string) {
	if b[offset] == 0 {
		// len big packet
		var pLen uint16
		var tempB []byte
		tempB = append(tempB, b[offset:]...)
		br := bytes.NewReader(tempB)
		br.ReadAt(tempB, 1)
		binary.Read(br, binary.LittleEndian, &pLen)
		return int(pLen), "big"
	} else {
		var pLen uint8
		pLen = b[offset]
		return int(pLen), "small"
	}
}

func (fs *fiestaStream) readPacket(seen time.Time, pLen int, pType string, data []byte) {
	if fs.target == "server" {
		dst, _ := strconv.Atoi(fs.transport.Dst().String())
		if knownServices[dst].xorKey == nil {
			panic("missing xorKey")
		}
		xorCipher(data, knownServices[dst].xorKey)
	}
	var opCode, department, command uint16
	br := bytes.NewReader(data)
	binary.Read(br, binary.LittleEndian, &opCode)
	if opCode == 2055 {
		var xorKey uint16
		src, _ := strconv.Atoi(fs.transport.Src().String())
		binary.Read(br, binary.LittleEndian, &xorKey)
		knownServices[src].xorKey = &xorKey
		log.Printf("[%v]Found xor key %v for service %v\n", seen, xorKey, knownServices[src].name)
		log.Printf("[%v]Found xor key %v for service %v\n", seen, xorKey, knownServices[src].name)
		log.Printf("[%v]Found xor key %v for service %v\n", seen, xorKey, knownServices[src].name)
	}

	department = opCode >> 10
	command = opCode & 1023
	pc := PC{
		pcb: ProtocolCommandBase{
			packetType:    pType,
			length:        pLen,
			department:    department,
			command:       command,
			operationCode: opCode,
			data:          data,
		},
	}
	if fs.target == "server" {
		src, _ := strconv.Atoi(fs.transport.Src().String())
		dst, _ := strconv.Atoi(fs.transport.Dst().String())
		fmt.Printf("\n[%v] [%v] [%v - %v] %v", seen, fs.fkey, src, dst, pc.pcb.String())
	}
}

func (fs *fiestaStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if len(reassembly.Bytes) == 0 {
			continue
		}
		seg := fiestaSegment{data: reassembly.Bytes, seen: reassembly.Seen}
		fs.segment <- seg
	}
}

func (fs *fiestaStream) ReassemblyComplete() {
	// Server stream. Gives xorKey
	// Client stream. Uses xorKey
	// Client stream content cannot be decoded until xorKey is available
	// A decode goroutine that listens on a xorKey channel
	// Once Server stream finds xorKey, search thru the stream factory for a stream where dst port equals current stream src port
	// Send xorKey on that channel
	src, _ := strconv.Atoi(fs.transport.Src().String())
	dst, _ := strconv.Atoi(fs.transport.Dst().String())
	log.Printf("[Stream completed] [%v - %v]", src, dst)
}

// decrypt encrypted bytes
func xorCipher(eb []byte, xorPos *uint16) {
	for i, _ := range eb {
		eb[i] ^= xorKey[*xorPos]
		*xorPos++
		//if xorPos == 499 {
		if *xorPos == 350 {
			*xorPos = 0
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

	go listen(ctx, pf)

	select {
	case <-c:
		pf.persist()
		cancel()
	case <-ctx.Done():
		pf.persist()
	}

}

func listen(ctx context.Context, pf *PacketFlow) {

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
