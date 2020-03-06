package lib

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

type activeStreams struct {
	fromClient map[int]*shineStream
	fromServer map[int]*shineStream
	mu         sync.Mutex
}

type shineStreamFactory struct{}

type shineStream struct {
	src, dst           int //  tcp ports
	segment            chan<- shineSegment
	xorKey             chan<- uint16 // used to decrypt packets flowing from the client, it increments by one for each decrypted byte
	reassemblyComplete chan<- bool
}

type shineSegment struct {
	data []byte
	seen time.Time
}

type packetMetadata struct {
	src, dst   int
	seen       time.Time
	length     int
	packetType string
	data       []byte
}

type Shine struct {
	knownServices map[int]*service // port => serviceName
	mu            sync.Mutex
}

type service struct {
	name string
}

var xorKey []byte
var cs *activeStreams
var iface string
var snaplen int
var filter string
var shine Shine

func captureConfig()  {
	initPCList()
	// remove output folder if exists, create it again
	dir, err := filepath.Abs("output/")
	if _, err := os.Stat(dir); os.IsNotExist(err) {

	} else {
		err = os.RemoveAll(dir)
		logError(err)
	}

	err = os.Mkdir(dir, 0700)
	logError(err)

	iface = viper.GetString("network.interface")
	snaplen = viper.GetInt("network.snaplen")

	serverIp := viper.GetString("network.serverIp")
	startPort := viper.GetString("network.portRange.start")
	endPort := viper.GetString("network.portRange.end")
	portRange := fmt.Sprintf("%v-%v", startPort, endPort)

	filter = fmt.Sprintf("(dst net %v or src net %v) and (dst portrange %v or src portrange %v)", serverIp, serverIp, portRange, portRange)

	xorKey, err = hex.DecodeString(viper.GetString("protocol.xorTableHexString"))
	shine.mu.Lock()
	shine.knownServices = make(map[int]*service)
	if viper.IsSet("protocol.services") {
		// snippet for loading yaml array
		services := make([]map[string]string, 0)
		var m map[string]string
		servicesI := viper.Get("protocol.services")
		servicesS := servicesI.([]interface{})
		for _, s := range servicesS {
			serviceMap := s.(map[interface{}]interface{})
			m = make(map[string]string)
			for k, v := range serviceMap {
				m[k.(string)] = v.(string)
			}
			services = append(services, m)
		}
		for _, v := range services {
			port, err := strconv.Atoi(v["port"])
			logError(err)
			shine.knownServices[port] = &service{name: v["name"]}
		}
	} else {
		shine.knownServices[9000] = &service{name: "Account"}
		shine.knownServices[9311] = &service{name: "AccountLog"}
		shine.knownServices[9411] = &service{name: "Character"}
		shine.knownServices[9511] = &service{name: "GameLog"}
		shine.knownServices[9010] = &service{name: "Login"}
		shine.knownServices[9110] = &service{name: "WorldManager"}
		shine.knownServices[9210] = &service{name: "Zone00"}
		shine.knownServices[9212] = &service{name: "Zone01"}
		shine.knownServices[9214] = &service{name: "Zone02"}
		shine.knownServices[9216] = &service{name: "Zone03"}
		shine.knownServices[9218] = &service{name: "Zone04"}
	}
	shine.mu.Unlock()
}

func Capture(cmd *cobra.Command, args []string) {
	captureConfig()
	pf := &Flows{
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
		//persistXorKeys()
		cancel()
	case <-ctx.Done():
		pf.persist()
	}

}

func listen(ctx context.Context, pf *Flows) {
	cs = &activeStreams{
		fromClient: make(map[int]*shineStream),
		fromServer: make(map[int]*shineStream),
	}
	sf := &shineStreamFactory{}
	sp := tcpassembly.NewStreamPool(sf)
	a := tcpassembly.NewAssembler(sp)

	if handle, err := pcap.OpenLive(iface, int32(snaplen), true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(filter); err != nil { //
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


func (fsf *shineStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	src, _ := strconv.Atoi(transport.Src().String())
	dst, _ := strconv.Atoi(transport.Dst().String())
	segments := make(chan shineSegment, 512)
	reassemblyComplete := make(chan bool)
	xorKey := make(chan uint16)

	s := &shineStream{
		src:                src,
		dst:                dst,
		segment:            segments,
		xorKey:             xorKey,
		reassemblyComplete: reassemblyComplete,
	}

	cs.mu.Lock()
	if src >= 9000 && src <= 9600 {
		// server - client
		cs.fromServer[src] = s
		go s.decodeServerPackets(segments, reassemblyComplete)
	} else {
		// client - server
		cs.fromClient[src] = s
		go s.decodeClientPackets(segments, reassemblyComplete, xorKey)
	}
	cs.mu.Unlock()

	log.Printf("new stream %v:%v started", net, transport)

	return s
}

func (fs *shineStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, reassembly := range reassemblies {
		if len(reassembly.Bytes) == 0 {
			continue
		}
		seg := shineSegment{data: reassembly.Bytes, seen: reassembly.Seen}
		fs.segment <- seg
	}
}

func (fs *shineStream) ReassemblyComplete() {
	log.Printf("[Stream completed] [%v - %v]", fs.src, fs.dst)
	cs.mu.Lock()
	if fs.src >= 9000 && fs.src <= 9600 {
		cs.fromServer[fs.src] = nil
	} else {
		cs.fromClient[fs.dst] = nil
	}
	cs.mu.Unlock()
	fs.reassemblyComplete <- true
}

// wait for xor key to be found
// process segment data, decrypt it, create readable packet
func (fs *shineStream) decodeClientPackets(segments <-chan shineSegment, reassemblyComplete <-chan bool, xorKey <-chan uint16) {
	var d []byte
	var offset int
	var seen time.Time
	var xk uint16
	offset = 0
	xk = 999 // impossible value

	select {
	case xk = <-xorKey:
		break
	}

	for {
		select {
		case <-reassemblyComplete:
			log.Println("reassembly complete signal received, exiting decode function")
			return

		case segment := <-segments:
			d = append(d, segment.data...)
			seen = segment.seen

			if offset > len(d) {
				break
			}

			if xk == 999 {
				break
			}

			if offset != len(d) {
				var skipBytes int
				var pLen int
				var pType string
				var rs []byte

				pLen, pType = packetBoundary(offset, d)

				if pType == "small" {
					skipBytes = 1
				} else {
					skipBytes = 3
				}

				nextOffset := offset + skipBytes + pLen
				if nextOffset > len(d) {
					break
				}

				rs = append(rs, d[offset+skipBytes:nextOffset]...)

				xorCipher(rs, &xk)

				pm := &packetMetadata{
					src:        fs.src,
					dst:        fs.dst,
					seen:       seen,
					length:     pLen,
					packetType: pType,
					data:       rs,
				}
				pc := pm.processPacket()
				pm.logPacket(pc)
				offset += skipBytes + pLen
			}
		}
	}
}

// process segment data, create readable packet
func (fs *shineStream) decodeServerPackets(segments <-chan shineSegment, reassemblyComplete <-chan bool) {
	var d []byte
	var seen time.Time

	var offset int
	offset = 0

	for {
		select {
		case <-reassemblyComplete:
			log.Println("reassembly complete signal received, exiting decode function")
			return
		case segment := <-segments:
			d = append(d, segment.data...)
			seen = segment.seen
			if offset > len(d) {
				break
			}

			if offset != len(d) {
				var skipBytes int
				var pLen int
				var pType string
				var rs []byte

				pLen, pType = packetBoundary(offset, d)

				if pType == "small" {
					skipBytes = 1
				} else {
					skipBytes = 3
				}

				nextOffset := offset + skipBytes + pLen
				if nextOffset > len(d) {
					break
				}

				rs = append(rs, d[offset+skipBytes:nextOffset]...)

				pm := &packetMetadata{
					src:        fs.src,
					dst:        fs.dst,
					seen:       seen,
					length:     pLen,
					packetType: pType,
					data:       rs,
				}

				pc := pm.processPacket()

				pm.logPacket(pc)

				offset += skipBytes + pLen
			}
		}
	}
}

func (pm packetMetadata) logPacket(pc PC) {
	var flowKey string
	if pm.src >= 9000 && pm.src <= 9600 {
		flowKey = fmt.Sprintf("%v-Client", shine.knownServices[pm.src].name)
		pLog := fmt.Sprintf("\n[%v] [%v] [%v - %v] %v", pm.seen, flowKey, pm.src, pm.dst, pc.pcb.String())
		if viper.GetBool("protocol.log.client") {
			fmt.Print(pLog)
		}
	} else {
		flowKey = fmt.Sprintf("Client-%v", shine.knownServices[pm.dst].name)
		pLog := fmt.Sprintf("\n[%v] [%v] [%v - %v] %v", pm.seen, flowKey, pm.src, pm.dst, pc.pcb.String())
		if viper.GetBool("protocol.log.server") {
			fmt.Print(pLog)
		}
	}
}

// read packet data
// if xorKey is detected in a server flow (packets coming from the server), that is if header == 2055, notify the converse flow
// create PC struct with packet headers + data
func (pm packetMetadata) processPacket() PC {
	var opCode, department, command uint16
	br := bytes.NewReader(pm.data)
	binary.Read(br, binary.LittleEndian, &opCode)
	if opCode == 2055 {
		var xorKey uint16
		binary.Read(br, binary.LittleEndian, &xorKey)

		cs.mu.Lock()
		if cs.fromClient[pm.dst] != nil {
			cs.fromClient[pm.dst].xorKey <- xorKey
		}
		cs.mu.Unlock()

		log.Printf("[%v]Found xor key %v for service %v\n", pm.seen, xorKey, shine.knownServices[pm.src].name)
	}

	department = opCode >> 10
	command = opCode & 1023
	return PC{
		pcb: ProtocolCommandBase{
			packetType:    pm.packetType,
			length:        pm.length,
			department:    department,
			command:       command,
			operationCode: opCode,
			data:          pm.data,
		},
	}
}

// find out if big or small packet
// return length and type
func packetBoundary(offset int, b []byte) (int, string) {
	if b[offset] == 0 {
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

// decrypt encrypted bytes using captured xorKey and xorTable
func xorCipher(eb []byte, xorPos *uint16) {
	xorLimit := uint16(viper.GetInt("protocol.xorLimit"))
	for i, _ := range eb {
		eb[i] ^= xorKey[*xorPos]
		*xorPos++
		if *xorPos >= xorLimit {
			*xorPos = 0
		}
	}
}
