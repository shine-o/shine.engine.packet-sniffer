package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/viper"
	"log"
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

				pLen, pType = rawSlice(offset, d)

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
				pm.readPacket()

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

				pLen, pType = rawSlice(offset, d)

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

				pm.readPacket()

				offset += skipBytes + pLen
			}
		}
	}
}

// read packet data
// if xorKey is detected in a server flow (packets coming from the server), that is if header == 2055, notify the converse flow
// create PC struct with packet headers + data
func (pm packetMetadata) readPacket() {
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
	pc := PC{
		pcb: ProtocolCommandBase{
			packetType:    pm.packetType,
			length:        pm.length,
			department:    department,
			command:       command,
			operationCode: opCode,
			data:          pm.data,
		},
	}

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

// find out if big or small packet
// return length and type
func rawSlice(offset int, b []byte) (int, string) {
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
