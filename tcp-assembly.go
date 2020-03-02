package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
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
	net, transport     gopacket.Flow
	r                  tcpreader.ReaderStream
	fkey               string
	target             string
	segment            chan<- shineSegment
	xorKey             chan<- uint16
	reassemblyComplete chan<- bool
}

var cs *activeStreams

func (fsf *shineStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {

	src, _ := strconv.Atoi(transport.Src().String())
	dst, _ := strconv.Atoi(transport.Dst().String())

	var fkey string
	var target string

	if src >= 9000 && src <= 9600 {
		// server - client
		fkey = fmt.Sprintf("%v-Client", knownServices[src].name)
		target = "client"
	} else {
		// client - server
		fkey = fmt.Sprintf("Client-%v", knownServices[dst].name)
		target = "server"
	}

	log.Printf("new stream %v:%v started", net, transport)
	segments := make(chan shineSegment, 512)
	reassemblyComplete := make(chan bool)
	xorKey := make(chan uint16)
	s := &shineStream{
		net:                net,
		transport:          transport,
		fkey:               fkey,
		target:             target,
		segment:            segments,
		xorKey:             xorKey,
		reassemblyComplete: reassemblyComplete,
	}
	cs.mu.Lock()

	if target == "client" {
		cs.fromServer[src] = s
		go s.decodeServerPackets(segments, reassemblyComplete)
	} else {
		cs.fromClient[src] = s
		go s.decodeClientPackets(segments, reassemblyComplete, xorKey)
	}

	cs.mu.Unlock()

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
	src, _ := strconv.Atoi(fs.transport.Src().String())
	dst, _ := strconv.Atoi(fs.transport.Dst().String())
	log.Printf("[Stream completed] [%v - %v]", src, dst)
	cs.mu.Lock()
	if fs.target == "client" {
		cs.fromServer[src] = nil
	} else {
		cs.fromClient[dst] = nil
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

				fs.readPacket(seen, pLen, pType, rs)

				offset += skipBytes + pLen
			}
		}
	}
}

// process segment data, create readable packet
func (fs *shineStream) decodeServerPackets(segments <-chan shineSegment, reassemblyComplete <-chan bool) {
	var d []byte
	var offset int
	offset = 0

	for {
		select {
		case <-reassemblyComplete:
			log.Println("reassembly complete signal received, exiting decode function")
			return
		case segment := <-segments:
			d = append(d, segment.data...)

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
				fs.readPacket(segment.seen, pLen, pType, rs)

				offset += skipBytes + pLen
			}
		}
	}
}

// read packet data
// if xorKey is detected in a server flow (packets coming from the server), that is if header == 2055, notify the converse flow
// create PC struct with packet headers + data
func (fs *shineStream) readPacket(seen time.Time, pLen int, pType string, data []byte) {
	var opCode, department, command uint16
	br := bytes.NewReader(data)
	binary.Read(br, binary.LittleEndian, &opCode)
	if opCode == 2055 {
		var xorKey uint16
		src, _ := strconv.Atoi(fs.transport.Src().String())
		dst, _ := strconv.Atoi(fs.transport.Dst().String())
		binary.Read(br, binary.LittleEndian, &xorKey)

		cs.mu.Lock()
		if cs.fromClient[dst] != nil {
			cs.fromClient[dst].xorKey <- xorKey
		}
		cs.mu.Unlock()

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

	src, _ := strconv.Atoi(fs.transport.Src().String())
	dst, _ := strconv.Atoi(fs.transport.Dst().String())
	pLog := fmt.Sprintf("\n[%v] [%v] [%v - %v] %v", seen, fs.fkey, src, dst, pc.pcb.String())
	if fs.target == "server" {
		if viper.GetBool("protocol.log.client") {
			fmt.Print(pLog)
		}
	} else {
		if viper.GetBool("protocol.log.server") {
			fmt.Print(pLog)
		}
	}
}
