package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"log"
	"strconv"
	"time"
)

type ProtocolCommand interface {
	Type() int
	Length() int
	Department() uint16
	Command() uint16
	OperationCode() uint16
	Data() []byte
	RawData() []byte
	String() string
}

type ProtocolCommandBase struct {
	packetType    string
	length        int
	department    uint16
	command       uint16
	operationCode uint16
	data          []byte
}

type PC struct {
	pcb ProtocolCommandBase
	pcc interface{} // protocol command concrete, eg: PROTO_NC_QUEST_GIVEUP_ACK
}

type service struct {
	name   string
	xorKey *uint16
}

type fiestaSegment struct {
	data []byte
	seen time.Time
}

var xorKey []byte

func (pcb *ProtocolCommandBase) Type() string {
	return pcb.packetType
}

func (pcb *ProtocolCommandBase) Length() int {
	return pcb.length
}

func (pcb *ProtocolCommandBase) Department() uint16 {
	return pcb.department
}

func (pcb *ProtocolCommandBase) Command() uint16 {
	return pcb.command
}

func (pcb *ProtocolCommandBase) OperationCode() uint16 {
	return pcb.department<<10 | pcb.command&1023
}

func (pcb *ProtocolCommandBase) Data() []byte {
	return pcb.data
}

// reassemble packet raw data
func (pcb *ProtocolCommandBase) RawData() []byte {
	var r []byte
	if pcb.packetType == "small" {
		r = append(r, uint8(pcb.length))
	} else {
		r = append(r, uint8(0))
		r = append(r, byte(pcb.length))
	}
	r = append(r, byte(pcb.operationCode))
	r = append(r, pcb.data...)
	return r
}

func (pcb *ProtocolCommandBase) String() string {
	type exportedPcb struct {
		PacketType    string `json:"packetType"`
		Length        int    `json:"length"`
		Department    uint16 `json:"department"`
		Command       string `json:"command"`
		OperationCode uint16 `json:"opCode"`
		Data          string `json:"data"`
	}
	ePcb := exportedPcb{
		PacketType:    pcb.packetType,
		Length:        pcb.length,
		Department:    pcb.department,
		Command:       fmt.Sprintf("%x", pcb.command),
		OperationCode: pcb.operationCode,
		Data:          hex.EncodeToString(pcb.data),
	}
	rawJson, err := json.Marshal(&ePcb)
	if err != nil {
		log.Println(err.Error())
	}
	return string(rawJson)
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
	//if fs.target == "server" {
	//
	//}
	src, _ := strconv.Atoi(fs.transport.Src().String())
	dst, _ := strconv.Atoi(fs.transport.Dst().String())
	fmt.Printf("\n[%v] [%v] [%v - %v] %v", seen, fs.fkey, src, dst, pc.pcb.String())
}

// decrypt encrypted bytes
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