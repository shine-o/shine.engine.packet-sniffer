package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"log"
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

type shineSegment struct {
	data []byte
	seen time.Time
}

var xorKey []byte

// big or small packet
func (pcb *ProtocolCommandBase) Type() string {
	return pcb.packetType
}

func (pcb *ProtocolCommandBase) Length() int {
	return pcb.length
}

// network command category inside the Client [ more info with the leaked pdb ]
func (pcb *ProtocolCommandBase) Department() uint16 {
	return pcb.department
}

// network command category action inside the Client [ more info with the leaked pdb ]
func (pcb *ProtocolCommandBase) Command() uint16 {
	return pcb.command
}

// a.k.a packet header
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

// readable packet format
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

// find out if big or small packet
// return length and type
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
