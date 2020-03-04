package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"path/filepath"
	"strconv"
	"strings"
)

type PCList struct {
	Departments map[uint8]Department
}

type RawPCList struct {
	Departments []Department `yaml:"departments,flow"`
}

type Department struct {
	HexId             string `yaml:"hexId"`
	Name              string `yaml:"name"`
	RawCommands       string `yaml:"commands"`
	ProcessedCommands map[string]string
}

var pcl *PCList

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
		FriendlyName  string `json:"friendlyName"`
	}

	ePcb := exportedPcb{
		PacketType:    pcb.packetType,
		Length:        pcb.length,
		Department:    pcb.department,
		Command:       fmt.Sprintf("%X", pcb.command),
		OperationCode: pcb.operationCode,
		Data:          hex.EncodeToString(pcb.data),
	}

	if dpt, ok := pcl.Departments[uint8(pcb.department)]; ok {
		//fmt.Println(dpt.ProcessedCommands)
		ePcb.FriendlyName = dpt.ProcessedCommands[ePcb.Command]
	}

	rawJson, err := json.Marshal(&ePcb)
	if err != nil {
		log.Println(err.Error())
	}
	return string(rawJson)
}

// struct information about captured network packets
func initPCList() {

	pcl = &PCList{
		Departments: make(map[uint8]Department),
	}

	pathName, err := filepath.Abs(viper.GetString("protocol.nc-data"))
	panicError(err)

	d, err := ioutil.ReadFile(pathName)
	logError(err)

	rPcl := &RawPCList{}

	err = yaml.Unmarshal(d, rPcl)
	panicError(err)

	for _, d := range rPcl.Departments {

		dptHexVal := strings.ReplaceAll(d.HexId, "0x", "")

		dptIntVal, _ := strconv.ParseUint(dptHexVal, 16, 32)

		department := Department{
			HexId:             d.HexId,
			Name:              d.Name,
			ProcessedCommands: make(map[string]string),
		}
		cmdsRaw := d.RawCommands
		cmdsRaw = strings.ReplaceAll(cmdsRaw, "\n", "")
		cmdsRaw = strings.ReplaceAll(cmdsRaw, " ", "")
		cmdsRaw = strings.ReplaceAll(cmdsRaw, "0x", "")
		cmdsRaw = strings.ReplaceAll(cmdsRaw, "\t", "")

		cmds := strings.Split(cmdsRaw, ",")

		for _, c := range cmds {
			if c == "" {
				continue
			}
			cs := strings.Split(c, "=")
			department.ProcessedCommands[cs[1]] = cs[0]
		}

		pcl.Departments[uint8(dptIntVal)] = department
	}
	fmt.Println(pcl)
}
