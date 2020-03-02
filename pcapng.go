package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

type Flows struct {
	pfm map[string][]gopacket.Packet
	m   sync.Mutex
}

// asses the package flow, either Client-Service or Service-Client
func (pf *Flows) add(p gopacket.Packet) {

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
func (pf *Flows) persist() {
	pf.m.Lock()
	for k, v := range pf.pfm {
		pathName, err := filepath.Abs(fmt.Sprintf("%v%v", "output/", k))

		f, err := os.OpenFile(pathName, os.O_WRONLY|os.O_CREATE, 0666)

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
	pf.m.Unlock()
}

// persist the available xorKeys
//func persistXorKeys() {
//	xorKeysFile, err := filepath.Abs(fmt.Sprintf("%v%v", "output/", "xorKeys.txt"))
//
//	xkf, err := os.OpenFile(xorKeysFile, os.O_WRONLY|os.O_CREATE, 0666)
//
//	if err != nil {
//		fmt.Println(err)
//	}
//	for _, v := range knownServices {
//		if v.xorKey != nil {
//			sx := fmt.Sprintf("%v -> %v\n", v.name, *v.xorKey)
//			_, err := xkf.Write([]byte(sx))
//			if err != nil {
//				fmt.Println(err)
//			}
//		}
//	}
//	xkf.Close()
//}
