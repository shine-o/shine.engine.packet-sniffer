package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"log"
	"strconv"
)

type fiestaStreamFactory struct{}

type fiestaStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	fkey           string
	target         string
	segment        chan<- fiestaSegment
	xorKey         uint16
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
