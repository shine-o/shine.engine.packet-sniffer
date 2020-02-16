package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

type ProtoGroup struct {
	Id   uint8
	Name [512]byte
}

func main() {
	dat, err := os.Open(".\\proto.ppb")
	//dat, err := ioutil.ReadFile(".\\proto.ppb")
	//dat, err := ioutil.ReadFile(".\\Fiesta.h")

	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s", dat)

	r := bufio.NewReader(dat)
	for {
		var pg ProtoGroup
		b, _, err := r.ReadLine()

		br := bytes.NewReader(b)
		binary.Read(br, binary.LittleEndian, &pg)
		if err != nil {
			return
		}
		fmt.Println(b)
	}

}
