package lib

import "log"

func logError(e error) {
	if e != nil {
		log.Println(e)
	}
}

func panicError(e error) {
	if e != nil {
		panic(e)
	}
}
