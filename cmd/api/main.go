package main

import (
	"log"

	"github.com/tobiasthedanish/go-report/internal"
)

func main() {
	server, err := internal.NewServer()
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(server.ListenAndServe())
}
