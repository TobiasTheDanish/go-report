package main

import (
	"log"

	"github.com/tobiasthedanish/go-report/internal/server"
)

func main() {
	s, err := server.NewServer()
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(s.ListenAndServe())
}
