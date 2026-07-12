package main

import (
	"log"

	"elvanto-broker/internal/app"
)

func main() {
	server, err := app.NewFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.Run())
}
