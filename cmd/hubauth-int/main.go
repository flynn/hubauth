package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	httpPort := os.Getenv("PORT")
	if httpPort == "" {
		httpPort = "8000"
	}

	http.HandleFunc("/cron", func(w http.ResponseWriter, r *http.Request) {
	})

	log.Fatal(http.ListenAndServe(":"+httpPort, nil))
}
