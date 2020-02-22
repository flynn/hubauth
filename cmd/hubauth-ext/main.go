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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://flynn.io/", http.StatusTemporaryRedirect)
	})
	http.HandleFunc("/privacy", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://flynn.io/legal/privacy", http.StatusTemporaryRedirect)
	})

	log.Fatal(http.ListenAndServe(":"+httpPort, nil))
}
