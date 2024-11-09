package main

import (
	"fmt"
	"net/http"
)

func main() {
	// Handler function for the root path ("/")
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from Go web server!\n")
	})

	// Start the server listening on port 8080
	fmt.Println("Server listening on http://localhost:8080/")
	http.ListenAndServe(":8080", nil)
}
