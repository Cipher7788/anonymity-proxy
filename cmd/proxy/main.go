package main

import (
	"fmt"
	"net/http"
)

func main() {
	fmt.Println("Starting proxy engine...")

	// Set up HTTP server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	})

	// Bind to port 8080 and start the server
	if err := http.ListenAndServe":"8080, nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}