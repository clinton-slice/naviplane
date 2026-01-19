package main

import (
	"log"
	"net/http"

	"navplane/internal/config"
	"navplane/internal/handler"
)

func main() {
	cfg := config.Load()

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	log.Printf("NavPlane server starting on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatal(err)
	}
}
