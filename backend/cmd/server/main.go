package main

import (
	"log"
	"net/http"

	"navplane/internal/config"
	"navplane/internal/handler"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	log.Printf("NavPlane server starting on :%s (env: %s)", cfg.Port, cfg.Environment)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatal(err)
	}
}
