package handler

import "net/http"

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", HealthCheck)
	mux.HandleFunc("GET /api/v1/status", Status)
}
