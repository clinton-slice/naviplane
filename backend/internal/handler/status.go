package handler

import (
	"encoding/json"
	"net/http"
)

func Status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"service": "navplane",
		"version": "0.1.0",
		"status":  "operational",
	})
}
