package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"navplane/internal/config"
	"navplane/internal/openai"
)

// httpClient is the shared HTTP client for upstream requests.
// Using a shared client enables connection pooling.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// chatCompletionsHandler returns an HTTP handler that forwards requests to the upstream provider.
// This pattern allows the handler to access provider configuration.
//
// Current behavior:
//   - Parses and validates the request body
//   - For non-streaming requests: forwards to upstream provider and returns response
//   - For streaming requests: returns 501 Not Implemented (streaming comes in next task)
//   - Returns 400 Bad Request for invalid JSON or validation errors
//   - Returns 405 Method Not Allowed for non-POST requests
//   - Returns 502 Bad Gateway if upstream call fails
//
// Security notes:
//   - Request bodies are intentionally not logged
//   - Client Authorization header is never forwarded upstream
//   - Provider API key is injected server-side
func chatCompletionsHandler(cfg *config.Config) http.HandlerFunc {
	// Pre-compute the upstream URL (handle trailing slash)
	upstreamURL := strings.TrimSuffix(cfg.Provider.BaseURL, "/") + "/v1/chat/completions"

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Only allow POST method
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "method not allowed",
					"type":    "invalid_request_error",
				},
			})
			return
		}

		// Read the raw request body (preserve for forwarding)
		rawBody, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "failed to read request body",
					"type":    "invalid_request_error",
				},
			})
			return
		}

		// Parse the request body
		var req openai.ChatCompletionsRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "invalid JSON: " + err.Error(),
					"type":    "invalid_request_error",
				},
			})
			return
		}

		// Validate the request
		if err := req.Validate(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": err.Error(),
					"type":    "invalid_request_error",
				},
			})
			return
		}

		// Check for streaming - not implemented yet
		if req.Stream != nil && *req.Stream {
			w.WriteHeader(http.StatusNotImplemented)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "streaming not implemented yet",
					"type":    "not_implemented_error",
				},
			})
			return
		}

		// Forward the request to the upstream provider
		upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, bytes.NewReader(rawBody))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "failed to create upstream request",
					"type":    "server_error",
				},
			})
			return
		}

		// Set required headers for upstream
		upstreamReq.Header.Set("Content-Type", "application/json")
		upstreamReq.Header.Set("Authorization", "Bearer "+cfg.Provider.APIKey)

		// Forward safe headers from client (optional)
		// Forward X-Request-ID if present, or we could generate one
		if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
			upstreamReq.Header.Set("X-Request-ID", reqID)
		}

		// Make the upstream request
		upstreamResp, err := httpClient.Do(upstreamReq)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "upstream request failed",
					"type":    "upstream_error",
				},
			})
			return
		}
		defer upstreamResp.Body.Close()

		// Read the upstream response body
		upstreamBody, err := io.ReadAll(upstreamResp.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"message": "failed to read upstream response",
					"type":    "upstream_error",
				},
			})
			return
		}

		// Preserve Content-Type from upstream (usually application/json)
		if ct := upstreamResp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}

		// Return the upstream response transparently (same status code and body)
		w.WriteHeader(upstreamResp.StatusCode)
		w.Write(upstreamBody)
	}
}

// ChatCompletions is kept for backward compatibility with existing tests.
// It wraps chatCompletionsHandler with a nil config check for testing scenarios.
// In production, use chatCompletionsHandler(cfg) via RegisterRoutes.
//
// Deprecated: Use chatCompletionsHandler via RegisterRoutes instead.
func ChatCompletions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Only allow POST method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "method not allowed",
				"type":    "invalid_request_error",
			},
		})
		return
	}

	// Read the raw request body
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "failed to read request body",
				"type":    "invalid_request_error",
			},
		})
		return
	}

	// Parse the request body
	var req openai.ChatCompletionsRequest
	if err := json.Unmarshal(rawBody, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "invalid JSON: " + err.Error(),
				"type":    "invalid_request_error",
			},
		})
		return
	}

	// Validate the request
	if err := req.Validate(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": err.Error(),
				"type":    "invalid_request_error",
			},
		})
		return
	}

	// Check for streaming - not implemented yet
	if req.Stream != nil && *req.Stream {
		w.WriteHeader(http.StatusNotImplemented)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "streaming not implemented yet",
				"type":    "not_implemented_error",
			},
		})
		return
	}

	// This function is for backward compatibility with validation tests.
	// In production, chatCompletionsHandler handles the upstream forwarding.
	// Return error indicating no provider configured.
	w.WriteHeader(http.StatusServiceUnavailable)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"message": "no provider configured",
			"type":    "server_error",
		},
	})
}

// SetHTTPClient allows tests to inject a custom HTTP client.
// This is useful for testing without making real network calls.
func SetHTTPClient(client *http.Client) {
	httpClient = client
}

// buildUpstreamURL constructs the upstream URL for chat completions.
// Exported for testing purposes.
func BuildUpstreamURL(baseURL string) string {
	return strings.TrimSuffix(baseURL, "/") + "/v1/chat/completions"
}

// ForwardRequest is a test helper that creates and executes an upstream request.
// This is exported to allow integration testing of the forwarding logic.
func ForwardRequest(cfg *config.Config, rawBody []byte, clientHeaders http.Header) (*http.Response, error) {
	upstreamURL := BuildUpstreamURL(cfg.Provider.BaseURL)

	upstreamReq, err := http.NewRequest(http.MethodPost, upstreamURL, bytes.NewReader(rawBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create upstream request: %w", err)
	}

	// Set required headers
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("Authorization", "Bearer "+cfg.Provider.APIKey)

	// Forward X-Request-ID if present
	if reqID := clientHeaders.Get("X-Request-ID"); reqID != "" {
		upstreamReq.Header.Set("X-Request-ID", reqID)
	}

	return httpClient.Do(upstreamReq)
}
