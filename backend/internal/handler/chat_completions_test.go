package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"navplane/internal/config"
)

// ========================================================================
// Validation Tests (using ChatCompletions without provider - returns 503 for valid requests)
// ========================================================================

func TestChatCompletions_InvalidJSON(t *testing.T) {
	// Test: POST with invalid JSON returns 400
	body := `{"model": "gpt-4", "messages": [`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	// Verify Content-Type header
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Verify error response structure
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %T", resp["error"])
	}
	if errObj["type"] != "invalid_request_error" {
		t.Errorf("expected error type 'invalid_request_error', got %v", errObj["type"])
	}
	msg, ok := errObj["message"].(string)
	if !ok || !strings.Contains(msg, "invalid JSON") {
		t.Errorf("expected error message to contain 'invalid JSON', got %v", errObj["message"])
	}
}

func TestChatCompletions_MissingModel(t *testing.T) {
	// Test: POST missing model returns 400
	body := `{
		"messages": [{"role": "user", "content": "Hello"}]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "model") {
		t.Errorf("expected error message to mention 'model', got %s", msg)
	}
}

func TestChatCompletions_EmptyModel(t *testing.T) {
	// Test: POST with empty model returns 400
	body := `{
		"model": "",
		"messages": [{"role": "user", "content": "Hello"}]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "model") {
		t.Errorf("expected error message to mention 'model', got %s", msg)
	}
}

func TestChatCompletions_MissingMessages(t *testing.T) {
	// Test: POST missing messages returns 400
	body := `{
		"model": "gpt-4"
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "messages") {
		t.Errorf("expected error message to mention 'messages', got %s", msg)
	}
}

func TestChatCompletions_EmptyMessages(t *testing.T) {
	// Test: POST with empty messages array returns 400
	body := `{
		"model": "gpt-4",
		"messages": []
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "messages") {
		t.Errorf("expected error message to mention 'messages', got %s", msg)
	}
}

func TestChatCompletions_MessageMissingRole(t *testing.T) {
	// Test: POST with message missing role returns 400
	body := `{
		"model": "gpt-4",
		"messages": [{"content": "Hello"}]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "role") {
		t.Errorf("expected error message to mention 'role', got %s", msg)
	}
}

func TestChatCompletions_MessageEmptyRole(t *testing.T) {
	// Test: POST with message having empty role returns 400
	body := `{
		"model": "gpt-4",
		"messages": [{"role": "", "content": "Hello"}]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "role") {
		t.Errorf("expected error message to mention 'role', got %s", msg)
	}
}

func TestChatCompletions_MessageMissingContent(t *testing.T) {
	// Test: POST with message missing content returns 400
	body := `{
		"model": "gpt-4",
		"messages": [{"role": "user"}]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "content") {
		t.Errorf("expected error message to mention 'content', got %s", msg)
	}
}

func TestChatCompletions_MessageEmptyContent(t *testing.T) {
	// Test: POST with message having empty content returns 400
	body := `{
		"model": "gpt-4",
		"messages": [{"role": "user", "content": ""}]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "content") {
		t.Errorf("expected error message to mention 'content', got %s", msg)
	}
}

func TestChatCompletions_MethodNotAllowed_GET(t *testing.T) {
	// Test: GET returns 405
	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}

	// Verify Content-Type header
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %T", resp["error"])
	}
	if errObj["type"] != "invalid_request_error" {
		t.Errorf("expected error type 'invalid_request_error', got %v", errObj["type"])
	}
}

func TestChatCompletions_MethodNotAllowed_PUT(t *testing.T) {
	// Test: PUT returns 405
	body := `{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

func TestChatCompletions_MethodNotAllowed_DELETE(t *testing.T) {
	// Test: DELETE returns 405
	req := httptest.NewRequest(http.MethodDelete, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

func TestChatCompletions_MethodNotAllowed_PATCH(t *testing.T) {
	// Test: PATCH returns 405
	req := httptest.NewRequest(http.MethodPatch, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", rec.Code)
	}
}

func TestChatCompletions_MultipleMessages(t *testing.T) {
	// Test: POST with multiple messages passes validation
	// Note: Without provider config, returns 503 (service unavailable)
	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Hello"},
			{"role": "assistant", "content": "Hi there!"},
			{"role": "user", "content": "How are you?"}
		]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	// Valid request without provider returns 503
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", rec.Code)
	}
}

func TestChatCompletions_SecondMessageMissingRole(t *testing.T) {
	// Test: Validation catches errors in non-first messages
	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "First message"},
			{"content": "Second message without role"}
		]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	msg := errObj["message"].(string)
	if !strings.Contains(msg, "index 1") {
		t.Errorf("expected error message to mention 'index 1', got %s", msg)
	}
}

func TestChatCompletions_EmptyBody(t *testing.T) {
	// Test: Empty body returns 400
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestChatCompletions_StreamingReturns501(t *testing.T) {
	// Test: stream: true returns 501 Not Implemented
	body := `{
		"model": "gpt-4",
		"messages": [{"role": "user", "content": "Hello"}],
		"stream": true
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	ChatCompletions(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", rec.Code)
	}

	// Verify Content-Type header
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type 'application/json', got '%s'", contentType)
	}

	// Verify error response
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %T", resp["error"])
	}
	if errObj["message"] != "streaming not implemented yet" {
		t.Errorf("expected streaming error message, got %v", errObj["message"])
	}
	if errObj["type"] != "not_implemented_error" {
		t.Errorf("expected error type 'not_implemented_error', got %v", errObj["type"])
	}
}

// ========================================================================
// Integration Tests with Fake Provider
// ========================================================================

// createTestHandler creates a handler with a fake provider for testing
func createTestHandler(fakeProviderURL string) http.HandlerFunc {
	cfg := &config.Config{
		Port:        "8080",
		Environment: "test",
		Provider: config.ProviderConfig{
			BaseURL: fakeProviderURL,
			APIKey:  "test-api-key-12345678901234567890",
		},
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, cfg)

	return func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
	}
}

func TestChatCompletionsHandler_ForwardsToProvider(t *testing.T) {
	// Create a fake provider that returns a mock completion response
	fakeProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("expected path /v1/chat/completions, got %s", r.URL.Path)
		}

		// Verify Authorization header is set correctly
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-api-key-12345678901234567890" {
			t.Errorf("expected correct Authorization header, got %s", auth)
		}

		// Verify Content-Type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Return a mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-test123",
			"object":  "chat.completion",
			"created": 1677858242,
			"model":   "gpt-4",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "Hello! How can I help you?",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     10,
				"completion_tokens": 8,
				"total_tokens":      18,
			},
		})
	}))
	defer fakeProvider.Close()

	// Create handler with fake provider
	handler := createTestHandler(fakeProvider.URL)

	// Make request
	body := `{
		"model": "gpt-4",
		"messages": [{"role": "user", "content": "Hello!"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Verify response
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["id"] != "chatcmpl-test123" {
		t.Errorf("expected id 'chatcmpl-test123', got %v", resp["id"])
	}
	if resp["object"] != "chat.completion" {
		t.Errorf("expected object 'chat.completion', got %v", resp["object"])
	}
}

func TestChatCompletionsHandler_PreservesProviderStatusCode(t *testing.T) {
	// Test that provider error status codes are passed through
	fakeProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"message": "Rate limit exceeded",
				"type":    "rate_limit_error",
			},
		})
	}))
	defer fakeProvider.Close()

	handler := createTestHandler(fakeProvider.URL)

	body := `{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Verify provider status code is preserved
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", rec.Code)
	}

	// Verify response body is passed through
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["type"] != "rate_limit_error" {
		t.Errorf("expected error type 'rate_limit_error', got %v", errObj["type"])
	}
}

func TestChatCompletionsHandler_DoesNotForwardClientAuth(t *testing.T) {
	// Test that client Authorization header is NOT forwarded
	var receivedAuth string
	fakeProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"id":      "test",
			"object":  "chat.completion",
			"created": 1677858242,
			"model":   "gpt-4",
			"choices": []map[string]any{},
		})
	}))
	defer fakeProvider.Close()

	handler := createTestHandler(fakeProvider.URL)

	body := `{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer client-secret-key-should-not-be-forwarded")
	rec := httptest.NewRecorder()

	handler(rec, req)

	// Verify that the provider received the server's API key, not the client's
	if receivedAuth == "Bearer client-secret-key-should-not-be-forwarded" {
		t.Error("client Authorization header was incorrectly forwarded to provider")
	}
	if receivedAuth != "Bearer test-api-key-12345678901234567890" {
		t.Errorf("expected server API key to be used, got %s", receivedAuth)
	}
}

func TestChatCompletionsHandler_ForwardsXRequestID(t *testing.T) {
	// Test that X-Request-ID is forwarded
	var receivedRequestID string
	fakeProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestID = r.Header.Get("X-Request-ID")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"id":      "test",
			"object":  "chat.completion",
			"created": 1677858242,
			"model":   "gpt-4",
			"choices": []map[string]any{},
		})
	}))
	defer fakeProvider.Close()

	handler := createTestHandler(fakeProvider.URL)

	body := `{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "req-12345")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if receivedRequestID != "req-12345" {
		t.Errorf("expected X-Request-ID 'req-12345', got %s", receivedRequestID)
	}
}

func TestChatCompletionsHandler_PreservesUnknownFields(t *testing.T) {
	// Test that unknown fields in the request are forwarded to the provider
	var receivedBody map[string]any
	fakeProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		json.Unmarshal(bodyBytes, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"id":      "test",
			"object":  "chat.completion",
			"created": 1677858242,
			"model":   "gpt-4",
			"choices": []map[string]any{},
		})
	}))
	defer fakeProvider.Close()

	handler := createTestHandler(fakeProvider.URL)

	// Request includes unknown fields
	body := `{
		"model": "gpt-4",
		"messages": [{"role": "user", "content": "Hello"}],
		"response_format": {"type": "json_object"},
		"seed": 42,
		"custom_field": "custom_value"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	// Verify unknown fields were forwarded
	if receivedBody["custom_field"] != "custom_value" {
		t.Errorf("expected custom_field 'custom_value', got %v", receivedBody["custom_field"])
	}
	if receivedBody["seed"] != float64(42) {
		t.Errorf("expected seed 42, got %v", receivedBody["seed"])
	}
	respFormat, ok := receivedBody["response_format"].(map[string]any)
	if !ok || respFormat["type"] != "json_object" {
		t.Errorf("expected response_format.type 'json_object', got %v", receivedBody["response_format"])
	}
}

func TestChatCompletionsHandler_StreamingReturns501(t *testing.T) {
	// Test that stream: true returns 501 even with a valid provider
	fakeProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("provider should not be called for streaming requests")
	}))
	defer fakeProvider.Close()

	handler := createTestHandler(fakeProvider.URL)

	body := `{
		"model": "gpt-4",
		"messages": [{"role": "user", "content": "Hello"}],
		"stream": true
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("expected status 501, got %d", rec.Code)
	}
}

func TestChatCompletionsHandler_ProviderUnavailable(t *testing.T) {
	// Test that connection failures return 502 Bad Gateway
	// Use a closed server to simulate connection failure
	fakeProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	providerURL := fakeProvider.URL
	fakeProvider.Close() // Close immediately to simulate unavailable provider

	handler := createTestHandler(providerURL)

	body := `{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", rec.Code)
	}

	// Verify error response
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	errObj := resp["error"].(map[string]any)
	if errObj["type"] != "upstream_error" {
		t.Errorf("expected error type 'upstream_error', got %v", errObj["type"])
	}
}

func TestChatCompletionsHandler_PreservesContentType(t *testing.T) {
	// Test that Content-Type from provider is preserved
	fakeProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"test"}`))
	}))
	defer fakeProvider.Close()

	handler := createTestHandler(fakeProvider.URL)

	body := `{"model": "gpt-4", "messages": [{"role": "user", "content": "Hello"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler(rec, req)

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("expected Content-Type 'application/json; charset=utf-8', got '%s'", contentType)
	}
}

func TestBuildUpstreamURL(t *testing.T) {
	tests := []struct {
		baseURL  string
		expected string
	}{
		{"https://api.openai.com", "https://api.openai.com/v1/chat/completions"},
		{"https://api.openai.com/", "https://api.openai.com/v1/chat/completions"},
		{"http://localhost:8080", "http://localhost:8080/v1/chat/completions"},
		{"http://localhost:8080/", "http://localhost:8080/v1/chat/completions"},
	}

	for _, tt := range tests {
		t.Run(tt.baseURL, func(t *testing.T) {
			result := BuildUpstreamURL(tt.baseURL)
			if result != tt.expected {
				t.Errorf("BuildUpstreamURL(%q) = %q, expected %q", tt.baseURL, result, tt.expected)
			}
		})
	}
}

func TestChatCompletionsHandler_ValidationStillWorks(t *testing.T) {
	// Test that validation errors are returned before calling provider
	fakeProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("provider should not be called for invalid requests")
	}))
	defer fakeProvider.Close()

	handler := createTestHandler(fakeProvider.URL)

	tests := []struct {
		name string
		body string
	}{
		{"missing model", `{"messages": [{"role": "user", "content": "Hello"}]}`},
		{"empty model", `{"model": "", "messages": [{"role": "user", "content": "Hello"}]}`},
		{"missing messages", `{"model": "gpt-4"}`},
		{"empty messages", `{"model": "gpt-4", "messages": []}`},
		{"missing role", `{"model": "gpt-4", "messages": [{"content": "Hello"}]}`},
		{"missing content", `{"model": "gpt-4", "messages": [{"role": "user"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected status 400 for %s, got %d", tt.name, rec.Code)
			}
		})
	}
}

// Ensure unused imports are used
var _ = time.Second
