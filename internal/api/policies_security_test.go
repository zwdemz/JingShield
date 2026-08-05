package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPolicyImportRejectsNonJSONContentType(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	new(API).policyImport(recorder, request)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnsupportedMediaType)
	}
}

func TestPolicyImportRejectsUnknownTypeMetadata(t *testing.T) {
	body := `{"schema":"jingshield.rules/v1","version":"v1","rules":[],"$type":"System.Diagnostics.Process"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	recorder := httptest.NewRecorder()
	new(API).policyImport(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestPolicyImportRejectsOversizedBody(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", strings.NewReader(strings.Repeat(" ", maxPolicyImportBody+1)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	new(API).policyImport(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}
}
