package reqctx

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
)

func TestNewRequestContextPreservesFormBody(t *testing.T) {
	body := "name=alice&comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
	r := httptest.NewRequest("POST", "http://example.test/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rc, err := NewRequestContext(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := rc.Post.Get("name"); got != "alice" {
		t.Fatalf("form name = %q", got)
	}
	forwarded, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(forwarded) != body {
		t.Fatalf("forwarded body = %q, want %q", forwarded, body)
	}
}

func TestNewRequestContextInspectsMultipartFileAndPreservesBody(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="upload"; filename="avatar.jpg.php"`)
	header.Set("Content-Type", "image/jpeg")
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("<?php echo 'blocked'; ?>")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), body.Bytes()...)
	r := httptest.NewRequest("POST", "http://example.test/upload", bytes.NewReader(original))
	r.Header.Set("Content-Type", writer.FormDataContentType())

	rc, err := NewRequestContext(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rc.BodyValues, "\n")
	for _, expected := range []string{`"__jingshield_upload__":true`, `"filename":"avatar.jpg.php"`, `"type_mismatch":true`, "__jingshield_upload_sample__:<?php"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("multipart inspection context missing %q: %s", expected, joined)
		}
	}
	forwarded, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forwarded, original) {
		t.Fatal("multipart request body changed after inspection")
	}
}

func TestNewRequestContextExtractsJSONValuesAndPreservesBody(t *testing.T) {
	body := `{"profile":{"display_name":"<script>alert(1)</script>"}}`
	r := httptest.NewRequest("POST", "http://example.test/api", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")

	rc, err := NewRequestContext(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, value := range rc.AllParamValues() {
		if value == "<script>alert(1)</script>" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("nested JSON string was not exposed to detectors")
	}
	forwarded, _ := io.ReadAll(r.Body)
	if string(forwarded) != body {
		t.Fatalf("forwarded body = %q, want %q", forwarded, body)
	}
}
