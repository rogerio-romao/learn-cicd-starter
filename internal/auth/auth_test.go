package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test case 1: Valid Authorization header
	headers := http.Header{"Authorization": []string{"ApiKey my-api-key"}}
	expectedKey := "my-api-key"
	key, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if key != expectedKey {
		t.Errorf("Expected key: %s, but got: %s", expectedKey, key)
	}

	// Test case 2: Missing Authorization header
	headers = http.Header{}
	expectedErr := ErrNoAuthHeaderIncluded
	_, err = GetAPIKey(headers)
	if err != expectedErr {
		t.Errorf("Expected error: %v, but got: %v", expectedErr, err)
	}

	// Test case 3: Malformed Authorization header
	headers = http.Header{"Authorization": []string{"Bearer token"}}
	expectedErr = errors.New("malformed authorization header")
	_, err = GetAPIKey(headers)
	if err == nil || err.Error() != expectedErr.Error() {
		t.Errorf("Expected error: %v, but got: %v", expectedErr, err)
	}
}