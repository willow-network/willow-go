package willow

import (
	"errors"
	"testing"
)

func TestWillowErrorBasic(t *testing.T) {
	err := &WillowError{
		Type:    ErrorTypeNetwork,
		Message: "connection failed",
	}

	expected := "network: connection failed"
	if err.Error() != expected {
		t.Errorf("Expected error '%s', got '%s'", expected, err.Error())
	}
}

func TestWillowErrorWithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := &WillowError{
		Type:    ErrorTypeNetwork,
		Message: "connection failed",
		Cause:   cause,
	}

	expected := "network: connection failed: underlying error"
	if err.Error() != expected {
		t.Errorf("Expected error '%s', got '%s'", expected, err.Error())
	}
}

func TestWillowErrorUnwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &WillowError{
		Type:    ErrorTypeNetwork,
		Message: "connection failed",
		Cause:   cause,
	}

	unwrapped := errors.Unwrap(err)
	if unwrapped != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestWillowErrorIs(t *testing.T) {
	err1 := &WillowError{Type: ErrorTypeNetwork, Message: "err1"}
	err2 := &WillowError{Type: ErrorTypeNetwork, Message: "err2"}
	err3 := &WillowError{Type: ErrorTypeHTTP, Message: "err3"}

	if !errors.Is(err1, err2) {
		t.Error("Errors of same type should match")
	}
	if errors.Is(err1, err3) {
		t.Error("Errors of different types should not match")
	}
}

func TestHTTPError(t *testing.T) {
	err := NewHTTPError(404, "not found")

	expected := "HTTP 404: not found"
	if err.Error() != expected {
		t.Errorf("Expected error '%s', got '%s'", expected, err.Error())
	}
	if err.StatusCode != 404 {
		t.Errorf("Expected status code 404, got %d", err.StatusCode)
	}
}

func TestTransactionError(t *testing.T) {
	err := NewTransactionError("failed", "abc123", 5)

	if err.TxHash != "abc123" {
		t.Errorf("Expected TxHash 'abc123', got '%s'", err.TxHash)
	}
	if err.ErrorCode != 5 {
		t.Errorf("Expected ErrorCode 5, got %d", err.ErrorCode)
	}

	expected := "transaction error (code 5, tx abc123): failed"
	if err.Error() != expected {
		t.Errorf("Expected error '%s', got '%s'", expected, err.Error())
	}
}

func TestTransactionErrorNoHash(t *testing.T) {
	err := NewTransactionError("failed", "", 5)

	expected := "transaction error (code 5): failed"
	if err.Error() != expected {
		t.Errorf("Expected error '%s', got '%s'", expected, err.Error())
	}
}

func TestInsufficientFundsError(t *testing.T) {
	err := NewInsufficientFundsError(1000, 500)

	if err.Required != 1000 {
		t.Errorf("Expected Required 1000, got %d", err.Required)
	}
	if err.Available != 500 {
		t.Errorf("Expected Available 500, got %d", err.Available)
	}
}

func TestErrorFactories(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		errType  ErrorType
		contains string
	}{
		{
			name:     "NetworkError",
			err:      NewNetworkError("timeout", nil),
			errType:  ErrorTypeNetwork,
			contains: "timeout",
		},
		{
			name:     "AuthenticationError",
			err:      NewAuthenticationError("invalid token"),
			errType:  ErrorTypeAuthentication,
			contains: "invalid token",
		},
		{
			name:     "ValidationError",
			err:      NewValidationError("invalid input"),
			errType:  ErrorTypeValidation,
			contains: "invalid input",
		},
		{
			name:     "NotFoundError",
			err:      NewNotFoundError("user"),
			errType:  ErrorTypeNotFound,
			contains: "user not found",
		},
		{
			name:     "PermissionDeniedError",
			err:      NewPermissionDeniedError("access denied"),
			errType:  ErrorTypePermissionDenied,
			contains: "access denied",
		},
		{
			name:     "SerializationError",
			err:      NewSerializationError("json failed", nil),
			errType:  ErrorTypeSerialization,
			contains: "json failed",
		},
		{
			name:     "CryptoError",
			err:      NewCryptoError("invalid key", nil),
			errType:  ErrorTypeCrypto,
			contains: "invalid key",
		},
		{
			name:     "ProofError",
			err:      NewProofError("verification failed"),
			errType:  ErrorTypeProof,
			contains: "verification failed",
		},
		{
			name:     "LightClientError",
			err:      NewLightClientError("sync failed", nil),
			errType:  ErrorTypeLightClient,
			contains: "sync failed",
		},
		{
			name:     "ConfigError",
			err:      NewConfigError("invalid config"),
			errType:  ErrorTypeConfig,
			contains: "invalid config",
		},
		{
			name:     "ConsensusError",
			err:      NewConsensusError("consensus failed", nil),
			errType:  ErrorTypeConsensus,
			contains: "consensus failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			we, ok := tt.err.(*WillowError)
			if !ok {
				t.Fatal("Expected *WillowError")
			}
			if we.Type != tt.errType {
				t.Errorf("Expected type %s, got %s", tt.errType, we.Type)
			}
			if we.Message == "" || !containsString(we.Error(), tt.contains) {
				t.Errorf("Error should contain '%s', got '%s'", tt.contains, we.Error())
			}
		})
	}
}

func TestIsNotAuthenticated(t *testing.T) {
	if !IsNotAuthenticated(ErrNotAuthenticated) {
		t.Error("IsNotAuthenticated should return true for ErrNotAuthenticated")
	}
	if IsNotAuthenticated(errors.New("other error")) {
		t.Error("IsNotAuthenticated should return false for other errors")
	}
}

func TestIsNotFound(t *testing.T) {
	err := NewNotFoundError("resource")
	if !IsNotFound(err) {
		t.Error("IsNotFound should return true for not found errors")
	}

	otherErr := NewValidationError("invalid")
	if IsNotFound(otherErr) {
		t.Error("IsNotFound should return false for other error types")
	}
}

func TestIsValidationError(t *testing.T) {
	err := NewValidationError("invalid")
	if !IsValidationError(err) {
		t.Error("IsValidationError should return true for validation errors")
	}

	otherErr := NewNotFoundError("resource")
	if IsValidationError(otherErr) {
		t.Error("IsValidationError should return false for other error types")
	}
}

func TestIsHTTPError(t *testing.T) {
	httpErr := NewHTTPError(500, "internal error")
	statusCode, ok := IsHTTPError(httpErr)
	if !ok {
		t.Error("IsHTTPError should return true for HTTP errors")
	}
	if statusCode != 500 {
		t.Errorf("Expected status code 500, got %d", statusCode)
	}

	otherErr := NewValidationError("invalid")
	_, ok = IsHTTPError(otherErr)
	if ok {
		t.Error("IsHTTPError should return false for non-HTTP errors")
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
