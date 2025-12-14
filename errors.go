package willow

import (
	"errors"
	"fmt"
)

// Error types for the Willow SDK.
var (
	// ErrNotAuthenticated is returned when an operation requires authentication but no session exists.
	ErrNotAuthenticated = errors.New("not authenticated: please authenticate first")

	// ErrSessionExpired is returned when the current session has expired.
	ErrSessionExpired = errors.New("session expired: please re-authenticate")

	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrProofVerificationFailed is returned when proof verification fails.
	ErrProofVerificationFailed = errors.New("proof verification failed")

	// ErrLightClientNotInitialized is returned when light client operations are attempted without initialization.
	ErrLightClientNotInitialized = errors.New("light client not initialized")
)

// WillowError represents an error from the Willow SDK.
type WillowError struct {
	Type    ErrorType
	Message string
	Cause   error
	Details map[string]interface{}
}

// ErrorType categorizes the type of error.
type ErrorType string

const (
	ErrorTypeNetwork          ErrorType = "network"
	ErrorTypeHTTP             ErrorType = "http"
	ErrorTypeAuthentication   ErrorType = "authentication"
	ErrorTypeValidation       ErrorType = "validation"
	ErrorTypeNotFound         ErrorType = "not_found"
	ErrorTypePermissionDenied ErrorType = "permission_denied"
	ErrorTypeSerialization    ErrorType = "serialization"
	ErrorTypeCrypto           ErrorType = "crypto"
	ErrorTypeProof            ErrorType = "proof"
	ErrorTypeLightClient      ErrorType = "light_client"
	ErrorTypeConfig           ErrorType = "config"
	ErrorTypeConsensus        ErrorType = "consensus"
	ErrorTypeTransaction      ErrorType = "transaction"
)

// Error implements the error interface.
func (e *WillowError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the underlying cause of the error.
func (e *WillowError) Unwrap() error {
	return e.Cause
}

// Is checks if the target error matches this error type.
func (e *WillowError) Is(target error) bool {
	if t, ok := target.(*WillowError); ok {
		return e.Type == t.Type
	}
	return false
}

// NewNetworkError creates a new network error.
func NewNetworkError(message string, cause error) *WillowError {
	return &WillowError{
		Type:    ErrorTypeNetwork,
		Message: message,
		Cause:   cause,
	}
}

// HTTPError represents an HTTP error with status code.
type HTTPError struct {
	WillowError
	StatusCode int
}

// NewHTTPError creates a new HTTP error.
func NewHTTPError(statusCode int, message string) *HTTPError {
	return &HTTPError{
		WillowError: WillowError{
			Type:    ErrorTypeHTTP,
			Message: message,
		},
		StatusCode: statusCode,
	}
}

// Error implements the error interface.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// NewAuthenticationError creates a new authentication error.
func NewAuthenticationError(message string) *WillowError {
	return &WillowError{
		Type:    ErrorTypeAuthentication,
		Message: message,
	}
}

// NewValidationError creates a new validation error.
func NewValidationError(message string) *WillowError {
	return &WillowError{
		Type:    ErrorTypeValidation,
		Message: message,
	}
}

// NewNotFoundError creates a new not found error.
func NewNotFoundError(resource string) *WillowError {
	return &WillowError{
		Type:    ErrorTypeNotFound,
		Message: fmt.Sprintf("%s not found", resource),
	}
}

// NewPermissionDeniedError creates a new permission denied error.
func NewPermissionDeniedError(message string) *WillowError {
	return &WillowError{
		Type:    ErrorTypePermissionDenied,
		Message: message,
	}
}

// NewSerializationError creates a new serialization error.
func NewSerializationError(message string, cause error) *WillowError {
	return &WillowError{
		Type:    ErrorTypeSerialization,
		Message: message,
		Cause:   cause,
	}
}

// NewCryptoError creates a new cryptography error.
func NewCryptoError(message string, cause error) *WillowError {
	return &WillowError{
		Type:    ErrorTypeCrypto,
		Message: message,
		Cause:   cause,
	}
}

// NewProofError creates a new proof verification error.
func NewProofError(message string) *WillowError {
	return &WillowError{
		Type:    ErrorTypeProof,
		Message: message,
	}
}

// NewLightClientError creates a new light client error.
func NewLightClientError(message string, cause error) *WillowError {
	return &WillowError{
		Type:    ErrorTypeLightClient,
		Message: message,
		Cause:   cause,
	}
}

// NewConfigError creates a new configuration error.
func NewConfigError(message string) *WillowError {
	return &WillowError{
		Type:    ErrorTypeConfig,
		Message: message,
	}
}

// NewConsensusError creates a new consensus error.
func NewConsensusError(message string, cause error) *WillowError {
	return &WillowError{
		Type:    ErrorTypeConsensus,
		Message: message,
		Cause:   cause,
	}
}

// TransactionError represents a transaction-specific error.
type TransactionError struct {
	WillowError
	TxHash    string
	ErrorCode int
}

// NewTransactionError creates a new transaction error.
func NewTransactionError(message string, txHash string, errorCode int) *TransactionError {
	return &TransactionError{
		WillowError: WillowError{
			Type:    ErrorTypeTransaction,
			Message: message,
		},
		TxHash:    txHash,
		ErrorCode: errorCode,
	}
}

// Error implements the error interface.
func (e *TransactionError) Error() string {
	if e.TxHash != "" {
		return fmt.Sprintf("transaction error (code %d, tx %s): %s", e.ErrorCode, e.TxHash, e.Message)
	}
	return fmt.Sprintf("transaction error (code %d): %s", e.ErrorCode, e.Message)
}

// InsufficientFundsError represents an insufficient funds error.
type InsufficientFundsError struct {
	TransactionError
	Required  uint64
	Available uint64
}

// NewInsufficientFundsError creates a new insufficient funds error.
func NewInsufficientFundsError(required, available uint64) *InsufficientFundsError {
	return &InsufficientFundsError{
		TransactionError: TransactionError{
			WillowError: WillowError{
				Type:    ErrorTypeTransaction,
				Message: fmt.Sprintf("insufficient funds: required %d, available %d", required, available),
			},
		},
		Required:  required,
		Available: available,
	}
}

// IsNotAuthenticated checks if the error is a not authenticated error.
func IsNotAuthenticated(err error) bool {
	return errors.Is(err, ErrNotAuthenticated)
}

// IsSessionExpired checks if the error is a session expired error.
func IsSessionExpired(err error) bool {
	return errors.Is(err, ErrSessionExpired)
}

// IsNotFound checks if the error is a not found error.
func IsNotFound(err error) bool {
	var we *WillowError
	if errors.As(err, &we) {
		return we.Type == ErrorTypeNotFound
	}
	return false
}

// IsValidationError checks if the error is a validation error.
func IsValidationError(err error) bool {
	var we *WillowError
	if errors.As(err, &we) {
		return we.Type == ErrorTypeValidation
	}
	return false
}

// IsHTTPError checks if the error is an HTTP error and returns the status code.
func IsHTTPError(err error) (int, bool) {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.StatusCode, true
	}
	return 0, false
}
