package coordinator

import (
	"errors"
	"fmt"
	"strings"
)

const maxModelIDBytes = 256

func normalizeModelID(value string) (string, error) {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "", errors.New("model id is required")
	}
	if len(normalized) > maxModelIDBytes {
		return "", fmt.Errorf("model id exceeds %d bytes", maxModelIDBytes)
	}
	if strings.ContainsAny(normalized, "\x00\r\n") {
		return "", errors.New("model id contains control characters")
	}
	return normalized, nil
}

func validatePersistedModelID(value string) error {
	normalized, err := normalizeModelID(value)
	if err != nil {
		return err
	}
	if normalized != value {
		return errors.New("persisted model id must use canonical whitespace")
	}
	return nil
}

func legacyModelIDValidationPlaceholder() string {
	return DefaultModelID
}
