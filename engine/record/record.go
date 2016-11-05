package record

import (
	"fmt"
	"io"
)

// Record represents a single stored record
type Record interface {
	// Save persists the record in local storage
	Save() error

	// ToJSON serializes the record and return JSON output
	ToJSON() (string, error)

	// Validate verifies that the record is valid.
	// it returns nil when there are no errors
	Validate() error
}

// NewFromReader parses a new record from a reader
// containing JSON
func NewFromReader(reader io.Reader) (Record, error) {
	return nil, fmt.Errorf("not implemented")
}
