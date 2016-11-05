package record

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

// Record represents a single stored record
type Record interface {
	// PublicKey return the record's public key. Returns
	// the empty string if the record has no public key.
	PublicKey() string

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
	str, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	data := &Data{}
	err = json.Unmarshal(str, data)
	if err != nil {
		return nil, err
	}
	return &redisRecord{data: data}, nil
}
