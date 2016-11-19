package record

import "io"

// Record represents a single stored record
type Record interface {
	// PublicKeys return the record's public keys. The
	// private keys associated with these public keys are
	// the only ones allowed to modify this version of the
	// record
	PublicKeys() []string

	// Save persists the record in local storage
	Save() error

	// ToJSON serializes the record and return JSON output
	ToJSON() (string, error)

	// Signature returns the signature provided with
	// this copy of the record
	Signature() string

	// Validate verifies that the record is valid.
	// In order to be considered valid, the record
	// must have at least one valid PublicKey and must
	// have a signature from one of the PublicKeys
	// it returns nil when there are no errors
	Validate() error
}

// New instantiates a new record
func New(metadata *Metadata, data io.Reader) Record {
	return &redisRecord{metadata: metadata, data: data}
}
