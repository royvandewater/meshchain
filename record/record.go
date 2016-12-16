package record

import (
	"encoding/base64"
	"fmt"
)

// Record represents a single stored record
type Record interface {
	// Hash returns the sha256 hash of the record, minus the signature
	Hash() ([]byte, error)

	// JSON serializes the record and return JSON output
	JSON() (string, error)
}

// New instantiates a new record. Records must be valid at time of creation.
// This means they must have:
// * at least one publicKey
// * a metadata.ID, which must be a hash of all publicKeys on the record
//   combined with an optional metadata.localID.
// * A signature from one of the metadata.PublicKeys that signs a combination
//   of both the metadata and data properties
func New(metadata Metadata, data []byte, signatureBase64 string) (Record, error) {
	if _, err := NewUnsignedRootRecord(metadata, data); err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, fmt.Errorf("Failed to base64 decode metadata.signature: %v", err.Error())
	}

	record := &redisRecord{metadata, data, signature}

	if err := record.validateSignature(); err != nil {
		return nil, err
	}

	return record, nil
}
