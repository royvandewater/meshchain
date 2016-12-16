package record

// Record represents a single stored record
type Record interface {
	// Hash returns the sha256 hash of the record, minus the signature
	Hash() ([]byte, error)

	// ToJSON serializes the record and return JSON output
	ToJSON() (string, error)
}

// New instantiates a new record. Records must be valid at time of creation.
// This means they must have:
// * at least one publicKey
// * a metadata.ID, which must be a hash of all publicKeys on the record
//   combined with an optional metadata.localID.
// * A signature from one of the metadata.PublicKeys that signs a combination
//   of both the metadata and data properties
func New(metadata Metadata, data []byte, signature string) (Record, error) {
	if _, err := NewUnsignedRootRecord(metadata, data); err != nil {
		return nil, err
	}

	record := &redisRecord{metadata, data, signature}

	if err := record.validateSignature(); err != nil {
		return nil, err
	}

	return record, nil
}
