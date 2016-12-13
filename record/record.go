package record

// Record represents a single stored record
type Record interface {
	// Hash returns the sha256 hash of the record, minus the signature
	Hash() ([]byte, error)

	// PublicKeys return the record's public keys. The
	// private keys associated with these public keys are
	// the only ones allowed to modify this version of the
	// record
	PublicKeys() []string

	// Save persists the record in local storage
	Save() error

	// ToJSON serializes the record and return JSON output
	ToJSON() (string, error)

	// SetSignature sets the signature for this version of the record
	// and verifies that the record is valid. In order to be considered
	// valid, the record must have at least one valid PublicKey and must
	// have a signature from one of the PublicKeys it returns nil when
	// there are no errors
	SetSignature(signature string) error

	// Signature returns the signature provided with
	// this version of the record
	Signature() string
}

// New instantiates a new record
func New(metadata *Metadata, data []byte) Record {
	return &redisRecord{metadata: metadata, data: data}
}
