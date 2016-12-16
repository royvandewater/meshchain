package record

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

type redisRecord struct {
	metadata  Metadata
	data      []byte
	signature string
}

// Hash returns the sha256 hash of the record. This incorporates
// only the Data and Metadata properties, not the signature. This
// is the portion of the record that must be signed
func (record *redisRecord) Hash() ([]byte, error) {
	unsignedRootRecord, err := NewUnsignedRootRecord(record.metadata, record.data)
	if err != nil {
		return nil, err
	}

	return unsignedRootRecord.Hash()
}

// PublicKeys return the record's public keys. The
// private keys associated with these public keys are
// the only ones allowed to modify this version of the
// record
func (record *redisRecord) PublicKeys() []string {
	return record.metadata.PublicKeys
}

// Save persists the record in local storage
func (record *redisRecord) Save() error {
	return nil
}

// SetSignature sets the signature for this version of the record
// and verifies that the record is valid. In order to be considered
// valid, the record must have at least one valid PublicKey and must
// have a signature from one of the PublicKeys it returns nil when
// there are no errors
func (record *redisRecord) SetSignature(signature string) error {
	publicKeys, err := buildRSAPublicKeys(record.PublicKeys())
	if err != nil {
		return err
	}

	sig := []byte(signature)
	hashed, err := record.Hash()
	if err != nil {
		return fmt.Errorf("Failed to generate Hash: %v", err.Error())
	}

	for _, publicKey := range publicKeys {
		if nil == rsa.VerifyPSS(publicKey, crypto.SHA256, hashed, sig, nil) {
			record.signature = signature
			return nil
		}
	}

	return fmt.Errorf("None of the PublicKeys matches the signature")
}

// Signature returns the signature provided with
// this copy of the record
func (record *redisRecord) Signature() string {
	return record.signature
}

// ToJSON serializes the record and return JSON output
func (record *redisRecord) ToJSON() (string, error) {
	return "", nil
}
