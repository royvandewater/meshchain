package record

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/royvandewater/meshchain/cryptohelpers"
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

// ToJSON serializes the record and return JSON output
func (record *redisRecord) ToJSON() (string, error) {
	return "", nil
}

// validateSignature validates the signature for this version of the record
func (record *redisRecord) validateSignature() error {
	publicKeys, err := cryptohelpers.BuildRSAPublicKeys(record.metadata.PublicKeys)
	if err != nil {
		return err
	}

	signature := []byte(record.signature)
	hashed, err := record.Hash()
	if err != nil {
		return fmt.Errorf("Failed to generate Hash: %v", err.Error())
	}

	for _, publicKey := range publicKeys {
		if nil == rsa.VerifyPSS(publicKey, crypto.SHA256, hashed, signature, nil) {
			return nil
		}
	}

	return fmt.Errorf("None of the PublicKeys matches the signature")
}
