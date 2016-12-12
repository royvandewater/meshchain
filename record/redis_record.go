package record

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
)

type redisRecord struct {
	metadata  *Metadata
	data      io.Reader
	signature string
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

// ToJSON serializes the record and return JSON output
func (record *redisRecord) ToJSON() (string, error) {
	return "", nil
}

// Signature returns the signature provided with
// this copy of the record
func (record *redisRecord) Signature() string {
	return record.signature
}

// Validate verifies that the record is valid.
// In order to be considered valid, the record
// must have at least one valid PublicKey and must
// have a signature from one of the PublicKeys
// it returns nil when there are no errors
func (record *redisRecord) Validate() error {
	publicKeys, err := buildRSAPublicKeys(record.PublicKeys())
	if err != nil {
		return err
	}

	sig := []byte(record.Signature())
	hashed, err := record.hashed()
	if err != nil {
		return fmt.Errorf("Failed to read data: %v", err.Error())
	}

	for _, publicKey := range publicKeys {
		if nil == rsa.VerifyPSS(publicKey, crypto.SHA256, hashed, sig, nil) {
			return nil
		}
	}

	return fmt.Errorf("None of the PublicKeys matches the signature")
}

func (record *redisRecord) hashed() ([]byte, error) {
	// metadata := record.metadata.MarshalBinary()

	data, err := ioutil.ReadAll(record.data)
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(data)
	return hashed[:], nil // [32]byte -> []byte
}
