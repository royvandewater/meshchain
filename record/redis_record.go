package record

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/royvandewater/meshchain/record/encoding"
)

type redisRecord struct {
	metadata  *Metadata
	data      []byte
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

// Hash returns the sha256 hash of the record, minus the signature. This
// is the portion of the record that must be signed
func (record *redisRecord) Hash() ([]byte, error) {
	metadata, err := record.metadata.Proto()
	if err != nil {
		return nil, err
	}

	bytes, err := proto.Marshal(&encoding.Record{
		Metadata: metadata,
		Data:     record.data,
	})
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(bytes)
	return hashed[:], nil // [32]byte -> []byte
}
