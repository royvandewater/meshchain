package record

import (
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/royvandewater/meshchain/cryptohelpers"
	"github.com/royvandewater/meshchain/record/encoding"
)

// signedRootRecord is a record is verified to
// be correct at construction time, provided it's
// constructed using NewRootRecord.
type signedRootRecord struct {
	metadata  Metadata
	data      []byte
	signature []byte
}

// Hash returns the sha256 hash of the record. This incorporates
// only the Data and Metadata properties, not the signature. This
// is the portion of the record that must be signed
func (record *signedRootRecord) Hash() ([]byte, error) {
	unsignedRootRecord, err := NewUnsignedRootRecord(record.metadata, record.data)
	if err != nil {
		return nil, err
	}

	return unsignedRootRecord.Hash()
}

// JSON serializes the record and return JSON output
func (record *signedRootRecord) JSON() (string, error) {
	hash, err := record.Hash()
	if err != nil {
		return "", err
	}

	metadata, err := record.metadata.Proto()
	if err != nil {
		return "", err
	}

	jsonBytes, err := json.Marshal(&encoding.Record{
		Metadata: metadata,
		Data:     record.data,
		Seal: &encoding.Seal{
			Hash:      hash,
			Signature: record.signature,
		},
	})
	if err != nil {
		return "", nil
	}
	return string(jsonBytes), nil
}

// validateSignature validates the signature for this version of the record
func (record *signedRootRecord) validateSignature() error {
	publicKeys, err := cryptohelpers.BuildRSAPublicKeys(record.metadata.PublicKeys)
	if err != nil {
		return err
	}

	hashed, err := record.Hash()
	if err != nil {
		return fmt.Errorf("Failed to generate Hash: %v", err.Error())
	}

	for _, publicKey := range publicKeys {
		if nil == rsa.VerifyPSS(publicKey, crypto.SHA256, hashed, record.signature, nil) {
			return nil
		}
	}

	return fmt.Errorf("None of the PublicKeys matches the signature")
}
