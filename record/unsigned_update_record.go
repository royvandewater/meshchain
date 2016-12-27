package record

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/royvandewater/meshchain/record/encoding"
)

// UnsignedUpdateRecord is an update record without a signature.
// However, in order to be constructed, it must have valid metadata.
// This means that there must be at least one publicKey and
// a valid parent record (with verifiably correct ancestry)
type UnsignedUpdateRecord interface {
	// GenerateSignature generates a base64 encoded signature that
	// incorporates the metadata and data of the record, and validates
	// that the private key matches one of the public keys in the parent
	GenerateSignature(privateKey *rsa.PrivateKey) (string, error)

	// Hash returns the sha256 hash of the record. This incorporates
	// only the Data and Metadata properties, not the signature. This
	// is the portion of the record that must be signed
	Hash() ([]byte, error)
}

// NewUnsignedUpdateRecord constructs a new unsigned update record
// with a reference to the given parent record. The parent
// record's ancestry is verified
func NewUnsignedUpdateRecord(parent Record, metadata Metadata, data []byte) (UnsignedUpdateRecord, error) {
	if parent == nil {
		return nil, fmt.Errorf("A valid parent record is required")
	}
	return &unsignedUpdateRecord{metadata: metadata, data: data}, nil
}

type unsignedUpdateRecord struct {
	metadata Metadata
	data     []byte
}

func (record *unsignedUpdateRecord) GenerateSignature(privateKey *rsa.PrivateKey) (string, error) {
	hash, err := record.Hash()
	if err != nil {
		return "", err
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash, nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signatureBytes), nil
}

// Hash returns the sha256 hash of the record. This incorporates
// only the Data and Metadata properties, not the signature. This
// is the portion of the record that must be signed
func (record *unsignedUpdateRecord) Hash() ([]byte, error) {
	metadata, err := record.metadata.Proto()
	if err != nil {
		return nil, err
	}

	bytes, err := proto.Marshal(&encoding.UnsignedRecord{
		Metadata: metadata,
		Data:     record.data,
	})
	if err != nil {
		return nil, err
	}

	hashed := sha256.Sum256(bytes)
	return hashed[:], nil // [32]byte -> []byte
}
