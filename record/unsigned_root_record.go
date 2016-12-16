package record

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/royvandewater/meshchain/record/encoding"
)

// UnsignedRootRecord is a record without a signature. However, in order
// to be constructed, it must have valid metadata. This means
// that there must be at least one publicKey and that the ID is
// a composition of the localID and publicKeys
type UnsignedRootRecord interface {
	// GenerateSignature generates a signature that incorporates
	// the metadata and data of the record
	GenerateSignature(privateKey *rsa.PrivateKey) (string, error)

	// Hash returns the sha256 hash of the record. This incorporates
	// only the Data and Metadata properties, not the signature. This
	// is the portion of the record that must be signed
	Hash() ([]byte, error)
}

// NewUnsignedRootRecord constructs a new instance of an UnsignedRootRecord.
// It must have valid metadata. This means that there must be at least one
// publicKey and that the ID is a composition of the localID and publicKeys.
func NewUnsignedRootRecord(metadata Metadata, data []byte) (UnsignedRootRecord, error) {
	record := &unsignedRootRecord{metadata: metadata, data: data}

	err := record.validateMetadata()
	if err != nil {
		return nil, err
	}

	return record, nil
}

type unsignedRootRecord struct {
	metadata Metadata
	data     []byte
}

func (record *unsignedRootRecord) GenerateSignature(privateKey *rsa.PrivateKey) (string, error) {
	hash, err := record.Hash()
	if err != nil {
		return "", err
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash, nil)
	if err != nil {
		return "", err
	}

	return string(signatureBytes), nil
}

// Hash returns the sha256 hash of the record. This incorporates
// only the Data and Metadata properties, not the signature. This
// is the portion of the record that must be signed
func (record *unsignedRootRecord) Hash() ([]byte, error) {
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

func (record *unsignedRootRecord) validateMetadata() error {
	if len(record.metadata.PublicKeys) == 0 {
		return fmt.Errorf("metadata must contain at least one publicKey")
	}
	if record.metadata.ID == "" {
		return fmt.Errorf("metadata must contain an ID")
	}
	if record.metadata.ID != record.metadata.GenerateID() {
		return fmt.Errorf("metadata.ID does not match publicKeys + localName")
	}
	return nil
}
