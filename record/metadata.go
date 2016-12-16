package record

import (
	"crypto/x509"

	"github.com/golang/protobuf/proto"
	"github.com/royvandewater/meshchain/cryptohelpers"
	"github.com/royvandewater/meshchain/record/encoding"
	"github.com/royvandewater/meshchain/record/generators"
)

// Metadata defines the metadata of a record
type Metadata struct {
	ID         string
	LocalID    string
	PublicKeys []string
}

// GenerateID returns a deterministic ID that is
// a function of the PublicKeys and LocalID
func (metadata *Metadata) GenerateID() string {
	return generators.ID(metadata.LocalID, metadata.PublicKeys)
}

// MarshalBinary returns the binary representation of Metadata
func (metadata *Metadata) MarshalBinary() ([]byte, error) {
	metadataPB, err := metadata.Proto()
	if err != nil {
		return nil, err
	}

	return proto.Marshal(metadataPB)
}

// Proto returns the protobuf version of this data
func (metadata *Metadata) Proto() (*encoding.Metadata, error) {
	PublicKeys, err := metadata.publicKeysAsBytes()
	if err != nil {
		return nil, err
	}

	return &encoding.Metadata{
		ID:         metadata.ID,
		LocalID:    metadata.LocalID,
		PublicKeys: PublicKeys,
	}, nil
}

// publicKeysAsBytes converts the public keys to their raw bytes
func (metadata *Metadata) publicKeysAsBytes() ([][]byte, error) {
	var publicKeyDers [][]byte

	publicKeys, err := cryptohelpers.BuildRSAPublicKeys(metadata.PublicKeys)
	if err != nil {
		return nil, err
	}

	for _, publicKey := range publicKeys {
		publicKeyDer, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, err
		}

		publicKeyDers = append(publicKeyDers, publicKeyDer)
	}

	return publicKeyDers, nil
}
