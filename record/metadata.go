package record

import (
	"crypto/x509"

	"github.com/golang/protobuf/proto"
	"github.com/royvandewater/meshchain/record/encoding"
)

// Metadata defines the metadata of a record
type Metadata struct {
	PublicKeys []string
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
	publicKeys, err := metadata.publicKeysAsBytes()
	if err != nil {
		return nil, err
	}

	return &encoding.Metadata{PublicKeys: publicKeys}, nil
}

// publicKeysAsBytes converts the public keys to their raw bytes
func (metadata *Metadata) publicKeysAsBytes() ([][]byte, error) {
	var publicKeyDers [][]byte

	publicKeys, err := buildRSAPublicKeys(metadata.PublicKeys)
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
