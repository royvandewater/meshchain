package record

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func buildRSAPublicKeys(publicKeyStrings []string) ([]*rsa.PublicKey, error) {
	publicKeys := make([]*rsa.PublicKey, len(publicKeyStrings))

	for i, publicKeyString := range publicKeyStrings {
		publicKey, err := buildRSAPublicKey(publicKeyString)
		if err != nil {
			return nil, fmt.Errorf("PublicKey at index '%v' is invalid: %v", i, err.Error())
		}

		publicKeys[i] = publicKey
	}

	return publicKeys, nil
}

func buildRSAPublicKey(publicKeyString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyString))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("publicKey is of the wrong type. Must be rsa")
	}

	return publicKey, nil
}
