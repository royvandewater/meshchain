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
		block, _ := pem.Decode([]byte(publicKeyString))
		if block == nil {
			return nil, fmt.Errorf("PublicKey at index '%v' is invalid: failed to parse PEM block containing the public key", i)
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PublicKey at index '%v' is invalid: %v", i, err.Error())
		}

		publicKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PublicKey at index '%v' is of the wrong type. Must be rsa", i)
		}

		publicKeys[i] = publicKey
	}

	return publicKeys, nil
}
