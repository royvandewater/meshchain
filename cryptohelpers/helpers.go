package cryptohelpers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// BuildRSAPublicKeys generates rsa.PublicKey instances for an array of strings
// representing RSA public keys in pem format
func BuildRSAPublicKeys(publicKeyStrings []string) ([]*rsa.PublicKey, error) {
	publicKeys := make([]*rsa.PublicKey, len(publicKeyStrings))

	for i, publicKeyString := range publicKeyStrings {
		publicKey, err := BuildRSAPublicKey(publicKeyString)
		if err != nil {
			return nil, fmt.Errorf("PublicKey at index '%v' is invalid: %v", i, err.Error())
		}

		publicKeys[i] = publicKey
	}

	return publicKeys, nil
}

// BuildRSAPublicKey generates an rsa.PublicKey instance for a string
// representing an RSA public key in pem format
func BuildRSAPublicKey(publicKeyString string) (*rsa.PublicKey, error) {
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

// RSAPublicKeyToBase64 converts a publicKey given in RSA pem
// format and converts it to base64
func RSAPublicKeyToBase64(publicKeyStr string) (string, error) {
	publicKey, err := BuildRSAPublicKey(publicKeyStr)
	if err != nil {
		return "", err
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(publicKeyDer)
	return encoded, nil
}
