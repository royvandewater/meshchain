package record_test

import (
	"crypto"
	"crypto/rsa"

	"github.com/royvandewater/meshchain/cryptohelpers"
)

func assertSignatureValid(hash []byte, signature, publicKeyStr string) error {
	publicKey, err := cryptohelpers.BuildRSAPublicKey(publicKeyStr)
	if err != nil {
		return err
	}

	return rsa.VerifyPSS(publicKey, crypto.SHA256, hash, []byte(signature), nil)
}
