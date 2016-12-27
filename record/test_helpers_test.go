package record_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	. "github.com/onsi/gomega"
	"github.com/royvandewater/meshchain/cryptohelpers"
	"github.com/royvandewater/meshchain/record"
	"github.com/royvandewater/meshchain/record/generators"
)

func assertSignatureValid(hash []byte, signatureBase64, publicKeyStr string) error {
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return err
	}

	publicKey, err := cryptohelpers.BuildRSAPublicKey(publicKeyStr)
	if err != nil {
		return err
	}

	return rsa.VerifyPSS(publicKey, crypto.SHA256, hash, signature, nil)
}

func generateKeys() (string, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return "", nil, err
	}

	publicKey := privateKey.Public()
	publicKeyDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", nil, err
	}

	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	return publicKeyPem, privateKey, nil
}

func generateSignature(metadata record.Metadata, data []byte, privateKey *rsa.PrivateKey) (string, error) {
	rec, err := record.NewUnsignedRootRecord(metadata, data)
	if err != nil {
		return "", err
	}

	hash, err := rec.Hash()
	if err != nil {
		return "", err
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash, nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signatureBytes), nil
}

func generateRootRecord() (record.RootRecord, string, *rsa.PrivateKey) {
	publicKey, privateKey, err := generateKeys()
	Expect(err).To(BeNil())

	metadata := record.Metadata{
		ID:         generators.ID("", []string{publicKey}),
		PublicKeys: []string{publicKey},
	}
	data := []byte(`random data`)

	unsignedParent, err := record.NewUnsignedRootRecord(metadata, data)
	Expect(err).To(BeNil())

	signature, err := unsignedParent.GenerateSignature(privateKey)
	Expect(err).To(BeNil())

	rec, err := record.NewRootRecord(metadata, data, signature)
	Expect(err).To(BeNil())

	return rec, publicKey, privateKey
}
