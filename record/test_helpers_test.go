package record_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"github.com/golang/protobuf/proto"
	. "github.com/onsi/gomega"
	"github.com/royvandewater/meshchain/cryptohelpers"
	"github.com/royvandewater/meshchain/record"
	"github.com/royvandewater/meshchain/record/encoding"
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

func generateKeys() (string, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	Expect(err).To(BeNil())

	publicKey := privateKey.Public()
	publicKeyDer, err := x509.MarshalPKIXPublicKey(publicKey)
	Expect(err).To(BeNil())

	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	return publicKeyPem, privateKey
}

func generateSignature(metadata record.Metadata, data []byte, privateKey *rsa.PrivateKey) string {
	metadataProto, err := metadata.Proto()
	Expect(err).To(BeNil())

	bytes, err := proto.Marshal(&encoding.UnsignedRecord{
		Metadata: metadataProto,
		Data:     data,
	})
	Expect(err).To(BeNil())

	hash := sha256.Sum256(bytes)

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash[:], nil)
	Expect(err).To(BeNil())

	return base64.StdEncoding.EncodeToString(signatureBytes)
}

// generateRootRecord creates a new record with public/private key pair.
// it has assertions on all error cases, so it throws if anything goes
// wrong.
func generateRootRecord() (record.RootRecord, string, *rsa.PrivateKey) {
	publicKey, privateKey := generateKeys()

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
