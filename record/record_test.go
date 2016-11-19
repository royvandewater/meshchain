package record_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/royvandewater/meshchain/record"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Record", func() {
	var sut record.Record

	Describe("New", func() {
		Describe("When given JSON with a publicKey", func() {
			BeforeEach(func() {
				metadata := &record.Metadata{
					PublicKeys: []string{"key"},
					Signature:  "signature",
				}
				data := strings.NewReader(`random data`)

				sut = record.New(metadata, data)
			})

			It("should create a sut", func() {
				Expect(sut).NotTo(BeNil())
			})

			It("should have a publicKey", func() {
				Expect(sut.PublicKeys()).To(ContainElement("key"))
			})

			It("should have a Signature", func() {
				Expect(sut.Signature()).To(Equal("signature"))
			})
		})
	})

	Describe("sut.Validate()", func() {
		Describe("When created with a valid Signature and PublicKey", func() {
			BeforeEach(func() {
				publicKey, signature, err := generateKeyAndSignature()
				Expect(err).To(BeNil())

				metadata := &record.Metadata{
					PublicKeys: []string{publicKey},
					Signature:  signature,
				}
				data := strings.NewReader(``)

				sut = record.New(metadata, data)
			})

			It("should not yield an error", func() {
				err := sut.Validate()
				Expect(err).To(BeNil())
			})
		})
	})
})

func generateKeyAndSignature() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return "", "", err
	}

	publicKey := privateKey.Public()
	publicKeyDer, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyBlock := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))

	hashed := sha256.Sum256([]byte(""))
	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return "", "", err
	}

	signature := string(signatureBytes)
	return publicKeyPem, signature, nil
}
