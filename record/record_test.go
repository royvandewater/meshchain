package record_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/royvandewater/meshchain/record"
	"github.com/royvandewater/meshchain/record/generators"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Record", func() {
	var sut record.Record
	var err error

	Describe("New", func() {
		Describe("When given Metadata with an ID and a publicKey", func() {
			var publicKey string

			BeforeEach(func() {
				publicKey, _, err = generateKeys()
				Expect(err).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey},
				}
				data := []byte(`random data`)

				sut, err = record.New(metadata, []byte(data))
				Expect(err).To(BeNil())
			})

			It("should not yield an error", func() {
				Expect(err).To(BeNil())
			})

			It("should create a sut", func() {
				Expect(sut).NotTo(BeNil())
			})

			It("should have a publicKey", func() {
				Expect(sut.PublicKeys()).To(ContainElement(publicKey))
			})

			It("should not have a Signature", func() {
				Expect(sut.Signature()).To(Equal(""))
			})
		})

		Describe("When created with no metadata.ID", func() {
			BeforeEach(func() {
				publicKey, _, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         "",
					PublicKeys: []string{publicKey},
				}
				data := []byte(`asdf`)
				sut, err = record.New(metadata, data)
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("metadata must contain an ID"))
			})
		})

		Describe("When created with an invalid metadata.ID", func() {
			BeforeEach(func() {
				publicKey, _, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         "invalid",
					PublicKeys: []string{publicKey},
				}
				data := []byte(`asdf`)
				sut, err = record.New(metadata, data)
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("metadata.ID does not match publicKeys + localName"))
			})
		})
	})

	Describe("sut.SetSignature()", func() {
		Describe("When created with a valid Signature and PublicKey", func() {
			BeforeEach(func() {
				publicKey, privateKey, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey},
				}
				data := []byte(`asdf`)
				sut, beforeErr = record.New(metadata, data)
				Expect(beforeErr).To(BeNil())

				signature, beforeErr := generateSignature(sut, privateKey)
				Expect(beforeErr).To(BeNil())
				err = sut.SetSignature(signature)
			})

			It("should not yield an error", func() {
				Expect(err).To(BeNil())
			})
		})

		Describe("When created with a valid publicKey, but Signature doesn't match the data", func() {
			BeforeEach(func() {
				publicKey, privateKey, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey},
				}
				data := []byte(`asdf`)
				wrongData := []byte(`wrong`)

				badRecord, beforeErr := record.New(metadata, wrongData)
				Expect(beforeErr).To(BeNil())
				signature, beforeErr := generateSignature(badRecord, privateKey)
				Expect(beforeErr).To(BeNil())

				sut, beforeErr = record.New(metadata, data)
				Expect(beforeErr).To(BeNil())
				err = sut.SetSignature(signature)
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("None of the PublicKeys matches the signature"))
			})
		})

		Describe("When created with a valid publicKey, but Signature doesn't match the metadata", func() {
			BeforeEach(func() {
				publicKey, privateKey, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				publicKey2, _, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey},
				}
				data := []byte(`asdf`)

				wrongMetadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey, publicKey2}),
					PublicKeys: []string{publicKey, publicKey2},
				}

				badRecord, beforeErr := record.New(wrongMetadata, data)
				Expect(beforeErr).To(BeNil())
				signature, beforeErr := generateSignature(badRecord, privateKey)
				Expect(beforeErr).To(BeNil())

				sut, beforeErr = record.New(metadata, data)
				Expect(beforeErr).To(BeNil())
				err = sut.SetSignature(signature)
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("None of the PublicKeys matches the signature"))
			})
		})
	})
})

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

func generateSignature(rec record.Record, privateKey *rsa.PrivateKey) (string, error) {
	hash, err := rec.Hash()
	if err != nil {
		return "", err
	}

	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash, nil)
	if err != nil {
		return "", err
	}

	return string(signatureBytes), nil
}
