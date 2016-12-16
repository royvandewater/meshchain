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
				var privateKey *rsa.PrivateKey

				publicKey, privateKey, err = generateKeys()
				Expect(err).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey},
				}
				data := []byte(`random data`)

				signature, beforeErr := generateSignature(metadata, data, privateKey)
				Expect(beforeErr).To(BeNil())

				sut, err = record.New(metadata, data, signature)
				Expect(err).To(BeNil())
			})

			It("should create a sut", func() {
				Expect(sut).NotTo(BeNil())
			})
		})

		Describe("When created with no metadata.publicKeys", func() {
			BeforeEach(func() {
				metadata := record.Metadata{
					ID:         "whatevs",
					PublicKeys: []string{},
				}
				data := []byte(`asdf`)
				sut, err = record.New(metadata, data, "")
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("metadata must contain at least one publicKey"))
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

				sut, err = record.New(metadata, data, "shouldn't get this far")
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

				sut, err = record.New(metadata, data, "shoudn't get this far")
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("metadata.ID does not match publicKeys + localName"))
			})
		})

		Describe("When created with an metadata.ID that does not account for the publicKey", func() {
			BeforeEach(func() {
				publicKey, _, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", nil),
					PublicKeys: []string{publicKey},
				}
				data := []byte(`asdf`)

				sut, err = record.New(metadata, data, "shouldn't get this far")
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("metadata.ID does not match publicKeys + localName"))
			})
		})

		Describe("When created with an metadata.ID that does not account for the localID", func() {
			BeforeEach(func() {
				publicKey, _, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					LocalID:    "my-id",
					PublicKeys: []string{publicKey},
				}
				data := []byte(`asdf`)

				sut, err = record.New(metadata, data, "shouldn't get this far")
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("metadata.ID does not match publicKeys + localName"))
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

				signature, beforeErr := generateSignature(metadata, wrongData, privateKey)
				Expect(beforeErr).To(BeNil())

				_, err = record.New(metadata, data, signature)
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("None of the PublicKeys matches the signature"))
			})
		})

		Describe("When created with a valid publicKey, but Signature doesn't match the metadata.publicKeys", func() {
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

				signature, beforeErr := generateSignature(wrongMetadata, data, privateKey)
				Expect(beforeErr).To(BeNil())

				_, err = record.New(metadata, data, signature)
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("None of the PublicKeys matches the signature"))
			})
		})
	})

	Describe("sut.Hash()", func() {
		Describe("two suts with the same metadata", func() {
			var hash1, hash2 []byte

			BeforeEach(func() {
				publicKey, privateKey, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata1 := record.Metadata{
					ID:         generators.ID("name", []string{publicKey}),
					LocalID:    "name",
					PublicKeys: []string{publicKey},
				}
				metadata2 := record.Metadata{
					ID:         generators.ID("name", []string{publicKey}),
					LocalID:    "name",
					PublicKeys: []string{publicKey},
				}

				signature1, beforeErr := generateSignature(metadata1, []byte{}, privateKey)
				Expect(beforeErr).To(BeNil())

				signature2, beforeErr := generateSignature(metadata2, []byte{}, privateKey)
				Expect(beforeErr).To(BeNil())

				sut1, beforeErr := record.New(metadata1, []byte{}, signature1)
				Expect(beforeErr).To(BeNil())

				sut2, beforeErr := record.New(metadata2, []byte{}, signature2)
				Expect(beforeErr).To(BeNil())

				hash1, err = sut1.Hash()
				Expect(err).To(BeNil())

				hash2, err = sut2.Hash()
				Expect(err).To(BeNil())
			})

			It("should have the same hashes", func() {
				Expect(hash1).To(Equal(hash2))
			})
		})

		Describe("two suts with different publicKeys", func() {
			var hash1, hash2 []byte

			BeforeEach(func() {
				publicKey, privateKey, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey},
				}

				signature, beforeErr := generateSignature(metadata, []byte{}, privateKey)
				Expect(beforeErr).To(BeNil())

				sut, beforeErr := record.New(metadata, []byte{}, signature)
				Expect(beforeErr).To(BeNil())

				hash1, err = sut.Hash()
				Expect(err).To(BeNil())
			})

			BeforeEach(func() {
				publicKey, privateKey, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey},
				}

				signature, beforeErr := generateSignature(metadata, []byte{}, privateKey)
				Expect(beforeErr).To(BeNil())

				sut, beforeErr := record.New(metadata, []byte{}, signature)
				Expect(beforeErr).To(BeNil())

				hash2, err = sut.Hash()
				Expect(err).To(BeNil())
			})

			It("should have different hashes", func() {
				Expect(hash1).NotTo(Equal(hash2))
			})
		})

		Describe("two suts with different localNames", func() {
			var hash1, hash2 []byte

			BeforeEach(func() {
				publicKey, privateKey, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata1 := record.Metadata{
					ID:         generators.ID("name-1", []string{publicKey}),
					LocalID:    "name-1",
					PublicKeys: []string{publicKey},
				}
				metadata2 := record.Metadata{
					ID:         generators.ID("name-2", []string{publicKey}),
					LocalID:    "name-2",
					PublicKeys: []string{publicKey},
				}

				signature1, beforeErr := generateSignature(metadata1, []byte{}, privateKey)
				Expect(beforeErr).To(BeNil())

				signature2, beforeErr := generateSignature(metadata2, []byte{}, privateKey)
				Expect(beforeErr).To(BeNil())

				sut1, beforeErr := record.New(metadata1, []byte{}, signature1)
				Expect(beforeErr).To(BeNil())

				sut2, beforeErr := record.New(metadata2, []byte{}, signature2)
				Expect(beforeErr).To(BeNil())

				hash1, err = sut1.Hash()
				Expect(err).To(BeNil())

				hash2, err = sut2.Hash()
				Expect(err).To(BeNil())
			})

			It("should have different hashes", func() {
				Expect(hash1).NotTo(Equal(hash2))
			})
		})
	})

	Describe("sut.SetSignature()", func() {
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

	return string(signatureBytes), nil
}
