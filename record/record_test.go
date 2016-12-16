package record_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"

	"github.com/royvandewater/meshchain/cryptohelpers"
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

	Describe("sut.JSON()", func() {
		Describe("with a record", func() {
			var theJSON string
			var metadata record.Metadata
			var signature string

			BeforeEach(func() {
				publicKey, privateKey, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata = record.Metadata{
					ID:         generators.ID("test-object", []string{publicKey}),
					LocalID:    "test-object",
					PublicKeys: []string{publicKey},
				}
				data := []byte(`howdy`)

				signature, err = generateSignature(metadata, data, privateKey)
				Expect(err).To(BeNil())

				sut, err = record.New(metadata, data, signature)
				Expect(err).To(BeNil())

				theJSON, err = sut.JSON()
			})

			Describe("when parsed", func() {
				var parsed struct {
					Metadata struct {
						ID         string   `json:"id"`
						LocalID    string   `json:"localId"`
						PublicKeys []string `json:"publicKeys"`
					} `json:"metadata"`

					Data string `json:"data"`

					Seal struct {
						Hash      string `json:"hash"`
						Signature string `json:"signature"`
					} `json:"seal"`
				}

				BeforeEach(func() {
					itErr := json.Unmarshal([]byte(theJSON), &parsed)
					Expect(itErr).To(BeNil())
				})

				It("should contain the metadata.ID", func() {
					Expect(parsed.Metadata.ID).To(Equal(metadata.ID))
				})

				It("should contain the metadata.LocalID", func() {
					Expect(parsed.Metadata.LocalID).To(Equal("test-object"))
				})

				It("should contain the metadata.PublicKeys, base64 encoded", func() {
					for i, publicKey := range metadata.PublicKeys {
						publicKeyBase64, itErr := cryptohelpers.RSAPublicKeyToBase64(publicKey)
						Expect(itErr).To(BeNil())

						Expect(parsed.Metadata.PublicKeys[i]).To(Equal(publicKeyBase64))
					}
				})

				It("should contain the data, base64 encoded", func() {
					decoded, itErr := base64.StdEncoding.DecodeString(parsed.Data)
					Expect(itErr).To(BeNil())
					Expect(decoded).To(Equal([]byte(`howdy`)))
				})

				It("should contain the seal.Hash", func() {
					hashBytes, itErr := sut.Hash()
					Expect(itErr).To(BeNil())

					hash := base64.StdEncoding.EncodeToString(hashBytes)
					Expect(parsed.Seal.Hash).To(Equal(hash))
				})

				It("should contain the signature", func() {
					Expect(parsed.Seal.Signature).To(Equal(signature))
				})
			})
		})
	})
})
