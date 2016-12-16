package record_test

import (
	"github.com/royvandewater/meshchain/record"
	"github.com/royvandewater/meshchain/record/generators"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("UnsignedRootRecord", func() {
	var sut record.UnsignedRootRecord
	var err error

	Describe("NewUnsignedRootRecord", func() {

	})

	Describe("record.GenerateSignature", func() {

	})

	Describe("record.Hash", func() {
		Describe("two suts with the same metadata", func() {
			var hash1, hash2 []byte

			BeforeEach(func() {
				publicKey, _, beforeErr := generateKeys()
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

				sut1, beforeErr := record.New(metadata1, []byte{})
				Expect(beforeErr).To(BeNil())

				sut2, beforeErr := record.New(metadata2, []byte{})
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
				publicKey, _, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey},
				}
				sut, beforeErr := record.New(metadata, []byte{})
				Expect(beforeErr).To(BeNil())

				hash1, err = sut.Hash()
				Expect(err).To(BeNil())
			})

			BeforeEach(func() {
				publicKey, _, beforeErr := generateKeys()
				Expect(beforeErr).To(BeNil())

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey},
				}
				sut, beforeErr := record.New(metadata, []byte{})
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
				publicKey, _, beforeErr := generateKeys()
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

				sut1, beforeErr := record.New(metadata1, []byte{})
				Expect(beforeErr).To(BeNil())

				sut2, beforeErr := record.New(metadata2, []byte{})
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

	Describe("record.ValidateMetadata", func() {
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

				sut, err = record.NewUnsignedRootRecord(metadata, []byte(data))
			})

			It("should not yield an error", func() {
				Expect(err).To(BeNil())
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
				sut, err = record.NewUnsignedRootRecord(metadata, data)
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
				sut, err = record.NewUnsignedRootRecord(metadata, data)
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
				sut, err = record.NewUnsignedRootRecord(metadata, data)
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
				sut, err = record.NewUnsignedRootRecord(metadata, data)
			})

			It("should yield an error", func() {
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("metadata.ID does not match publicKeys + localName"))
			})
		})
	})
})
