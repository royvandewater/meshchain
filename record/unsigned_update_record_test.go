package record_test

import (
	"crypto/rsa"

	"github.com/royvandewater/meshchain/record"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("UnsignedUpdateRecord", func() {
	var sut record.UnsignedUpdateRecord
	var err error
	var parent record.Record

	Describe("NewFromRecord", func() {
		Describe("without parent record", func() {
			Describe("when called", func() {
				BeforeEach(func() {
					metadata := record.Metadata{}
					data := make([]byte, 0)
					sut, err = record.NewUnsignedUpdateRecord(nil, metadata, data)
				})

				It("should return an error", func() {
					Expect(err).NotTo(BeNil())
				})

				It("should not return an instance", func() {
					Expect(sut).To(BeNil())
				})
			})
		})

		Describe("with a parent record", func() {
			BeforeEach(func() {
				parent, _, _ = generateRootRecord()
			})

			Describe("when called", func() {
				BeforeEach(func() {
					metadata := record.Metadata{}
					data := make([]byte, 0)
					sut, err = record.NewUnsignedUpdateRecord(parent, metadata, data)
					Expect(err).To(BeNil())
				})

				It("should return an instance", func() {
					Expect(sut).NotTo(BeNil())
				})
			})
		})
	})

	Describe("record.GenerateSignature", func() {
		var signature string
		var hash []byte
		var publicKey string
		var privateKey *rsa.PrivateKey

		Describe("with a valid record", func() {
			BeforeEach(func() {
				metadata := record.Metadata{}
				data := []byte(`random data`)
				parent, publicKey, privateKey = generateRootRecord()

				sut, err = record.NewUnsignedUpdateRecord(parent, metadata, data)
				Expect(err).To(BeNil())

				hash, err = sut.Hash()
				Expect(err).To(BeNil())
			})

			Describe("when called with a privateKey for a publicKey in the parent", func() {
				BeforeEach(func() {
					signature, err = sut.GenerateSignature(privateKey)
					Expect(err).To(BeNil())
				})

				It("should return a signature", func() {
					Expect(signature).NotTo(BeEmpty())
				})

				It("should be a valid signature for that privateKey", func() {
					Expect(assertSignatureValid(hash, signature, publicKey)).To(BeNil())
				})
			})
		})
	})
})
