package record_test

import (
	"github.com/royvandewater/meshchain/record"
	"github.com/royvandewater/meshchain/record/generators"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("UpdateRecord", func() {
	var sut record.UpdateRecord
	var err error

	Describe("NewUpdateRecord", func() {
		Describe("When called with valid parameters", func() {
			BeforeEach(func() {
				parent, publicKey, privateKey := generateRootRecord()
				publicKey2, _ := generateKeys()

				metadata := record.Metadata{
					ID:         generators.ID("", []string{publicKey}),
					PublicKeys: []string{publicKey2},
				}
				data := []byte(`data`)

				signature := generateSignature(metadata, data, privateKey)

				sut, err = record.NewUpdateRecord(parent, metadata, data, signature)
			})

			It("should not have an error", func() {
				Expect(err).To(BeNil())
			})

			It("should exist", func() {
				Expect(sut).NotTo(BeNil())
			})
		})
	})
})
