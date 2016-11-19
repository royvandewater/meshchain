package record_test

import (
	"strings"

	"github.com/royvandewater/meshchain/engine/record"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Record", func() {
	var sut record.Record
	var err error

	Describe("NewFromReader", func() {
		Describe("When given JSON with a publicKey", func() {
			BeforeEach(func() {
				reader := strings.NewReader(`{
					"publicKey": "key"
				}`)

				sut, err = record.NewFromReader(reader)
			})

			It("should not error", func() {
				Expect(err).To(BeNil())
			})

			It("should create a sut", func() {
				Expect(sut).NotTo(BeNil())
			})

			It("should have a publicKey", func() {
				Expect(sut.PublicKey()).To(Equal("key"))
			})
		})
	})
})
