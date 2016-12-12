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
				}
				data := strings.NewReader(`random data`)

				sut = record.New(metadata, data, "signature")
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
				publicKey, signature, err := generateKeyAndSignature(`asdf`)
				Expect(err).To(BeNil())

				metadata := &record.Metadata{
					PublicKeys: []string{publicKey},
				}
				data := strings.NewReader(`asdf`)

				sut = record.New(metadata, data, signature)
			})

			It("should not yield an error", func() {
				err := sut.Validate()
				Expect(err).To(BeNil())
			})
		})

		Describe("When created with a valid publicKey, but Signature doesn't match the data", func() {
			BeforeEach(func() {
				publicKey, signature, err := generateKeyAndSignature(`asdf`)
				Expect(err).To(BeNil())

				metadata := &record.Metadata{
					PublicKeys: []string{publicKey},
				}
				data := strings.NewReader(`asdfa`)

				sut = record.New(metadata, data, signature)
			})

			It("should yield an error", func() {
				err := sut.Validate()
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("None of the PublicKeys matches the signature"))
			})
		})

		Describe("When created with a valid publicKey, but Signature doesn't match the metadata", func() {
			BeforeEach(func() {
				publicKey, signature, err := generateKeyAndSignature(`asdf`)
				Expect(err).To(BeNil())

				publicKey2, _, err := generatePublicPrivateKeyPair()
				Expect(err).To(BeNil())

				metadata := &record.Metadata{
					PublicKeys: []string{publicKey, publicKey2},
				}
				data := strings.NewReader(`asdf`)

				sut = record.New(metadata, data, signature)
			})

			It("should yield an error", func() {
				err := sut.Validate()
				Expect(err).NotTo(BeNil())
				Expect(err.Error()).To(Equal("None of the PublicKeys matches the signature"))
			})
		})
	})
})

func generatePublicPrivateKeyPair() (string, *rsa.PrivateKey, error) {
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

func generateKeyAndSignature(data string) (string, string, error) {
	publicKeyPem, privateKey, err := generatePublicPrivateKeyPair()
	if err != nil {
		return "", "", err
	}

	hashed := sha256.Sum256([]byte(data))
	signatureBytes, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return "", "", err
	}

	signature := string(signatureBytes)
	return publicKeyPem, signature, nil
}
