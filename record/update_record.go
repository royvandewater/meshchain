package record

// UpdateRecord is a signed update record. In order to be
// constructed, it must have valid metadata. This means
// that there must be at least one publicKey and a valid
// parent record (with verifiably correct ancestry), and
// that the record is signed using a privateKey that matches
// on of the parents' publicKey
type UpdateRecord interface {
}

// NewUpdateRecord instantiates a new update record. Records must
// be valid at time of creation. This means they must have:
//    * At least one publicKey
//    * A parent record
//    * A signature from one of the parents' metadata.PublicKeys
//      that signs a combination of both the metadata and data properties
func NewUpdateRecord(parent Record, metadata Metadata, data []byte, signatureBase64 string) (UpdateRecord, error) {
	return &signedUpdateRecord{}, nil
}

type signedUpdateRecord struct{}
