package record

type redisRecord struct {
	data *Data
}

// PublicKey return the record's public key. Returns
// the empty string if the record has no public key.
func (record *redisRecord) PublicKey() string {
	return record.data.PublicKey
}

// Save persists the record in local storage
func (record *redisRecord) Save() error {
	return nil
}

// ToJSON serializes the record and return JSON output
func (record *redisRecord) ToJSON() (string, error) {
	return "", nil
}

// Validate verifies that the record is valid.
// it returns nil when there are no errors
func (record *redisRecord) Validate() error {
	return nil
}
