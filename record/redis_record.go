package record

type redisRecord struct {
	data *Data
}

func (record *redisRecord) PublicKey() string {
	return record.data.PublicKey
}

func (record *redisRecord) Save() error {
	return nil
}

func (record *redisRecord) ToJSON() (string, error) {
	return "", nil
}

func (record *redisRecord) Validate() error {
	return nil
}
