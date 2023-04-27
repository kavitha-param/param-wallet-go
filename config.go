package ecies

type Account struct {
	ParamID    string `json:"paramID"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

type Payload struct {
	EncrypedString      string `json:"encrypedString"`
	EncryptRandomString string `json:"encryptRandomString"`
	Receiptkey          string `json:"receiptKey"`
	RandomHexString     string `json:"randomHexString"`
}
