package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

var openSSLSaltHeader string = "Salted__"
var saltsize int = 8

func GenerateCipherText(receiverpublickey string, payloadlen int, account Account) string {
	len := hexutil.EncodeBig(big.NewInt(int64(payloadlen)))
	len = len[2:]
	return account.PublicKey[2:] + "1" + len + receiverpublickey
}

func PayloadEncrypt(senderPrivateKey, payload string, receiverpublickey string) (string, error) {
	if receiverpublickey == "" || senderPrivateKey == "" {
		return "", errors.New("receiver/private  key is empty")
	}

	paramHDWallet, err := CreateParamHDWalletFromPrivateKey(senderPrivateKey)
	if err != nil {
		return "", err
	}

	senderPublicKey, err := paramHDWallet.GetPublicKey()
	if err != nil {
		return "", err
	}
	sharedkey := GetSharedKey(senderPrivateKey, "04"+receiverpublickey)

	randomstr, err := GenerateRandomStr(384)
	if err != nil {
		return "", err
	}
	encryptrandomstr, err := AesEncrypt(randomstr, sharedkey)

	if err != nil {
		return "", err
	}
	encryptionversion := "1"
	receiptkey := GetDigest(sharedkey, randomstr, encryptionversion)
	ciphertext, err := AesEncrypt(payload, receiptkey)

	if err != nil {
		return "", err
	}

	encryptedstrlen := len(encryptrandomstr)
	len := hexutil.EncodeBig(big.NewInt(int64(encryptedstrlen)))
	len = len[2:]
	senderNonPadPublicKey := *senderPublicKey

	payloadObj := Payload{}
	payloadObj.EncrypedString = senderNonPadPublicKey + encryptionversion + len + encryptrandomstr + ciphertext + receiverpublickey
	payloadObj.EncryptRandomString = encryptrandomstr
	payloadObj.Receiptkey = hexutil.Encode(receiptkey)[2:]
	payloadObj.RandomHexString = randomstr
	jsonBytes, err := json.Marshal(payloadObj)

	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func AesEncrypt(plaintext string, passphrase []byte) (string, error) {
	pass := hexutil.Encode(passphrase)
	pass = pass[2:]
	salt, err := GetSalt(saltsize)
	if err != nil {
		return "", err
	}
	superkey := Evpkdf(md5.New, []byte(pass), []byte(salt), 48, 1)
	key := superkey[:32]
	iv := superkey[32:]
	padtext, err := Pkcs5pad([]byte(plaintext), aes.BlockSize)
	if err != nil {
		return "", err
	}
	pdtext := string(padtext)
	plaintext = pdtext
	ciphertext := make([]byte, len(plaintext))
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, []byte(plaintext))
	cipherText := []byte(openSSLSaltHeader)
	cipherText = append(cipherText, salt...)
	cipherText = append(cipherText, ciphertext...)
	//openSSLSaltHeader + string(salt) + string(ciphertext)
	base := base64.StdEncoding.EncodeToString(cipherText)
	return base, nil
}
