package ecies

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/xdg-go/pbkdf2"
)

func FormatPublicKey(publickey string) string {
	if publickey[:2] == "0x" {
		publickey = publickey[2:]
	}
	if len(publickey) == 128 {
		publickey = "04" + publickey
	}
	return publickey
}
func GetSharedKey(privateKey, publicKey string) []byte {
	publicKey = FormatPublicKey(publicKey)
	if len(privateKey) < 2 {
		return nil
	}
	EcdsaPrivateKey, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return nil
	}
	publikeybyte, err := hexutil.Decode("0x" + publicKey)
	if err != nil {
		return nil
	}
	publicKeyECDSA, err := crypto.UnmarshalPubkey(publikeybyte)
	if err != nil {
		return nil
	}
	privkey := ecies.ImportECDSA(EcdsaPrivateKey)
	EciesPublickey := ecies.ImportECDSAPublic(publicKeyECDSA)
	sharedkey, err := privkey.GenerateShared(EciesPublickey, 16, 16)
	if err != nil {
		return nil
	}
	return sharedkey
}

func GenerateRandomStr(num int) (string, error) {
	b := make([]byte, num)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	base := base64.StdEncoding.EncodeToString(b)
	return base, nil
}

func GetSalt(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func Evpkdf(hash func() hash.Hash, password []byte, salt []byte, keysize int, iterations int) []byte {
	hasher := hash()
	derivedKey := []byte{}
	block := []byte{}

	for len(derivedKey) < keysize {
		if len(block) != 0 {
			io.Copy(hasher, bytes.NewBuffer(block))
		}
		io.Copy(hasher, bytes.NewBuffer(password))
		io.Copy(hasher, bytes.NewBuffer(salt))
		block = hasher.Sum(nil)
		hasher.Reset()

		for i := 1; i < iterations; i++ {
			io.Copy(hasher, bytes.NewBuffer(block))
			block = hasher.Sum(nil)
			hasher.Reset()
		}

		derivedKey = append(derivedKey, block...)
	}
	return derivedKey[0:keysize]
}

func GetDigest(sharedKey []byte, randomStr, encryptionVersion string) []byte {
	if encryptionVersion == "1" {
		sharedKey = nil
	}
	fmt.Println("Random string: ", len(randomStr))
	digest := pbkdf2.Key(sharedKey, []byte(randomStr), 2048, 256, sha512.New)
	return digest
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func Pkcs5pad(ciphertext []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...), nil
}
