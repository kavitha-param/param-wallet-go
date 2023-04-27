package ecies

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type PrivateKey ecdsa.PrivateKey
type PublicKey ecdsa.PublicKey
type Address common.Address
// type SignType byte

// const (
// 	Block SignType = 0
// 	Txn SignType = 1
// )

type NodeSignedTxn struct {
	NodeSignedTxn string `json:"nodeSignedHash"`
	NodeID        string `json:"nodeID"`
}

type SignedTxn struct {
	ID             string `json:"_id"`
	FromSignedHash string `json:"fromSignedHash"`
	From           string `json:"from"`
}
type ParamHDWallet struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	paramID    common.Address
}

func GetParamHDWallet(privateKey *ecdsa.PrivateKey) (*ParamHDWallet, error) {
	if privateKey == nil {
		return nil, errors.New("private key should not be empty")
	}
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("error casting public key to ECDSA")
	}
	paramHDWallet := &ParamHDWallet{}
	paramHDWallet.privateKey = privateKey
	paramHDWallet.publicKey = publicKeyECDSA
	paramHDWallet.paramID = crypto.PubkeyToAddress(*publicKeyECDSA)
	return paramHDWallet, nil
}

func CreateParamWallet() (*ParamHDWallet, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	return GetParamHDWallet(privateKey)
}

func CreateParamHDWalletFromPrivateKey(privateKeyStr string) (*ParamHDWallet, error) {
	if len(privateKeyStr) < 2 {
		return nil, errors.New("invalid private key length")
	}
	if privateKeyStr[:2] == "0x" {
		privateKeyStr = privateKeyStr[2:]
	}
	privateKey, err := crypto.HexToECDSA(privateKeyStr)
	if err != nil {
		return nil, err
	}
	return GetParamHDWallet(privateKey)
}

func (paramHDWallet ParamHDWallet) GetParamID() string {
	return paramHDWallet.paramID.Hex()
}

func (paramHDWallet ParamHDWallet) GetPrivateKey() (*string, error) {
	if paramHDWallet.privateKey == nil {
		return nil, errors.New("private key can not be empty")
	}
	privateKeyBytes := crypto.FromECDSA(paramHDWallet.privateKey)
	privateKeyHex := hexutil.Encode(privateKeyBytes)[2:]
	return &privateKeyHex, nil
}

func (paramHDWallet ParamHDWallet) GetPublicKey() (*string, error) {
	if paramHDWallet.publicKey == nil {
		return nil, errors.New("public key can not be empty")
	}
	publicKeyBytes := crypto.FromECDSAPub(paramHDWallet.publicKey)
	privateKeyHex := hexutil.Encode(publicKeyBytes)[2:]
	return &privateKeyHex, nil
}

//func (ParamHDWallet ParamHDWallet) SignId(Id string) (*string, error) {
//	if Id == "" {
//		log.Errorln("[Wallet]TxnId is empty")
//		return nil, errors.New("ID cannot be empty")
//	}
//	jsonByteID, err := json.Marshal(Id)
//	if err != nil {
//		return nil, err
//	}
//	payloadHash := crypto.Keccak256Hash(jsonByteID)
//	signature, err := crypto.Sign(payloadHash.Bytes(), ParamHDWallet.privateKey)
//	if err != nil {
//		return nil, err
//	}
//	StrId:= hexutil.Encode(signature)
//	return &StrId, nil
//}
func (paramHDWallet ParamHDWallet) Sign(txnInterface interface{}, signType  byte) (map[string]interface{}, error) {
	if signType != 1 && signType != 0 {
		return nil, errors.New("invalid signed type")
	}
	var paramPayload = make(map[string]interface{}, 0)
	paramTxnPoolBytes, err := json.Marshal(txnInterface)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(paramTxnPoolBytes, &paramPayload)
	if err != nil {
		return nil, err
	}
	codeSigner := "from"
	codeSignedHash := "fromSignedHash"
	ID := "_id"
	if signType == 1 {
		codeSignedHash = "nodeSignedHash"
		codeSigner = "nodeID"
	}
	delete(paramPayload, ID)                              //Txn Hash //TBD Vaidee
	delete(paramPayload, codeSignedHash)                  // Node Signed hash,
	jsonBytesWithoutID, err := json.Marshal(paramPayload) //TBD Vaidee Txn Vs Blk!
	if err != nil {
		return nil, err
	}
	payloadHash := crypto.Keccak256Hash(jsonBytesWithoutID)
	signature, err := crypto.Sign(payloadHash.Bytes(), paramHDWallet.privateKey)
	if err != nil {
		return nil, err
	}
	paramPayload[codeSignedHash] = hexutil.Encode(signature)
	signedTxnBytes, err := json.Marshal(paramPayload)
	if err != nil {
		return nil, err
	}
	txnHash := crypto.Keccak256Hash(signedTxnBytes).Hex()
	paramPayload[codeSigner] = paramHDWallet.GetParamID()
	paramPayload[ID] = txnHash

	return paramPayload, nil
}
func IsValidSignature(fromKey, fromSignKey string, data interface{}) error {

	inputTxnBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	var txnMap map[string]interface{}
	err = json.Unmarshal(inputTxnBytes, &txnMap)
	if err != nil {
		return err
	}
	incomingSignature := txnMap[fromSignKey].(string)
	if len(fromSignKey) == 0 || len(incomingSignature) == 0 {
		return errors.New("from map key should not be empty")
	}
	fromAddress := txnMap[fromKey].(string)
	if !common.IsHexAddress(fromAddress) {
		return errors.New("invalid from address")
	}
	originalSignatureBytes, err := hexutil.Decode(incomingSignature)
	if err != nil {
		return err
	}
	delete(txnMap, "fromSignedHash")
	rawBytes, err := json.Marshal(txnMap)
	if err != nil {
		return err
	}
	sigPublicKey, err := crypto.Ecrecover(rawBytes, originalSignatureBytes)
	//pubKey, err := crypto.PubkeyToAddress()UnmarshalPubkey(sigPublicKey)
	//if err != nil {
	//	return err
	//}
	signedAddress := common.BytesToAddress(crypto.Keccak256(sigPublicKey[1:])[12:]).Hex() //crypto.PubkeyToAddress()
	if signedAddress != fromAddress {
		return errors.New("signature miss match")
	}
	return nil
}

//func (paramHDWallet ParamHDWallet) Sign(txnInterface interface{}, signType SignType) (map[string]interface{}, error) {
//	switch txnInterface.(type) {
//	case string:
//		signature, err := crypto.Sign([]byte(txnInterface.(string)), paramHDWallet.privateKey)
//		if err!=nil{
//			return nil,err
//		}
//		break
//	}
//	return paramHDWallet.signMap(signature,signType)
//
//}
//
//func (paramHDWallet ParamHDWallet) signMap(byt []byte, signType SignType) (map[string]interface{}, error) {
//	if signType != Txn && signType != Block {
//		return nil, errors.New("invalid signed type")
//	}
//	var paramPayload = make(map[string]interface{}, 0)
//	paramTxnPoolBytes, err := json.Marshal(txnInterface)
//	if err != nil {
//		return nil, err
//	}
//	err = json.Unmarshal(paramTxnPoolBytes, &paramPayload)
//	if err != nil {
//		return nil, err
//	}
//	codeSigner := "from"
//	codeSignedHash := "fromSignedHash"
//	ID := "_id"
//	if signType == Txn {
//		codeSignedHash = "nodeSignedHash"
//		codeSigner = "nodeID"
//	}
//	delete(paramPayload, ID)                              //Txn Hash //TBD Vaidee
//	delete(paramPayload, codeSignedHash)                  // Node Signed hash,
//	jsonBytesWithoutID, err := json.Marshal(paramPayload) //TBD Vaidee Txn Vs Blk!
//	if err != nil {
//		return nil, err
//	}
//	payloadHash := crypto.Keccak256Hash(jsonBytesWithoutID)
//	signature, err := crypto.Sign(payloadHash.Bytes(), paramHDWallet.privateKey)
//	if err != nil {
//		return nil, err
//	}
//	paramPayload[codeSignedHash] = hexutil.Encode(signature)
//	signedTxnBytes, err := json.Marshal(paramPayload)
//	if err != nil {
//		return nil, err
//	}
//	txnHash := crypto.Keccak256Hash(signedTxnBytes).Hex()
//	paramPayload[codeSigner] = paramHDWallet.GetParamID()
//	paramPayload[ID] = txnHash
//
//	return paramPayload, nil
//}