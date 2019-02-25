package creditNew

import (
	"fmt"
	"math/big"
	"reflect"
	"crypto/ecdsa"
	"github.com/usechain/go-committee/contract/contract"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-committee/wnode"
	"github.com/usechain/go-committee/shamirkey"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/crypto"
	"encoding/json"
	"github.com/usechain/go-committee/shamirkey/msg"
)

const creditAddr = "0x81ac0833c7048c3d2000a738d5ce581f891ea601"
const creditABI = "[{\"constant\": true,\"inputs\": [{\"name\": \"hash\",\"type\": \"bytes32\"}],\"name\": \"getHashData\",\"outputs\": [{\"name\": \"\",\"type\": \"bytes\"},{\"name\": \"\",\"type\": \"bytes\"},{\"name\": \"\",\"type\": \"bool\"},{\"name\": \"\",\"type\": \"string\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"getUnregisterHash\",\"outputs\": [{\"name\": \"\",\"type\": \"bytes32[]\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"addr\",\"type\": \"address\"}],\"name\": \"getUserInfo\",\"outputs\": [{\"name\": \"\",\"type\": \"address\"},{\"name\": \"\",\"type\": \"string\"},{\"name\": \"\",\"type\": \"bytes32\"},{\"name\": \"\",\"type\": \"bytes32[]\"},{\"name\": \"\",\"type\": \"bool[]\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"hashKey\",\"type\": \"bytes32\"},{\"name\": \"_identity\",\"type\": \"bytes\"},{\"name\": \"_issuer\",\"type\": \"bytes\"}],\"name\": \"addNewIdentity\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": true,\"stateMutability\": \"payable\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"account\",\"type\": \"address\"}],\"name\": \"isSigner\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"name\": \"unregister\",\"outputs\": [{\"name\": \"\",\"type\": \"bytes32\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"addr\",\"type\": \"address\"}],\"name\": \"verifyBase\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"addr\",\"type\": \"address\"},{\"name\": \"hash\",\"type\": \"bytes32\"}],\"name\": \"verifyHash\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"addr\",\"type\": \"address\"}],\"name\": \"getBaseData\",\"outputs\": [{\"name\": \"\",\"type\": \"bytes32\"},{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"getUnregisterLen\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [],\"name\": \"renounceSigner\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"account\",\"type\": \"address\"}],\"name\": \"addSigner\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"_publicKey\",\"type\": \"string\"},{\"name\": \"_hashKey\",\"type\": \"bytes32\"},{\"name\": \"_identity\",\"type\": \"bytes\"},{\"name\": \"_issuer\",\"type\": \"bytes\"}],\"name\": \"register\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": true,\"stateMutability\": \"payable\",\"type\": \"function\"},{\"anonymous\": false,\"inputs\": [{\"indexed\": true,\"name\": \"addr\",\"type\": \"address\"},{\"indexed\": true,\"name\": \"hash\",\"type\": \"bytes32\"}],\"name\": \"NewUserRegister\",\"type\": \"event\"},{\"anonymous\": false,\"inputs\": [{\"indexed\": true,\"name\": \"addr\",\"type\": \"address\"},{\"indexed\": true,\"name\": \"hash\",\"type\": \"bytes32\"}],\"name\": \"NewIdentity\",\"type\": \"event\"},{\"anonymous\": false,\"inputs\": [{\"indexed\": true,\"name\": \"account\",\"type\": \"address\"}],\"name\": \"SignerAdded\",\"type\": \"event\"},{\"anonymous\": false,\"inputs\": [{\"indexed\": true,\"name\": \"account\",\"type\": \"address\"}],\"name\": \"SignerRemoved\",\"type\": \"event\"}]"

//The struct of the identity
type identityInfo struct {
	Data 		string 		`json:"data"`
	Nation		string		`json:"nation"`
	Entity 	    string		`json:"entity"`
	Fpr 		string		`json:"fpr"`
	Alg			string		`json:"alg"`
	Certtype	string 		`json:"certtype"`
	Ver			string 		`json:"ver"`
	Cdate		string		`json:"cdate"`
}

func ScanCreditSystemAccount(usechain *config.Usechain, pool *shamirkey.SharePool, nodelist []string, max int) {
	rpc := usechain.NodeRPC
	coinbase := usechain.UserProfile.Address

	creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)

	// get unconfirmed address number
	res, err := creditCTR.ContractCall(rpc, coinbase, "getUnregisterLen")
	fmt.Println("res", res)
	if err != nil {
		log.Error("contract call", "err", err)
		return
	}
	if res == contract.ContractZero || res == contract.ContractNull{
		return
	}

	unconfirmedCount, _ := big.NewInt(0).SetString(res[2:], 16)
	//log.Debug("unconfirmedcount", "count", unconfirmedCount)
	for i := int64(0); i < unconfirmedCount.Int64(); i++ {
		// get unconfirmed address index
		res, err := creditCTR.ContractCallParsed(rpc, coinbase,"unregister", big.NewInt(i))
		if err != nil {
			log.Error("read unconfirmed address failed",  "err", err)
			return
		}
		certHash, ok := (res[0]).([32]uint8)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(res[0]))
			return
		}

		// get encrypted string based on address as index
		res, err = creditCTR.ContractCallParsed(rpc, coinbase,"getHashData", certHash)
		if err != nil {
			log.Error("ContractCallParsed failed", "err", err)
			return
		}
		// read identity info
		identity, ok := (res[0]).([]byte)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(res[0]))
			return
		}
		log.Debug("get identity string", "string", string(identity))

		m := identityInfo{}
		err = json.Unmarshal([]byte(identity), &m)
		if err != nil{
			log.Debug("Unmarshal failed")
			return
		}
		fmt.Println("m", m)
		// read requestor's public key
		pubkey, ok := (res[3]).(string)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(res[4]))
			return
		}
		log.Debug("get public key", "key", string(pubkey))

		sendPublickeyShared(usechain, nodelist, string(pubkey), max)
		pool.SaveEncryptedData(pubkey, m.Data)

		//issuer, ok := (res[1]).([]byte)
		//if !ok {
		//	log.Error("It's not ok for", "type", reflect.TypeOf(res[1]))
		//	return
		//}
		//log.Debug("get issuer string", "string", string(issuer))


		break
	}
}

func sendPublickeyShared(usechain *config.Usechain, nodelist []string, A string, max int) {
	priv := sssa.ExtractPrivateShare(usechain.UserProfile.PrivShares)	//bs
	if priv == nil {
		log.Error("No valid private share")
		return
	}
	publicA := crypto.ToECDSAPub(common.FromHex(A))		//A

	pubkey := new(ecdsa.PublicKey)
	pubkey.X, pubkey.Y = crypto.S256().ScalarMult(publicA.X, publicA.Y, priv.D.Bytes())   //bsA=[bs]B
	pubkey.Curve = crypto.S256()

	m := msg.PackVerifyShare(A, pubkey, usechain.UserProfile.CommitteeID)

	for _, id := range shamirkey.AccountVerifier(A, max) {
		wnode.SendMsg(m, crypto.ToECDSAPub(common.FromHex(nodelist[id])))
	}
}
