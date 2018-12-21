package creditTesting

import (
	"fmt"
	"math/big"
	"reflect"
	"crypto/ecdsa"
	"github.com/usechain/go-committee/contract/contract"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-committee/shamirkey/msg"
	"github.com/usechain/go-committee/wnode"
	"github.com/usechain/go-committee/shamirkey"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/crypto"
)

const creditAddr = "0xCa29f7b8D73584dBAf97502aC542E3Ab497f7fe9"
const creditABI = "[{\"constant\": true,\"inputs\": [{\"name\": \"\",\"type\": \"address\"}],\"name\": \"DataSet\",\"outputs\": [{\"name\": \"\",\"type\": \"string\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"name\": \"HashList\",\"outputs\": [{\"name\": \"\",\"type\": \"address\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"HashListLength\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"\",\"type\": \"address\"}],\"name\": \"PubkeySet\",\"outputs\": [{\"name\": \"\",\"type\": \"string\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"data\",\"type\": \"string\"},{\"name\": \"pubkey\",\"type\": \"string\"}],\"name\": \"addData\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"}]"

func ScanCreditSystemAccount(usechain *config.Usechain, pool *shamirkey.SharePool, nodelist []string, max int) {
	rpc := usechain.NodeRPC
	coinbase := usechain.UserProfile.Address

	creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)

	// get unconfirmed address number
	res, err := creditCTR.ContractCall(rpc, coinbase, "HashListLength")
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
		res, err := creditCTR.ContractCallParsed(rpc, coinbase,"HashList", big.NewInt(i))
		if err != nil {
			log.Error("read unconfirmed address failed",  "err", err)
			return
		}
		certAddr, ok := (res[0]).(common.Address)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(res[0]))
			return
		}

		// get encrypted string based on address as index
		res, err = creditCTR.ContractCallParsed(rpc, coinbase,"DataSet", certAddr)
		if err != nil {
			log.Error("ContractCallParsed failed", "err", err)
			return
		}
		fmt.Println("DataSet", res)
		et, ok := (res[0]).(string)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(res[1]))
			return
		}
		log.Debug("get a encrypted string", "string", et)

		// get A public key
		res, err = creditCTR.ContractCallParsed(rpc, coinbase,"PubkeySet", certAddr)
		if err != nil {
			log.Error("ContractCallParsed failed", "err", err)
			return
		}
		fmt.Println("PubkeySet", res)
		A, ok := (res[0]).(string)
		if !ok {
			log.Error("It's not ok for", "type", reflect.TypeOf(res[1]))
			return
		}
		log.Debug("get a A public key", "string", A)

		sendPublickeyShared(usechain, nodelist, A, max)
		pool.SaveEncryptedData(A, et)

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
