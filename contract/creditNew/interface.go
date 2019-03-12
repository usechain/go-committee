package creditNew

import (
	"math/big"
	"reflect"
	"crypto/ecdsa"
	"github.com/usechain/go-committee/contract/contract"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-committee/shamirkey/core"
	"github.com/usechain/go-committee/shamirkey/verify"
	"github.com/usechain/go-committee/wnode"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/crypto"
	"encoding/json"
	"github.com/usechain/go-committee/shamirkey/msg"
	"github.com/usechain/go-usechain/common/hexutil"
	"fmt"
)

//const creditAddr = "0x2398C03dE997b104116B57bfF1eEDC37a9ef7965"
//const creditABI = "[{\"constant\": true,\"inputs\": [{\"name\": \"addr\",\"type\": \"address\"}],\"name\": \"getBaseData\",\"outputs\": [{\"name\": \"\",\"type\": \"bytes32\"},{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"hash\",\"type\": \"bytes32\"}],\"name\": \"getHashData\",\"outputs\": [{\"name\": \"\",\"type\": \"bytes\"},{\"name\": \"\",\"type\": \"bytes\"},{\"name\": \"\",\"type\": \"bool\"},{\"name\": \"\",\"type\": \"string\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"getUnregisterHash\",\"outputs\": [{\"name\": \"\",\"type\": \"bytes32[]\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [],\"name\": \"getUnregisterLen\",\"outputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"addr\",\"type\": \"address\"}],\"name\": \"getUserInfo\",\"outputs\": [{\"name\": \"\",\"type\": \"address\"},{\"name\": \"\",\"type\": \"string\"},{\"name\": \"\",\"type\": \"bytes32\"},{\"name\": \"\",\"type\": \"bytes32[]\"},{\"name\": \"\",\"type\": \"bool[]\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"account\",\"type\": \"address\"}],\"name\": \"isSigner\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": true,\"inputs\": [{\"name\": \"\",\"type\": \"uint256\"}],\"name\": \"unregister\",\"outputs\": [{\"name\": \"\",\"type\": \"bytes32\"}],\"payable\": false,\"stateMutability\": \"view\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"addr\",\"type\": \"address\"},{\"name\": \"hash\",\"type\": \"bytes32\"}],\"name\": \"verifyHash\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"addr\",\"type\": \"address\"}],\"name\": \"verifyBase\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [],\"name\": \"renounceSigner\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"_publicKey\",\"type\": \"string\"},{\"name\": \"_hashKey\",\"type\": \"bytes32\"},{\"name\": \"_identity\",\"type\": \"bytes\"},{\"name\": \"_issuer\",\"type\": \"bytes\"}],\"name\": \"register\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": true,\"stateMutability\": \"payable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"account\",\"type\": \"address\"}],\"name\": \"addSigner\",\"outputs\": [],\"payable\": false,\"stateMutability\": \"nonpayable\",\"type\": \"function\"},{\"constant\": false,\"inputs\": [{\"name\": \"hashKey\",\"type\": \"bytes32\"},{\"name\": \"_identity\",\"type\": \"bytes\"},{\"name\": \"_issuer\",\"type\": \"bytes\"}],\"name\": \"addNewIdentity\",\"outputs\": [{\"name\": \"\",\"type\": \"bool\"}],\"payable\": true,\"stateMutability\": \"payable\",\"type\": \"function\"},{\"anonymous\": false,\"inputs\": [{\"indexed\": true,\"name\": \"account\",\"type\": \"address\"}],\"name\": \"SignerRemoved\",\"type\": \"event\"},{\"anonymous\": false,\"inputs\": [{\"indexed\": true,\"name\": \"account\",\"type\": \"address\"}],\"name\": \"SignerAdded\",\"type\": \"event\"},{\"anonymous\": false,\"inputs\": [{\"indexed\": true,\"name\": \"addr\",\"type\": \"address\"},{\"indexed\": true,\"name\": \"hash\",\"type\": \"bytes32\"}],\"name\": \"NewUserRegister\",\"type\": \"event\"},{\"anonymous\": false,\"inputs\": [{\"indexed\": true,\"name\": \"addr\",\"type\": \"address\"},{\"indexed\": true,\"name\": \"hash\",\"type\": \"bytes32\"}],\"name\": \"NewIdentity\",\"type\": \"event\"}]"
const creditAddr = "0xfffffffffffffffffffffffffffffffff0000001"
const creditABI = "[{\"constant\":true,\"inputs\":[],\"name\":\"unConfirmedAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"isCommittee\",\"outputs\":[{\"name\":\"added\",\"type\":\"bool\"},{\"name\":\"execution\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"contractVersion\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"contractName\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"CommitteePublicKey\",\"outputs\":[{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"confirmedSubAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"confirmedMainAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"confirmedMainAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"MAX_COMMITTEEMAN_COUNT\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_addr\",\"type\":\"address\"}],\"name\":\"checkOneTimeAddrAdded\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"requirement\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_addr\",\"type\":\"address\"}],\"name\":\"checkAddrConfirmed\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"},{\"name\":\"\",\"type\":\"address\"}],\"name\":\"CommitteeConfirmations\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"unConfirmedAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"CertificateAddr\",\"outputs\":[{\"name\":\"added\",\"type\":\"bool\"},{\"name\":\"confirmed\",\"type\":\"bool\"},{\"name\":\"addressType\",\"type\":\"uint8\"},{\"name\":\"ringSig\",\"type\":\"string\"},{\"name\":\"pubSKey\",\"type\":\"string\"},{\"name\":\"publicKeyMirror\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"OneTimeAddr\",\"outputs\":[{\"name\":\"confirmed\",\"type\":\"bool\"},{\"name\":\"caSign\",\"type\":\"string\"},{\"name\":\"certMsg\",\"type\":\"string\"},{\"name\":\"pubKey\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"CertToAddress\",\"outputs\":[{\"name\":\"confirmed\",\"type\":\"bool\"},{\"name\":\"toAddress\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"OneTimeAddrConfirmed\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"CMMTTEEs\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"OneTimeAddrConfirmedLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"confirmedSubAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"certIDCount\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"Committeeman\",\"type\":\"address\"}],\"name\":\"CommitteemanAddition\",\"type\":\"event\"},{\"inputs\":[{\"name\":\"_createrPubKey\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"constant\":false,\"inputs\":[{\"name\":\"_newPending\",\"type\":\"address\"}],\"name\":\"removeCommittee\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"sender\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"submitIndex\",\"type\":\"uint256\"},{\"indexed\":true,\"name\":\"added\",\"type\":\"bool\"}],\"name\":\"Submission\",\"type\":\"event\"},{\"constant\":false,\"inputs\":[{\"name\":\"_certID\",\"type\":\"uint256\"},{\"name\":\"_confirm\",\"type\":\"bool\"}],\"name\":\"confirmCert\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_addressType\",\"type\":\"uint8\"},{\"name\":\"_ringSig\",\"type\":\"string\"},{\"name\":\"_pub_S_Key\",\"type\":\"string\"},{\"name\":\"_publicKeyMirror\",\"type\":\"string\"}],\"name\":\"summitCert\",\"outputs\":[{\"name\":\"_certID\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_ringSig\",\"type\":\"string\"},{\"name\":\"_pub_S_Key\",\"type\":\"string\"},{\"name\":\"_publicKeyMirror\",\"type\":\"string\"}],\"name\":\"storeSubUserCert\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"},{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_pubkey\",\"type\":\"string\"},{\"name\":\"_sign\",\"type\":\"string\"},{\"name\":\"_CA\",\"type\":\"string\"}],\"name\":\"storeOneTimeAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_ringSig\",\"type\":\"string\"},{\"name\":\"_pub_S_Key\",\"type\":\"string\"},{\"name\":\"_publicKeyMirror\",\"type\":\"string\"}],\"name\":\"storeMainUserCert\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"},{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"submitIndex\",\"type\":\"uint256\"}],\"name\":\"ExecutionFailure\",\"type\":\"event\"},{\"constant\":false,\"inputs\":[{\"name\":\"_newPending\",\"type\":\"address\"},{\"name\":\"_publicKey\",\"type\":\"string\"}],\"name\":\"addCommittee\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"Committeeman\",\"type\":\"address\"}],\"name\":\"CommitteemanRemoval\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"confirmed\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"submitIndex\",\"type\":\"uint256\"},{\"indexed\":true,\"name\":\"added\",\"type\":\"bool\"}],\"name\":\"Confirmation\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"submitIndex\",\"type\":\"uint256\"}],\"name\":\"Execution\",\"type\":\"event\"}]"

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

func ScanCreditSystemAccount(usechain *config.Usechain, pool *core.SharePool, nodelist []string, max int) {

	processScan := func() {
		rpc := usechain.NodeRPC
		coinbase := usechain.UserProfile.Address

		creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)

		// get unconfirmed address number
		UnregisterLen, err := creditCTR.ContractCall(rpc, coinbase, "getUnregisterLen")
		log.Info("Read contract UnregisterLen", "length", UnregisterLen)
		if err != nil {
			log.Error("contract call", "err", err)
			return
		}

		if UnregisterLen == contract.ContractZero || UnregisterLen == contract.ContractNull{
			return
		}

		unconfirmedCount, _ := big.NewInt(0).SetString(UnregisterLen[2:], 16)
		log.Info("Get unconfirmed register count", "count", unconfirmedCount)

		certHashAddtoSet := NewSet()
		
		for i := int64(0); i < unconfirmedCount.Int64(); i++ {
			// get unconfirmed address index
			unregister, err := creditCTR.ContractCallParsed(rpc, coinbase, "unregister", big.NewInt(i))
			if err != nil && len(unregister) == 0 {
				log.Error("Read unconfirmed address failed", "err", err)
				return
			}
			certHash, ok := (unregister[0]).([32]uint8)
			if !ok {
				log.Error("It's not ok for", "type", reflect.TypeOf(unregister[0]))
				return
			}

			certHashToString := string(certHash[:])
			if certHashAddtoSet.Has(certHashToString) {
				continue
			} else {
				certHashAddtoSet.Add(certHashToString)
				// get encrypted string based on address as index
				log.Info("certHash", "certHash", certHashToString)
				getHashData, err := creditCTR.ContractCallParsed(rpc, coinbase, "getHashData", certHash)

				if err != nil {
					log.Error("ContractCallParsed failed", "err", err)
					return
				}

				// read identity info
				identity, ok := (getHashData[0]).([]byte)
				if !ok {
					log.Error("It's not ok for", "type", reflect.TypeOf(getHashData[0]))
					return
				}
				log.Info("Get identity string", "string", string(identity))

				m := identityInfo{}
				err = json.Unmarshal([]byte(identity), &m)
				if err != nil {
					log.Debug("Unmarshal failed")
					return
				}

				// read requestor's public key
				pubkey, ok := (getHashData[3]).(string)
				if !ok {
					log.Error("It's not ok for", "type", reflect.TypeOf(getHashData[3]))
					return
				}
				log.Debug("Get public key", "key", string(pubkey))
				//testData := "0x044da1f0e4bd859532f588372d2b63921fae49eaed12d5254f071993700c1835f1c6bcb351d3d042cd99dfeb30114be45272ec2167b49914669c42276bb58da91a59c6c4d5f3fc8e004dbca0613416a5669626987d9ba658d3cfb1294063264799d40c644e41736c1bb7e64530771f7af8521b67c6e03470253794dd3806587f083326da302f3725f0963962094beb20ca598b13a81823682c2ceb0cc4157c01091d9653900d6f940768cf8110c6c9293bd812420833402686cff61322421d3cbe78dd64a427ca8dc7a5dbf126d05abee2"
				//testM, _ := hexutil.Decode(testData)
				//fmt.Printf("m.data: %x\n", testM)

				encData, _ := hexutil.Decode(m.Data)
				sendPublickeyShared(usechain, nodelist, string(pubkey), max)
				pool.SaveEncryptedData(pubkey, common.Hash(certHash), string(encData))

				//issuer, ok := (res[1]).([]byte)
				//if !ok {
				//	log.Error("It's not ok for", "type", reflect.TypeOf(res[1]))
				//	return
				//}
				//log.Debug("get issuer string", "string", string(issuer))
			}
		}
	}

	ethQuitCh := make(chan struct{}, 1)
	loop := true
	for loop {
		select {
		case _,isClose := <- ethQuitCh:
			if !isClose {
				fmt.Println("[SCAN CLOSED] ScanCreditSystemAccount thread exitCh!")
				loop = false
			}
		default:
			processScan()
		}
	}
}

func ConfirmCreditSystemAccount(usechain *config.Usechain, addr common.Address, hash common.Hash) {
	rpc := usechain.NodeRPC
	coinbase := usechain.UserProfile.Address
	creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)

	// verify hash
	res, err := creditCTR.ContractTransaction(rpc, usechain.Kstore, coinbase, "verifyHash", addr, hash)
	log.Info("verifyHash transaction", "hash", res)
	if err != nil {
		log.Error("contract call", "err", err)
		return
	}
	if res == contract.ContractZero || res == contract.ContractNull {
		return
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

	///TODO: ID can be self
	for _, id := range verify.AccountVerifier(A, max) {
		log.Info("Send message to Verifier", "id", id, "node", nodelist[id])
		wnode.SendMsg(m, crypto.ToECDSAPub(common.FromHex(nodelist[id])))
	}
}

