package creditNew

import (
	"math/big"
	"reflect"
	"crypto/ecdsa"
  "fmt"
	"time"
	"encoding/pem"
	"crypto/x509"
	"strings"
	"io/ioutil"
  "encoding/json"
	"github.com/usechain/go-committee/contract/contract"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-committee/shamirkey/sssa"
	"github.com/usechain/go-committee/shamirkey/core"
	"github.com/usechain/go-committee/shamirkey/verify"
	"github.com/usechain/go-committee/wnode"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-committee/shamirkey/msg"
	"github.com/usechain/go-usechain/common/hexutil"
	"github.com/usechain/go-usechain/node"
)

const creditAddr = "0xa24178Fc0884420d96Ea7a3Add81079F280ca022"
const creditABI = "[{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"SubAddr\",\"outputs\":[{\"name\":\"confirmed\",\"type\":\"bool\"},{\"name\":\"pubKey\",\"type\":\"string\"},{\"name\":\"encryptedAS\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"UnConfirmedSubAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_pubkey\",\"type\":\"string\"},{\"name\":\"_encryptedAS\",\"type\":\"string\"}],\"name\":\"subRegister\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getUnConfirmedSubAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"CommitteeAddr\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"hash\",\"type\":\"bytes32\"}],\"name\":\"getHashData\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes\"},{\"name\":\"\",\"type\":\"bytes\"},{\"name\":\"\",\"type\":\"bool\"},{\"name\":\"\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getUnregisterHash\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"getUserInfo\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"string\"},{\"name\":\"\",\"type\":\"bytes32\"},{\"name\":\"\",\"type\":\"bytes32[]\"},{\"name\":\"\",\"type\":\"bool[]\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_user\",\"type\":\"address\"}],\"name\":\"isMainAccount\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"hashKey\",\"type\":\"bytes32\"},{\"name\":\"_identity\",\"type\":\"bytes\"},{\"name\":\"_issuer\",\"type\":\"bytes\"}],\"name\":\"addNewIdentity\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"account\",\"type\":\"address\"}],\"name\":\"isSigner\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"verifySub\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"unregister\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"verifyBase\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_addr\",\"type\":\"address\"}],\"name\":\"checkSubAddr\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_user\",\"type\":\"address\"}],\"name\":\"test\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"addr\",\"type\":\"address\"},{\"name\":\"hash\",\"type\":\"bytes32\"}],\"name\":\"verifyHash\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"getBaseData\",\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\"},{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"unConfirmedSubAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getUnregisterLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"renounceSigner\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"account\",\"type\":\"address\"}],\"name\":\"addSigner\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_publicKey\",\"type\":\"string\"},{\"name\":\"_hashKey\",\"type\":\"bytes32\"},{\"name\":\"_identity\",\"type\":\"bytes\"},{\"name\":\"_issuer\",\"type\":\"bytes\"}],\"name\":\"register\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"addr\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"hash\",\"type\":\"bytes32\"}],\"name\":\"NewUserRegister\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"addr\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"hash\",\"type\":\"bytes32\"}],\"name\":\"NewIdentity\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"account\",\"type\":\"address\"}],\"name\":\"SignerAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"account\",\"type\":\"address\"}],\"name\":\"SignerRemoved\",\"type\":\"event\"}]"

//The struct of the identity
type Identity struct {
	Data     string `json:"data"`
	Nation   string `json:"nation"`
	Entity   string `json:"entity"`
	Fpr      string `json:"fpr"`
	Alg      string `json:"alg"`
	CertType string `json:"certtype"`
	Ver      string `json:"ver"`
	Cdate    string `json:"cdate"`
}

type Issuer struct {
	Cert   string      `json:"cert"`
	Alg    string      `json:"alg"`
	UseId  string      `json:"useid"`
	PubKey interface{} `json:"-"`
	Cdate  string      `json:"cdate"`
	Edate  string      `json:"edate"`
}


func ScanCreditSystemAccount(usechain *config.Usechain, pool *core.SharePool, nodelist []string, max int) {
	rpc := usechain.NodeRPC
	coinbase := usechain.UserProfile.Address
	certHashAddtoSet := NewSet()
	creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)
	ethQuitCh := make(chan struct{}, 1)

	processScan := func() {
		// get unconfirmed main address number
		UnregisterLen, err := creditCTR.ContractCall(rpc, coinbase, "getUnregisterLen")
		if err != nil {
			log.Error("contract call", "err", err)
			return
		}
		if UnregisterLen == contract.ContractZero || UnregisterLen == contract.ContractNull{
			return
		}
		unconfirmedCount, _ := big.NewInt(0).SetString(UnregisterLen[2:], 16)


		// get unconfirmed sub address number
		UnConfirmedSubLen, err := creditCTR.ContractCall(rpc, coinbase, "getUnConfirmedSubAddressLen")
		if err != nil {
			log.Error("contract call", "err", err)
			return
		}
		if UnConfirmedSubLen == contract.ContractZero || UnConfirmedSubLen == contract.ContractNull{
			return
		}
		unconfirmedSub, _ := big.NewInt(0).SetString(UnConfirmedSubLen[2:], 16)


		for i := int64(0); i < unconfirmedCount.Int64(); i++ {
			// get unconfirmed address index
			unregister, err := creditCTR.ContractCallParsed(rpc, coinbase, "unregister", big.NewInt(i))
			if err != nil && len(unregister) == 0 {
				log.Debug("Read unconfirmed address failed", "err", err)
				return
			}
			certHash, ok := (unregister[0]).([32]uint8)
			if !ok {
				log.Error("It's not ok for", "type", reflect.TypeOf(unregister[0]))
				return
			}

			certHashToString := hexutil.Encode(certHash[:])
			if certHashAddtoSet.Has(certHashToString) {
				continue
			} else {
				certHashAddtoSet.Add(certHashToString)
				// get encrypted string based on address as index
				log.Info("Receive certHash", "certHash", certHashToString)
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
				log.Debug("Get identity string", "string", string(identity))

				id := Identity{}
				err = json.Unmarshal([]byte(identity), &id)
				if err != nil {
					log.Debug( "Unmarshal failed: " , err )
					return
				}

				// read issuer info
				issuer, ok := (getHashData[1]).([]byte)
				if !ok {
					log.Error("It's not ok for", "type", reflect.TypeOf(getHashData[1]))
					return
				}
				log.Debug("get issuer string", "string", string(issuer))

				issuerVerify := Issuer{}
				err = json.Unmarshal([]byte(issuer), &issuerVerify)
				if err != nil{
					log.Debug( "Unmarshal failed: " , "err", err )
				}

				err = CheckUserRegisterCert([]byte(issuerVerify.Cert), certHashToString, id.Fpr)
				if err != nil {
					log.Error("CheckUserRegisterCert failed", err)
					return
				}

				// read requestor's public key
				pubkey, ok := (getHashData[3]).(string)
				if !ok {
					log.Error("It's not ok for", "type", reflect.TypeOf(getHashData[3]))
					return
				}
				log.Debug("Get public key", "key", string(pubkey))

				decrypedAndVerifyData := strings.Join([]string{certHashToString, id.Data},"+")
				sendPublickeyShared(usechain, nodelist, string(pubkey), max)
				pool.SaveEncryptedData(pubkey, common.Hash(certHash), decrypedAndVerifyData)
			}
		}

		for i := int64(0); i < unconfirmedSub.Int64(); i++ {
			// get unconfirmed address
			unConfiredSubAddr, err := creditCTR.ContractCallParsed(rpc, coinbase, "UnConfirmedSubAddress", big.NewInt(i))
			if err != nil {
				log.Debug("Read unconfirmed  sub address failed", "err", err)
				return
			}

			SubAddr, err := creditCTR.ContractCallParsed(rpc, coinbase, "SubAddr", unConfiredSubAddr)
			if err != nil {
				log.Debug("Read unconfirmed  sub address failed", "err", err)
				return
			}
			subPubkey, ok := (SubAddr[1]).(string)
			if !ok {
				log.Error("It's not ok for", "type", reflect.TypeOf(SubAddr[1]))
				return
			}
			encryptedAS, ok := (SubAddr[2]).(string)
			if !ok {
				log.Error("It's not ok for", "type", reflect.TypeOf(SubAddr[2]))
				return
			}
			sendPublickeyShared(usechain, nodelist, string(subPubkey), max)
			pool.SaveEncryptedSub(subPubkey, encryptedAS)
		}
	}
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
			time.Sleep(time.Second * 5)
		}
	}
}

func ConfirmCreditSystemAccount(usechain *config.Usechain, addr common.Address, hash common.Hash) error {
	rpc := usechain.NodeRPC
	coinbase := usechain.UserProfile.Address
	creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)

	// verify hash
	res, err := creditCTR.ContractTransaction(rpc, usechain.Kstore, coinbase, "verifyHash", addr, hash)
	log.Info("VerifyHash transaction", "hash", res)
	if err != nil {
		log.Error("contract call", "err", err)
		return err
	}

	if res == contract.ContractZero || res == contract.ContractNull {
		return nil
	}
	return nil
}

func ConfirmSubAccount(usechain *config.Usechain, addr common.Address) error {
	rpc := usechain.NodeRPC
	coinbase := usechain.UserProfile.Address
	creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)

	// verify hash
	res, err := creditCTR.ContractTransaction(rpc, usechain.Kstore, coinbase, "verifySub", addr)
	log.Info("VerifySub transaction", "hash", res)
	if err != nil {
		log.Error("contract call", "err", err)
		return err
	}

	if res == contract.ContractZero || res == contract.ContractNull {
		return nil
	}
	return nil
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

func CheckUserRegisterCert(cert []byte, idhex string, fpr string) error {
	rcaCert, err := parseRcaRsa()
	certBlock, _ := pem.Decode(cert)
	if certBlock == nil {
		log.Error("User's cert not found!")
		return err
	}
	parsed, err := x509.ParseCertificate(certBlock.Bytes)

	err = parsed.CheckSignatureFrom(rcaCert)
	if err != nil {
		log.Error("Not from the official RCA")
		return err
	}

	subject := parsed.Subject.String()
	if !strings.Contains(subject, idhex) || !strings.Contains(subject, fpr) {
		log.Error("Not the right cert of this user")
		return err
	}

	return nil
}

func parseRcaRsa() (*x509.Certificate, error) {
	BaseDir := node.DefaultDataDir()
	rcaFile, err := ioutil.ReadFile(BaseDir + "/mainnetCA.pem")
	if err != nil {
		log.Error("ReadFile err:", "err", err)
		return nil, err
	}

	rcaBlock, _ := pem.Decode(rcaFile)
	if rcaBlock == nil {
		return nil, err
	}

	Cert, err := x509.ParseCertificate(rcaBlock.Bytes)
	if err != nil {
		log.Error("ParseCertificate err:", "err", err)
		return nil, err
	}
	return Cert, nil
}
