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
	"strconv"
)

const creditAddr = "0x16480bBf54C2de40AaF739501606c536A005292E"
const creditABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"_pubkey\",\"type\":\"string\"},{\"name\":\"_encryptedAS\",\"type\":\"string\"}],\"name\":\"subRegister\",\"outputs\":[{\"name\":\"_registerID\",\"type\":\"uint256\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getUnConfirmedSubAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"CommitteeAddr\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"confirmedMainAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"RegisterIDtoAddr\",\"outputs\":[{\"name\":\"verified\",\"type\":\"bool\"},{\"name\":\"toAddress\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"unConfirmedMainAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"account\",\"type\":\"address\"}],\"name\":\"isSigner\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_registerID\",\"type\":\"uint256\"},{\"name\":\"_status\",\"type\":\"uint8\"}],\"name\":\"verifySub\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"RegisterID\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_registerID\",\"type\":\"uint256\"},{\"name\":\"_hash\",\"type\":\"bytes32\"},{\"name\":\"_status\",\"type\":\"uint8\"}],\"name\":\"verifyHash\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"confirmedSubAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_user\",\"type\":\"address\"}],\"name\":\"test\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"UnConfirmedSubAddrID\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"unConfirmedSubAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"confirmedSubAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getUnConfirmedMainAddressLen\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"confirmedMainAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"renounceSigner\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"account\",\"type\":\"address\"}],\"name\":\"addSigner\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"SubAccount\",\"outputs\":[{\"name\":\"addr\",\"type\":\"address\"},{\"name\":\"status\",\"type\":\"uint8\"},{\"name\":\"publicKey\",\"type\":\"string\"},{\"name\":\"encryptedAS\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"UnConfirmedMainAddrID\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"MainAccount\",\"outputs\":[{\"name\":\"addr\",\"type\":\"address\"},{\"name\":\"hashKey\",\"type\":\"bytes32\"},{\"name\":\"status\",\"type\":\"uint8\"},{\"name\":\"identity\",\"type\":\"bytes\"},{\"name\":\"issuer\",\"type\":\"bytes\"},{\"name\":\"publicKey\",\"type\":\"string\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_publicKey\",\"type\":\"string\"},{\"name\":\"_hashKey\",\"type\":\"bytes32\"},{\"name\":\"_identity\",\"type\":\"bytes\"},{\"name\":\"_issuer\",\"type\":\"bytes\"}],\"name\":\"register\",\"outputs\":[{\"name\":\"_registerID\",\"type\":\"uint256\"}],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"_addr\",\"type\":\"address\"}],\"name\":\"getAccountStatus\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"addr\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"hash\",\"type\":\"bytes32\"}],\"name\":\"NewUserRegister\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"addr\",\"type\":\"address\"},{\"indexed\":true,\"name\":\"hash\",\"type\":\"bytes32\"}],\"name\":\"NewIdentity\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"account\",\"type\":\"address\"}],\"name\":\"SignerAdded\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"name\":\"account\",\"type\":\"address\"}],\"name\":\"SignerRemoved\",\"type\":\"event\"}]"

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
	registerIDSet := NewSet()
	creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)
	ethQuitCh := make(chan struct{}, 1)
	subSet := NewSet()
	processScan := func() {
		// get unconfirmed main address number
		getUnConfirmedMainAddressLen, err := creditCTR.ContractCall(rpc, coinbase, "getUnConfirmedMainAddressLen")
		if err != nil {
			log.Error("contract call", "err", err)
			return
		}
		if getUnConfirmedMainAddressLen == contract.ContractZero || getUnConfirmedMainAddressLen == contract.ContractNull{
			return
		}
		unconfirmedCount, _ := big.NewInt(0).SetString(getUnConfirmedMainAddressLen[2:], 16)

		for i := int64(0); i < unconfirmedCount.Int64(); i++ {
			// get unconfirmed address index
			UnConfirmedMainAddrID, err := creditCTR.ContractCall(rpc, coinbase, "UnConfirmedMainAddrID", big.NewInt(i))
			if err != nil && len(UnConfirmedMainAddrID) == 0 {
				log.Debug("Read unconfirmed address failed", "err", err)
				return
			}

			mainID , _ := big.NewInt(0).SetString(UnConfirmedMainAddrID[2:], 16)
			UnConfirmedMainAddr, err := creditCTR.ContractCallParsed(rpc, coinbase, "RegisterIDtoAddr", big.NewInt(mainID.Int64()))
			if err != nil && len(UnConfirmedMainAddrID) == 0 {
				log.Debug("Read UnConfirmedMainAddrID failed", "err", err)
				return
			}

			mainAccount, err := creditCTR.ContractCallParsed(rpc, coinbase, "MainAccount", UnConfirmedMainAddr[1])
			if err != nil {
				log.Debug("Read unconfirmed mainAccount failed", "err", err)
				return
			}

			addrIDstring := strconv.Itoa(int(mainID.Int64()))
			if registerIDSet.Has(addrIDstring) {
				continue
			} else {
				registerIDSet.Add(addrIDstring)
				// get encrypted string based on address as index
				log.Info("Receive UnConfirmedMainAddr", "UnConfirmedMainAddr", mainAccount[0].(common.Address))

				hashKey := mainAccount[1].([32]uint8)

				// read identity info
				identity, ok := (mainAccount[3]).([]byte)
				if !ok {
					log.Error("It's not ok for", "type", reflect.TypeOf(mainAccount[3]))
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
				issuer, ok := (mainAccount[4]).([]byte)
				if !ok {
					log.Error("It's not ok for", "type", reflect.TypeOf(mainAccount[4]))
					return
				}
				log.Debug("get issuer string", "string", string(issuer))

				issuerVerify := Issuer{}
				err = json.Unmarshal([]byte(issuer), &issuerVerify)
				if err != nil{
					log.Debug( "Unmarshal failed: " , "err", err )
				}

				hashKeyString := hexutil.Encode(hashKey[:])
				err = CheckUserRegisterCert([]byte(issuerVerify.Cert), hashKeyString, id.Fpr)
				if err != nil {
					log.Error("CheckUserRegisterCert failed", err)
					return
				}

				// read requestor's public key
				pubkey, ok := (mainAccount[5]).(string)
				if !ok {
					log.Error("It's not ok for", "type", reflect.TypeOf(mainAccount[5]))
					return
				}
				log.Debug("Get public key", "key", string(pubkey))

				decrypedAndVerifyData := strings.Join([]string{hashKeyString, id.Data},"+")
				sendPublickeyShared(usechain, nodelist, string(pubkey), max, addrIDstring)
				pool.SaveEncryptedData(addrIDstring, common.Hash(hashKey), decrypedAndVerifyData)
			}
		}
	}

	processSubScan := func() {
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

		for i := int64(0); i < unconfirmedSub.Int64(); i++ {
			// get unconfirmed address
			UnConfirmedSubAddrID, err := creditCTR.ContractCall(rpc, coinbase, "UnConfirmedSubAddrID", big.NewInt(i))
			if err != nil {
				log.Debug("Read UnConfirmedSubAddrID failed", "err", err)
				return
			}
			subID, _ := big.NewInt(0).SetString(UnConfirmedSubAddrID[2:], 16)
			SubAddr, err := creditCTR.ContractCallParsed(rpc, coinbase, "RegisterIDtoAddr", big.NewInt(subID.Int64()))
			if err != nil {
				log.Debug("Read unconfirmed sub address failed", "err", err)
				return
			}

			SubAccount, err := creditCTR.ContractCallParsed(rpc, coinbase, "SubAccount", SubAddr[1])
			if err != nil {
				log.Debug("Read unconfirmed SubAccount failed", "err", err)
				return
			}

			subPubkey, ok := (SubAccount[2]).(string)
			if !ok {
				log.Error("It's not ok for", "type", reflect.TypeOf(SubAccount[2]))
				return
			}
			encryptedAS, ok := (SubAccount[3]).(string)
			if !ok {
				log.Error("It's not ok for", "type", reflect.TypeOf(SubAccount[3]))
				return
			}

			addrSubIDstring := strconv.Itoa(int(subID.Int64()))
			if subSet.Has(string(addrSubIDstring)) {
				continue
			} else {
				subSet.Add(string(addrSubIDstring))
				sendSubPublickeyShared(usechain, nodelist, string(subPubkey), max, addrSubIDstring)
				subVerifyData := strings.Join([]string{string(subPubkey),encryptedAS}, "+")
				pool.SaveEncryptedSub(addrSubIDstring, subVerifyData)
			}
		}
	}

	processSub := func(subdata *core.SubData) {
		// TODO : CHECK Amain
		//if subdata.Amain not main account {
		//	return
		//}
		sendSubShared(usechain, nodelist, subdata.Amain, subdata.S, max)
		// many A with one HS
		pool.SaveSubData(subdata.S, subdata.H, subdata.SubID)
	}

	loop := true
	for loop {
		select {
		case _,isClose := <- ethQuitCh:
			if !isClose {
				fmt.Println("[SCAN CLOSED] ScanCreditSystemAccount thread exitCh!")
				loop = false
			}

		case subdata := <- pool.SubChan:
			processSub(subdata)

		default:
			processScan()
			processSubScan()
			time.Sleep(time.Second * 5)
		}
	}
}

func ConfirmCreditSystemAccount(usechain *config.Usechain, mainData core.VerifiedMain) error {
	rpc := usechain.NodeRPC
	coinbase := usechain.UserProfile.Address
	creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)

	// verify hash
	res, err := creditCTR.ContractTransaction(rpc, usechain.Kstore, coinbase, "verifyHash", mainData.RegisterID, mainData.Hashkey, mainData.Status)
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

func ConfirmSubAccount(usechain *config.Usechain, sub core.VerifiedSub) error {
	rpc := usechain.NodeRPC
	coinbase := usechain.UserProfile.Address
	creditCTR, _ := contract.New("credit contract", "", creditAddr, creditABI)

	// verify hash
	res, err := creditCTR.ContractTransaction(rpc, usechain.Kstore, coinbase, "verifySub", sub.RegisterID, sub.Status)
	if err != nil {
		log.Error("VerifySub transaction", "err", err)
		return err
	}
	log.Info("VerifySub transaction", "hash", res)

	if res == contract.ContractZero || res == contract.ContractNull {
		return nil
	}
	return nil
}

func sendPublickeyShared(usechain *config.Usechain, nodelist []string, A string, max int, addrID string) {
	priv := sssa.ExtractPrivateShare(usechain.UserProfile.PrivShares)	//bs
	if priv == nil {
		log.Error("No valid private share")
		return
	}
	publicA := crypto.ToECDSAPub(common.FromHex(A))		//A

	pubkey := new(ecdsa.PublicKey)
	pubkey.X, pubkey.Y = crypto.S256().ScalarMult(publicA.X, publicA.Y, priv.D.Bytes())   //bsA=[bs]B
	pubkey.Curve = crypto.S256()

	m := msg.PackVerifyShare(addrID, pubkey, usechain.UserProfile.CommitteeID)

	///TODO: ID can be self
	for _, id := range verify.AccountVerifier(addrID, max) {
		log.Info("Send message to Verifier", "id", id, "node", nodelist[id])
		wnode.SendMsg(m, crypto.ToECDSAPub(common.FromHex(nodelist[id])))
	}
}

func sendSubPublickeyShared(usechain *config.Usechain, nodelist []string, A string, max int, addrSubIDstring string) {
	priv := sssa.ExtractPrivateShare(usechain.UserProfile.PrivShares)	//bs
	if priv == nil {
		log.Error("No valid private share")
		return
	}
	publicA := crypto.ToECDSAPub(common.FromHex(A))		//A

	pubkey := new(ecdsa.PublicKey)
	pubkey.X, pubkey.Y = crypto.S256().ScalarMult(publicA.X, publicA.Y, priv.D.Bytes())   //bsA=[bs]B
	pubkey.Curve = crypto.S256()

	m := msg.PackVerifySubShare(addrSubIDstring, pubkey, usechain.UserProfile.CommitteeID)

	///TODO: ID can be self
	for _, id := range verify.AccountSubVerifier(addrSubIDstring, max) {
		log.Info("Send sub account message to Verifier", "id", id, "node", nodelist[id])
		wnode.SendMsg(m, crypto.ToECDSAPub(common.FromHex(nodelist[id])))
	}
}

func sendSubShared(usechain *config.Usechain, nodelist []string, A string,S string, max int) {
	priv := sssa.ExtractPrivateShare(usechain.UserProfile.PrivShares)	//bs
	if priv == nil {
		log.Error("No valid private share")
		return
	}
	publicA := crypto.ToECDSAPub(common.FromHex(A))		//A

	pubkey := new(ecdsa.PublicKey)
	pubkey.X, pubkey.Y = crypto.S256().ScalarMult(publicA.X, publicA.Y, priv.D.Bytes())   //bsA=[bs]B
	pubkey.Curve = crypto.S256()

	m := msg.PackVerifyShare(S, pubkey, usechain.UserProfile.CommitteeID)

	///TODO: ID can be self
	for _, id := range verify.AccountVerifier(S, max) {
		log.Info("Send main accunt of the sub account to Verifier", "id", id, "node", nodelist[id])
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
