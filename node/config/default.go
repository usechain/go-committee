// Copyright 2018 The go-committee Authors
// This file is part of the go-committee library.
//
// The go-committee library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-committee library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-committee library. If not, see <http://www.gnu.org/licenses/>.

package config

import (
	"os"
	"fmt"
	"encoding/json"
	"github.com/usechain/go-usedrpc"
	"github.com/usechain/go-usechain/accounts/keystore"
	"github.com/usechain/go-committee/contract/contract"
	"github.com/usechain/go-committee/utils"
	"github.com/usechain/go-usechain/log"
)

// Usechain implements the Usechain Committee full node service.
type Usechain struct {
	UserProfile  		*CommittteeProfile
	ManagerContract 	*contract.Contract
	IdentityContract 	*contract.Contract
	NodeRPC 			*usedrpc.UseRPC
	WisperInfo 			*NodeConfig
	UsedClient 			*UsedConfig
	Kstore  			*keystore.KeyStore
	Workstat 			State
}

// read the config from profile
func Init(u *Usechain) error{
	var err error
	u.UserProfile, err = ReadProfile()
	if err != nil {
		log.Error("Read the committee conf failed", "err", err)
		return err
	}
	u.ManagerContract, err = DefaultCommitteeContract()
	if err != nil {
		log.Error("Read the contract conf failed", "err", err)
		return err
	}
	u.IdentityContract, err = DefaultAuthenticationContract()
	if err != nil {
		log.Error("Read the identity contract conf failed", "err", err)
		return err
	}
	u.WisperInfo, err = ReadWhisperNode()
	if err != nil {
		log.Error("Read the whisper conf failed", "err", err)
		return err
	}
	u.UsedClient, err = ReadUsedConfig()
	if err != nil {
		log.Error("Read the used client conf failed", "err", err)
		return err
	}
	u.NodeRPC = usedrpc.NewUseRPC(u.UsedClient.Url)
	return nil
}


// Structure of a contract
type contractConfig struct {
	Name        string
	Description string
	Address   	string
	AbiStr      string
}

func DefaultCommitteeContract() (*contract.Contract, error) {
	crt, err := ReadManagerContractConfig()
	if err != nil {
		return nil, err
	}
	return contract.New(crt.Name, crt.Description, crt.Address, crt.AbiStr)
}

func ReadManagerContractConfig() (*contractConfig, error) {
	cfg, _ := os.Open(utils.DefaultDataDir() + "managerContract.json")
	defer cfg.Close()

	decoder := json.NewDecoder(cfg)
	ctr := &contractConfig{}
	err := decoder.Decode(&ctr)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return ctr, err
}

func UpdateManagerContractConfig(ctr *contractConfig) error {
	b, err := json.Marshal(ctr)
	if err != nil {
		fmt.Println("error:", err)
	}
	cfg, _ := os.OpenFile(utils.DefaultDataDir() + "managerContract.json", os.O_RDWR, 0666)
	defer cfg.Close()

	cfg.Truncate(0)
	_, err = cfg.WriteAt(b,0)
	if err != nil {
		fmt.Println("err", err)
	}
	return err
}



func DefaultAuthenticationContract() (*contract.Contract, error) {
	cfg, _ := os.Open(utils.DefaultDataDir() + "identityContract.json")
	defer cfg.Close()

	decoder := json.NewDecoder(cfg)
	crt := contractConfig{}
	err := decoder.Decode(&crt)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return contract.New(crt.Name, crt.Description, crt.Address, crt.AbiStr)
}

// Structure of a committee info
type CommittteeProfile struct {
	CommitteeID int
	Role 		string
	Address     string
	PrivShares	string
}


func ReadProfile() (*CommittteeProfile, error) {
	cfg, _ := os.Open(utils.DefaultDataDir() + "committee.json")
	defer cfg.Close()

	decoder := json.NewDecoder(cfg)
	crt := &CommittteeProfile{}
	err := decoder.Decode(&crt)
	if err != nil {
		fmt.Println("Error:", err)
	}
	//addr := common.StringToBase58Address(crt.Address)
	//crt.Address = common.Base58AddressToAddress(addr).String()
	return crt, err
}

func UpdateProfile(profile *CommittteeProfile) (error) {
	//if 	common.IsHexAddress(profile.Address) {
	//	Addr := common.HexToAddress(profile.Address)
	//	profile.Address = common.AddressToBase58Address(Addr).String()
	//}
	b, err := json.Marshal(*profile)
	if err != nil {
		fmt.Println("error:", err)
	}
	cfg, _ := os.OpenFile(utils.DefaultDataDir() + "committee.json", os.O_RDWR, 0666)
	defer cfg.Close()

	cfg.Truncate(0)
	_, err = cfg.WriteAt(b,0)
	if err != nil {
		fmt.Println("err", err)
	}
	return err
}

// Structure of a whisper node
type NodeConfig struct {
	NodeID	string
	Boot	string
	Topic   string
	Key     string
}

func ReadWhisperNode() (*NodeConfig, error) {
	fmt.Println(utils.DefaultDataDir() + "whisper.json")
	cfg, _ := os.Open(utils.DefaultDataDir() + "whisper.json")
	defer cfg.Close()

	decoder := json.NewDecoder(cfg)
	wsp := &NodeConfig{}
	err := decoder.Decode(&wsp)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return wsp, err
}

func UpdateWhisperNode(ws *NodeConfig) error {
	b, err := json.Marshal(ws)
	if err != nil {
		fmt.Println("error:", err)
	}
	cfg, _ := os.OpenFile(utils.DefaultDataDir() + "whisper.json", os.O_RDWR, 0666)
	defer cfg.Close()

	cfg.Truncate(0)
	_, err = cfg.WriteAt(b,0)
	if err != nil {
		fmt.Println("err", err)
	}
	return err
}

//Used node info
type UsedConfig struct {
	Name string
	Url  string
}

func ReadUsedConfig() (*UsedConfig, error) {
	cfg, _ := os.Open(utils.DefaultDataDir() + "used.json")
	defer cfg.Close()

	decoder := json.NewDecoder(cfg)
	used := &UsedConfig{}
	err := decoder.Decode(&used)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return used, err
}

func UpdateUsedConfig(used *UsedConfig) error {
	b, err := json.Marshal(used)
	if err != nil {
		fmt.Println("error:", err)
	}
	cfg, _ := os.OpenFile(utils.DefaultDataDir() + "used.json", os.O_RDWR, 0666)
	defer cfg.Close()

	cfg.Truncate(0)
	_, err = cfg.WriteAt(b,0)
	if err != nil {
		fmt.Println("err", err)
	}
	return err
}



