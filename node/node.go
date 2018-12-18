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

package node

import (
	"os"
	"github.com/usechain/go-usechain/cmd/utils"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-usedrpc"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-committee/account"
	"github.com/usechain/go-committee/contract/manager"
	"github.com/usechain/go-committee/shamirkey"
	"github.com/usechain/go-committee/node/config"
)

var (
	globalConfig  config.Usechain
)

//init the committee global config
func initial() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlDebug, log.StreamHandler(os.Stdout, log.TerminalFormat(true))))
	log.Info("Committee node initializing ......")

	var err error
	globalConfig.UserProfile, err = config.ReadProfile()
	if err != nil {
		utils.Fatalf("Read the committee conf failed, %v", err)
	}
	globalConfig.ManagerContract, err = config.DefaultCommitteeContract()
	if err != nil {
		utils.Fatalf("Read the contract conf failed, %v", err)
	}
	globalConfig.IdentityContract, err = config.DefaultAuthenticationContract()
	if err != nil {
		utils.Fatalf("Read the identity contract conf failed, %v", err)
	}
	globalConfig.WisperInfo, err = config.ReadWhisperNode()
	if err != nil {
		utils.Fatalf("Read the whisper conf failed, %v", err)
	}
	globalConfig.UsedClient, err = config.ReadUsedConfig()
	if err != nil {
		utils.Fatalf("Read the used client conf failed, %v", err)
	}
	globalConfig.NodeRPC = usedrpc.NewUseRPC(globalConfig.UsedClient.Url)

	//Check the committee account format && legality
	addr := globalConfig.UserProfile.Address
	if addr == "" || !common.IsHexAddress(addr) {
		utils.Fatalf("Please fill in correct committee address in conf")
	} else {
		globalConfig.Kstore = account.DefaultKeystore()
		signer, err := account.CommitteeAccount(common.HexToAddress(addr), globalConfig.Kstore)
		if err != nil {
			utils.Fatalf("Please import committee corresponding keystore file")
		}

		log.Warn("Please unlock the committee account")
		log.Warn("Enter \"committee.unlock \"passwd\"\"")
		select {
		case passwd := <- account.CommitteePasswd:
			err = globalConfig.Kstore.TimedUnlock(signer, passwd, 0)
			if err != nil {
				utils.Fatalf("Unlock the committee account failed %v", err)
			}
		}
	}

	log.Info("Usechain Committee Console Initialization Complete")
}

//committee work main process
func run() {
	globalConfig.Workstat = config.GetState(globalConfig)
	log.Debug("The process is in stage", "workStat", globalConfig.Workstat)

	switch globalConfig.Workstat {
	case config.NotCommittee:
		utils.Fatalf("Not a legal committee address!")

	case config.Selected:
		log.Debug("selected, please confirm")
		//Get committe id from contract
		id, err := manager.GetSelfCommitteeID( globalConfig)
		if err != nil || id == -1{
			log.Error("Get certid failed", "err", err)
		}
		globalConfig.UserProfile.CommitteeID = id
		if id == 0 {
			globalConfig.UserProfile.Role = "Verifier"
		}else {
			globalConfig.UserProfile.Role = "Sharer"
		}
		config.UpdateProfile(globalConfig.UserProfile)

		//Confirm & upload self asym key
		manager.ConfirmAndKeyUpload(globalConfig)

	case config.WaittingOther:
		log.Debug("Just waitting!")

	case config.KeyGenerating:
		log.Warn("KeyGenerating")
		//Read from contract to update certid, upload asym key, and download all committee certID and asym key
		shamirkey.InitShamirCommitteeNumber(globalConfig)

		go shamirkey.ShamirKeyShareCheck(&globalConfig)
		go shamirkey.ShamirKeySharesListening(globalConfig.UserProfile)

		shamirkey.SendRequesuShares(globalConfig.UserProfile.CommitteeID)
		shamirkey.ShamirKeySharesGenerate(globalConfig.UserProfile.CommitteeID)

	case config.Verifying:
		log.Debug("Verifying...")
		//Read from contract to update certid, upload asym key, and download all committee certID and asym key
		shamirkey.InitShamirCommitteeNumber(globalConfig)
		go shamirkey.ShamirKeySharesListening(globalConfig.UserProfile)
		switch globalConfig.UserProfile.Role {
		case "Sharer":
			log.Debug("Sharer start!")
			shamirkey.AccountShareSharer(&globalConfig)
		case "Verifier":
			log.Debug("Verifier start")
			shamirkey.AccountShareVerifer(&globalConfig)
		default:
			log.Debug("Unknown role")
		}

	default:
		utils.Fatalf("Unknown state")
	}

	return
}

//entry for committee working process
func Start() {
	initial()
	run()
}

