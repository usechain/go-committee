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

package shamirkey

import(
	"testing"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-usedrpc"
	"github.com/usechain/go-usechain/cmd/utils"
)

var (
	usechain  config.Usechain
)
func TestInitShamirCommitteeConfig(t *testing.T) {
	var err error
	usechain.UserProfile, err = config.ReadProfile()
	if err != nil {
		utils.Fatalf("Read the committee conf failed, %v", err)
	}
	usechain.ManagerContract, err = config.DefaultCommitteeContract()
	if err != nil {
		utils.Fatalf("Read the contract conf failed, %v", err)
	}
	usechain.WisperInfo, err = config.ReadWhisperNode()
	if err != nil {
		utils.Fatalf("Read the whisper conf failed, %v", err)
	}
	usechain.UsedClient, err = config.ReadUsedConfig()
	if err != nil {
		utils.Fatalf("Read the used client conf failed, %v", err)
	}
	usechain.NodeRPC = usedrpc.NewUseRPC(usechain.UsedClient.Url)


	InitShamirCommitteeNumber(usechain)
}
