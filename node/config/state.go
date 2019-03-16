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
	"github.com/usechain/go-committee/contract/contract"
	"github.com/usechain/go-usechain/log"
)

//The state of the Usechain committee
type State int

//Enum of the State
const (
	Voting State = iota	//value --> 0	in voting
	Selected			//value --> 1	selected, but not confirmed
	WaittingOther		//value --> 2	self confirmed, wait for all confirmed
	KeyGenerating		//value --> 3	in generating committee key
	Verifying			//value --> 4   in verification
	NotCommittee		//value --> 5	not a committee
	Other				//value --> 6
)

//Get the state of the committee
func GetState(config Usechain) State {
	node := config.NodeRPC
	c := config.ManagerContract
	addr := config.UserProfile.Address
	role := config.UserProfile.Role

	//Check whether a real committee
	res, err := c.ContractCall(node, addr, "IsCommittee")
	log.Debug("Get committee state ", "res", res)
	if err != nil || res == contract.ContractFalse {
		log.Error("Not a committee")
		return NotCommittee
	}

	//Check the confirmed stat, if not confirmed yet, confirm && upload self message pubkey
	res, err = c.ContractCall(node, addr, "getCommitteeConfirmStat")
	log.Debug("Get Committee ConfirmStat:", "res", res)
	if err != nil || res == contract.ContractFalse {
		log.Trace("Selected, but not confirmed")
		return Selected
	}

	//Check whether got key share already, if not try to generating
	res, err = c.ContractCall(node, addr, "isEntireConfirmed")
	log.Debug("Is Entire Confirmed? ", "res", res)
	if err != nil || res == contract.ContractFalse {
		log.Trace("Selected, but not all confirmed")
		return WaittingOther
	}

	//All confirmed, try to generate the private shares
	pr, err := ReadProfile()
	if (err != nil || pr.PrivShares == "") && role == "Sharer" {
		log.Trace("Key shares not exist")
		return KeyGenerating
	}

	//Otherwise, enter the regular work process, verify the AB address
	return Verifying
}
