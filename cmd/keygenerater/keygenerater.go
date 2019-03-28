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

package main

import (
	"fmt"
	"github.com/usechain/go-committee/account"
	"github.com/usechain/go-committee/console"
	"github.com/usechain/go-committee/node/config"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/wnode"
)

func main() {
	fmt.Println("Creating a new account......")
	fmt.Print("Please enter passwd:")
	passwd := console.Readline()

	ks := account.DefaultKeystore(*wnode.ArgMoonet)
	ac := account.NewAccount(ks, passwd)
	fmt.Printf("Account:%s generated!\n", ac.Address.Hex())

	fmt.Println("Want this account to be committee address: y/n?")
	active := true

	for active {
		input := console.Readline()

		switch input{
		case "y":
			p, _ := config.ReadProfile()
			p.Address = ac.Address.Hex()
			config.UpdateProfile(p)
			log.Info("committee.json Updated")
			active = false
		case "n":
			fmt.Println("Finished")
			active = false
		default:
			fmt.Println("Please enter \"y\" or \"n\"")
		}
	}

	fmt.Println("Please enter a used node url, example:\"http://10.30.43.237:8548\"")
	fmt.Print("URL:")
	url := console.Readline()
	p, _ := config.ReadUsedConfig()
	p.Url = url
	config.UpdateUsedConfig(p)
	fmt.Println("Confit file used.json updated")
}
