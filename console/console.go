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


package console

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/usechain/go-usedrpc"
	"github.com/usechain/go-usechain/log"
	"github.com/usechain/go-committee/wnode"
	"github.com/usechain/go-usechain/crypto"
	"github.com/usechain/go-usechain/common"
	"github.com/usechain/go-committee/account"
	"github.com/peterh/liner"
	"github.com/usechain/go-committee/utils"
	"path/filepath"
	"github.com/usechain/go-committee/node/config"
)

// Structure of a command
type command struct {
	name        string
	description string
	function    func(string)
}

// Console configurations
type Console struct {
	// Controls the console loop
	Active bool

	// Displayed at the beginning of a line. Defaults to no linebreak. Possible value is "\n".
	Prompt string

	// Displayed when a command is not found.
	NotFound string

	// Displayed when first opened on the top line.
	Title string

	// Displayed between each line
	NewLine string

	// Map of all the callable commands
	commands map[string]command
}

// The New function creates an instance of the console type.
func New(conf config.Usechain) *Console {
	con := &Console{}
	con.commands = make(map[string]command)
	con.Active = false
	con.Title = "*** Welcome to the Usechain Committee console! ***\n"
	con.Prompt = ""
	con.NotFound = "Command not found: "
	con.NewLine = "\n"

	// Load the default commands
	con.Add("clear", "Clear the screen", func(typed string) {
		ClearScreen()
	})

	con.Add("exit", "Exit the console", func(typed string) {
		con.Active = false
	})

	con.Add("use.coinbase", "Get the used node coinbase", func(typed string) {
		c := usedrpc.NewUseRPC(conf.NodeRPC.URL())
		coinbase, err := c.UseCoinbase()
		if err != nil {
			log.Info("err:", "err", err)
		} else {
			log.Info("GetCoinbase:", "coinbase", coinbase)
		}
	})

	con.Add("use.blockNumber", "Get the block number", func(typed string) {
		c := usedrpc.NewUseRPC(conf.NodeRPC.URL())
		blocknumber, err := c.UseBlockNumber()
		if err != nil {
			log.Info("err:", "err", err)
		} else {
			log.Info("BlockNumber:", "Number", blocknumber)
		}

	})

	con.Add("shh.sendMsg", "Send a whisper msg", func(typed string) {
		arr := strings.Fields(typed)
		if len(arr) == 3 {
			msg := []byte(arr[1])
			pub := crypto.ToECDSAPub(common.FromHex(arr[2]))
			wnode.SendMsg(msg, pub)
			return
		} else if len(arr) == 2 {
			msg := []byte(arr[1])
			wnode.SendMsg(msg, nil)
		} else {
			fmt.Println("Wrong format")
			fmt.Println("ssh.sendMsg message destination-public-key")
		}
	})

	con.Add("committee.unlock", "Unlock the committee account", func(typed string) {
		arr := strings.Fields(typed)
		if len(arr) != 2 {
			fmt.Println("Please use committee.unlock in right format")
			return
		}
		account.CommitteePasswd <- arr[1]
	})


	con.Add("help", "Show a list of available commands", func(typed string) {
		// Sort by keywords
		keys := make([]string, 0)
		for key := range con.commands {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		// Output the commands
		fmt.Println("Available commands:")
		for i, val := range keys {
			if i == len(keys)-1 {
				fmt.Print(con.commands[val].name, " - ", con.commands[val].description)
			} else {
				fmt.Println(con.commands[val].name, "-", con.commands[val].description)
			}
		}
	})

	return con
}

// The Start function starts the console loop where the user is prompted for keywords and then runs the associated functions.
func (con *Console) Start() {
	ClearScreen()
	fmt.Print(con.Title)

	// Set the initial values
	con.Active = true

	var history []string
	histfile := filepath.Join(utils.DefaultDataDir() + "history")

	Prompter := liner.NewLiner()
	defer Prompter.Close()

	if content, err := os.Open(histfile); err != nil {
		Prompter.ReadHistory(strings.NewReader(strings.Join(nil, "\n")))
		content.Close()
	} else {
		Prompter.ReadHistory(content)
		content.Close()
	}

	// Loop while the value is true
	for con.Active {
		//fmt.Print(con.Prompt)
		typed, err := Prompter.Prompt("> ")
		if err != nil {
			fmt.Println(err)
		}
		// If at least a character is typed
		if arr := strings.Fields(typed); len(arr) > 0 {
			if cmd, ok := con.commands[arr[0]]; ok {
				cmd.function(typed)
				fmt.Println()
			} else {
				fmt.Println(con.NotFound + arr[0])
			}
			fmt.Print(con.NewLine)
		}

		if command := strings.TrimSpace(typed); len(history) == 0 || command != history[len(history)-1] {
			history = append(history, command)
			Prompter.AppendHistory(command)

			if f, err := os.Create(histfile); err != nil {
				log.Error("Error writing history file: ", "error", err)
			} else {
				_, err := Prompter.WriteHistory(f)
				if err != nil{
					log.Error("Error writing history file: ", "error", err)
				}
				f.Close()
			}
		}
	}
}

// The Add function registers a new console keyword, description (used in the help keyword), and function. The function must receive a string type which is the entire string of text the user typed in before pressing Enter.
func (con *Console) Add(keyword string, description string, function func(string)) {
	con.commands[keyword] = command{keyword, description, function}
}

// The Remove function unregisters a console keyword so it cannot be called.
func (con *Console) Remove(keyword string) {
	delete(con.commands, keyword)
}

// The Clear function unregisters all the console keywords so they cannot be called.
func (con *Console) Clear() {
	con.commands = make(map[string]command)
}

// The Readline function waits for the user to type and then press Enter. Readline returns the typed string.
func Readline() string {
	bio := bufio.NewReader(os.Stdin)
	line, _, err := bio.ReadLine()
	if err != nil {
		fmt.Println(err)
	}
	return string(line)
}

// The ClearScreen function clears the screen. It is platform independent.
func ClearScreen() {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	} else {
		cmd := exec.Command("clear")
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}
