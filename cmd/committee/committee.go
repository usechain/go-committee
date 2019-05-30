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
	"github.com/usechain/go-committee/node"
	"github.com/usechain/go-committee/wnode"
	"github.com/usechain/go-committee/console"
)

func main() {
	// Start whisper node
	go wnode.Wnode()

	// Start committee service
	go node.Start()

	// Start console service
	con := console.New(&node.GlobalConfig)
	con.Start()
}
