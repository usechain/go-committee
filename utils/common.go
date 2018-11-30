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

package utils

//Return the n's binary and digits array
func BitCount(n int) (int, []int){
	var bitArray []int
	count, t := 0, 0
	for n != 0 {
		t = n
		n &= n - 1
		bitArray = append(bitArray, t - n)
		count++
	}
	return count, bitArray
}

//Expand One-dimensional array to Two-dimensional
func expandStringArray(m []string) [][]string {
	var t [][]string = make([][]string, len(m))

	for i := range m {
		t[i] = append(t[i], m[i])
	}
	return t
}

/**
 * Combine the string array
 * for [["a", "b"], ["c", "d"]] && ["x", "y"]
 * transform to
 * [["a", "b", "x"], ["a", "b", "y"], ["c", "d", "x"], ["c", "d", "y"]]
**/
func randomCombineSet(m [][]string, n []string) [][]string {
	var t [][]string = make([][]string, len(m)*len(n))
	var tmp []string = make([]string, len(n))
	var index int

	for i := range m {
		for j := range n {
			index = i * len(n) + j
			copy(tmp, m[i])
			if len(tmp) == len(m[i]) {
				t[index] = append(tmp, n[j])
			} else {
				t[index] = append(m[i], n[j])
			}

		}
	}
	return t
}

/**
 * Return all possible arrangement for select one item in a line
 * example:
 *   [["a", "b"],
 *    ["c", "d"]]  =====>[["a", "c"], ["a", "d"], ["b", "c"], ["b", "d"]]
**/
func PermutationStrings(m [][]string) [][]string {
	count := len(m)
	if 1 == count {
		return expandStringArray(m[0])
	}
	var t [][]string = make([][]string, count-1)
	copy(t, m[:count-1])
	r := randomCombineSet(PermutationStrings(t), m[count-1])
	return r
}

