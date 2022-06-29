// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package commitments contains common type definitions and functions used by other
// packages. Types that can cause circular import should be added here.
package commitments

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Use a constant key of zero to obtain consistent test vectors.
// Real commitment library MUST use random keys.
var zeroKey = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func TestCommit(t *testing.T) {
	for _, tc := range []struct {
		userID, data   string
		muserID, mdata string
		mutate         bool
		want           error
	}{
		{"foo", "bar", "foo", "bar", false, nil},
		{"foo", "bar", "fo", "obar", false, ErrInvalidCommitment},
		{"foo", "bar", "foob", "ar", false, ErrInvalidCommitment},
	} {
		data := []byte(tc.data)
		c := Commit(tc.userID, data, zeroKey)
		if tc.mutate {
			c[0] ^= 1
		}
		if got := Verify(tc.muserID, c, data, zeroKey); got != tc.want {
			t.Errorf("Verify(%v, %x, %x, %x): %v, want %v", tc.userID, c, data, zeroKey, got, tc.want)
		}
	}
}

func TestVectors(t *testing.T) {
	for _, tc := range []struct {
		userID, data string
		want         []byte
	}{
		{"", "", dh("dda03a79f4f00b914a7b79aa7b5e670209f93b1d9624dba231d3eeea38b0831c")},
		{"foo", "bar", dh("ad5771618dae3d9edf46b26ed4f901cfa7e2bfc6c43d761dad47189a8d343191")},
		{"foo1", "bar", dh("cc84d26cb9aa305dec2a37905a11dd37bbd078130c099aa5f69a3fd594d2849c")},
		{"foo", "bar1", dh("3da0c9b27d1113cde53341a561c0d479f915848cd49b61a16bd4c19179ba3f4b")},
	} {
		data := []byte(tc.data)
		if got, want := Commit(tc.userID, data, zeroKey), tc.want; !bytes.Equal(got, want) {
			t.Errorf("Commit(%v, %v): %x ,want %x", tc.userID, tc.data, got, want)
		}
	}
}

// Hex to Bytes
func dh(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic("DecodeString failed")
	}
	return result
}
