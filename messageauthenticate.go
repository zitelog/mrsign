/*
 * File: messageauthenticate.go
 * Project: mrsign
 * Created Date: Tuesday, October 19th 2021, 12:16:54 pm
 * Authors: Marcello Russo, Fabio Zito
 * -----
 * Last Modified:
 * Modified By:
 * -----
 * MIT License
 *
 * Copyright (c) 2021 MR&&Z
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * -----
 * HISTORY:
 * Date      	By	Comments
 * ----------	---	----------------------------------------------------------
 */

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const _clientChallengeLen = 64

type MessageFieldsAuthenticate struct {
	Headers
	Hash      VarField
	UUId      VarField
	Timestamp VarField
	//HostName          VarField
	//FolderName        VarField
	_     [8]byte
	Flags FlagsNegotiate
}

type MessageAuthenticate struct {
	Hash []byte
	UUId []byte
	//HostName          string
	//FolderName        string
	Timestamp       []byte
	ClientChallenge []byte
	NegotiateFlags  FlagsNegotiate
	Fields          MessageFieldsAuthenticate
}

func NewMessageAuthenticate() *MessageAuthenticate {
	return &MessageAuthenticate{}
}

func (am *MessageAuthenticate) Marshal() ([]byte, error) {
	if !am.NegotiateFlags.Has(negotiateFlagNEGOTIATEUNICODE) {
		return nil, errors.New("only unicode is supported")
	}

	ptr := binary.Size(&MessageFieldsAuthenticate{})
	am.Fields = MessageFieldsAuthenticate{
		Headers:   NewHeaders(3),
		Flags:     am.NegotiateFlags,
		Hash:      NewVarField(&ptr, len(am.Hash)),
		UUId:      NewVarField(&ptr, len(am.UUId)),
		Timestamp: NewVarField(&ptr, len(am.Timestamp)),
	}

	am.Fields.Flags.Unset(negotiateFlagNEGOTIATEVERSION)

	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &am.Fields); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &am.Hash); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &am.UUId); err != nil {
		return nil, err
	}
	if err := binary.Write(&b, binary.LittleEndian, &am.Timestamp); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (am *MessageAuthenticate) UnMarshal(data []byte) error {
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.LittleEndian, &am.Fields)
	if err != nil {
		return err
	}
	if !am.Fields.IsValid() {
		return fmt.Errorf("message is not a valid authenticate message: %+v", am.Fields.Headers)
	}
	am.NegotiateFlags = am.Fields.Flags
	if am.Fields.Hash.Len > 0 {
		if am.Hash, err = am.Fields.Hash.ReadFrom(data); err != nil {
			return err
		}
	}
	if am.Fields.UUId.Len > 0 {
		if am.UUId, err = am.Fields.UUId.ReadFrom(data); err != nil {
			return err
		}
	}
	//if am.Fields.HostName.Len > 0 {
	//	if am.HostName, err = am.Fields.HostName.ReadStringFrom(data); err != nil {
	//		return err
	//	}
	//}
	//if am.Fields.FolderName.Len > 0 {
	//	if am.FolderName, err = am.Fields.FolderName.ReadStringFrom(data); err != nil {
	//		return err
	//	}
	//}
	return nil
}

func (am *MessageAuthenticate) Build(cm *MessageChallenge) error {
	am.NegotiateFlags = cm.Fields.Flags

	am.Timestamp = cm.TargetInfo[avIDMsvAvTimestamp]
	if am.Timestamp == nil {
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000
		am.Timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(am.Timestamp, ft)
	}
	am.ClientChallenge = make([]byte, _clientChallengeLen)
	_, _ = rand.Reader.Read(am.ClientChallenge)

	//hasher := NewHasherZ()
	//hash := hasher.CreateHash(am.Key, am.UserName, am.HostName, am.FolderName)
	//am.ChallengeResponse = hasher.CreateResponse(hash, cm.Fields.ServerChallenge[:], am.ClientChallenge, am.Timestamp)
	return nil
}
