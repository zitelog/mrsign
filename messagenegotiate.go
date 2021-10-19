/*
 * File: messagenegotiate.go
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
	"encoding/hex"
	"fmt"
	"strings"
)

//const expMsgBodyLen = 48
const expMsgBodyLen = 64

type MessageFieldsNegotiate struct {
	Headers
	Flags           FlagsNegotiate
	UserName        VarField
	HostName        VarField
	FolderName      VarField
	Hash            VarField
	ClientChallenge VarField
	Version
}

const defaultFlags = negotiateFlagNEGOTIATETARGETINFO | negotiateFlagNEGOTIATEUNICODE

type NegotiateMessage struct {
	UserName        string
	HostName        string
	FolderName      string
	Hash            string
	ClientChallenge string
	Fields          MessageFieldsNegotiate
}

func NewMessageNegotiate() *NegotiateMessage {
	clientChallenge := make([]byte, _clientChallengeLen)
	_, _ = rand.Reader.Read(clientChallenge)

	return &NegotiateMessage{
		ClientChallenge: hex.EncodeToString(clientChallenge),
	}
}

func (nm *NegotiateMessage) Marshal() ([]byte, error) {
	userName := strings.ToUpper(nm.UserName)
	hostName := strings.ToUpper(nm.HostName)

	payloadOffset := expMsgBodyLen
	flags := defaultFlags
	if len(nm.UserName) > 0 {
		flags |= negotiateFlagNEGOTIATEUSERNAMESUPPLIED
	}
	if len(nm.HostName) > 0 {
		flags |= negotiateFlagNEGOTIATEHOSTNAMESUPPLIED
	}
	if len(nm.FolderName) > 0 {
		flags |= negotiateFlagNEGOTIATFOLDERNAMESUPPLIED
	}

	nm.Fields = MessageFieldsNegotiate{
		Headers:         NewHeaders(1),
		Flags:           flags,
		UserName:        NewVarField(&payloadOffset, len(userName)),
		HostName:        NewVarField(&payloadOffset, len(hostName)),
		FolderName:      NewVarField(&payloadOffset, len(nm.FolderName)),
		Hash:            NewVarField(&payloadOffset, len(nm.Hash)),
		ClientChallenge: NewVarField(&payloadOffset, len(nm.ClientChallenge)),
		Version:         DefaultVersion(),
	}
	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &nm.Fields); err != nil {
		return nil, err
	}
	if _, err := b.WriteString(userName); err != nil {
		return nil, err
	}
	if _, err := b.WriteString(hostName); err != nil {
		return nil, err
	}
	if _, err := b.WriteString(nm.FolderName); err != nil {
		return nil, err
	}
	if _, err := b.WriteString(nm.Hash); err != nil {
		return nil, err
	}
	if _, err := b.WriteString(nm.ClientChallenge); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (nm *NegotiateMessage) Unmarshal(in []byte) error {
	r := bytes.NewReader(in)
	err := binary.Read(r, binary.LittleEndian, &nm.Fields)
	if err != nil {
		return err
	}
	if !nm.IsValid() {
		return fmt.Errorf("message is not a valid challenge message: %+v", nm.Fields.Headers)
	}
	if nm.Fields.UserName.Len > 0 {
		if nm.UserName, err = nm.Fields.UserName.ReadStringFrom(in); err != nil {
			return err
		}
	}
	if nm.Fields.HostName.Len > 0 {
		if nm.HostName, err = nm.Fields.HostName.ReadStringFrom(in); err != nil {
			return err
		}
	}
	if nm.Fields.FolderName.Len > 0 {
		if nm.FolderName, err = nm.Fields.FolderName.ReadStringFrom(in); err != nil {
			return err
		}
	}
	if nm.Fields.Hash.Len > 0 {
		if nm.Hash, err = nm.Fields.Hash.ReadStringFrom(in); err != nil {
			return err
		}
	}
	if nm.Fields.ClientChallenge.Len > 0 {
		if nm.ClientChallenge, err = nm.Fields.ClientChallenge.ReadStringFrom(in); err != nil {
			return err
		}
	}
	return nil
}

func (nm NegotiateMessage) CreateKey() string {
	return GenerateHash(nm.UserName + "-" + nm.HostName + "-" + nm.FolderName)
}

func (nm NegotiateMessage) IsValid() bool {
	return nm.Fields.Headers.IsValid() && nm.Fields.MessageType == 1
}
