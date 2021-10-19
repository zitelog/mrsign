/*
 * File: messagechallenge.go
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
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"time"
)

const _serverChallengeLen = 64
const _saltLen = 8
const _timestampLen = 8

type MessageFieldsChallenge struct {
	Headers
	Flags           FlagsNegotiate
	UUID            [24]byte
	ServerChallenge [_serverChallengeLen]byte
	_               [8]byte
	TargetInfo      VarField
}

func (m MessageFieldsChallenge) IsValid() bool {
	return m.Headers.IsValid() && m.MessageType == 2
}

type MessageChallenge struct {
	Fields        MessageFieldsChallenge
	TargetInfo    map[avID][]byte
	TargetInfoRaw []byte
}

func NewMessageChallenge() *MessageChallenge {
	return &MessageChallenge{}
}

func (cm *MessageChallenge) Unmarshal(data []byte) error {
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.LittleEndian, &cm.Fields)
	if err != nil {
		return err
	}
	if !cm.Fields.IsValid() {
		return fmt.Errorf("message is not a valid challenge message: %+v", cm.Fields.Headers)
	}
	if cm.Fields.TargetInfo.Len > 0 {
		d, err := cm.Fields.TargetInfo.ReadFrom(data)
		cm.TargetInfoRaw = d
		if err != nil {
			return err
		}
		cm.TargetInfo = make(map[avID][]byte)
		r := bytes.NewReader(d)
		for {
			var id avID
			var l uint16
			err = binary.Read(r, binary.LittleEndian, &id)
			if err != nil {
				return err
			}
			if id == avIDMsvAvEOL {
				break
			}
			err = binary.Read(r, binary.LittleEndian, &l)
			if err != nil {
				return err
			}
			value := make([]byte, l)
			n, err := r.Read(value)
			if err != nil {
				return err
			}
			if n != int(l) {
				return fmt.Errorf("expected to read %d bytes, got only %d", l, n)
			}
			cm.TargetInfo[id] = value
		}
	}

	return nil
}

func (cm *MessageChallenge) Marshal() ([]byte, error) {
	targetInfoLen := 0
	if cm.TargetInfo != nil {
		for id, val := range cm.TargetInfo {
			size := uint16(binary.Size(val))
			targetInfoLen += binary.Size(id)
			targetInfoLen += binary.Size(size)
			targetInfoLen += binary.Size(val)
		}
		targetInfoLen += binary.Size(avIDMsvAvEOL)
	}
	ptr := binary.Size(&MessageFieldsChallenge{})
	cm.Fields = MessageFieldsChallenge{
		Headers:         NewHeaders(2),
		Flags:           cm.Fields.Flags,
		UUID:            cm.Fields.UUID,
		ServerChallenge: cm.Fields.ServerChallenge,
		TargetInfo:      NewVarField(&ptr, targetInfoLen),
	}
	b := bytes.Buffer{}
	if err := binary.Write(&b, binary.LittleEndian, &cm.Fields); err != nil {
		return nil, err
	}
	if cm.TargetInfo != nil {
		raw := bytes.Buffer{}
		for id, val := range cm.TargetInfo {
			size := uint16(binary.Size(val))
			if err := binary.Write(&raw, binary.LittleEndian, &id); err != nil {
				return nil, err
			}
			if err := binary.Write(&raw, binary.LittleEndian, &size); err != nil {
				return nil, err
			}
			if err := binary.Write(&raw, binary.LittleEndian, &val); err != nil {
				return nil, err
			}
		}
		eof2 := avIDMsvAvEOL
		if err := binary.Write(&raw, binary.LittleEndian, &eof2); err != nil {
			return nil, err
		}
		cm.TargetInfoRaw = raw.Bytes()
		if err := binary.Write(&b, binary.LittleEndian, &cm.TargetInfoRaw); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

func (cm *MessageChallenge) Build(nm *NegotiateMessage) error {
	cm.Fields.Flags = nm.Fields.Flags
	cm.Fields.Flags.Set(negotiateFlagNEGOTIATEUNICODE)

	cm.Fields.UUID = NextUUID()

	salt := make([]byte, _saltLen)
	_, _ = rand.Reader.Read(salt)
	h := sha512.New()

	targetName := nm.HostName + nm.UserName + nm.FolderName
	h.Write([]byte(targetName + fmt.Sprintf("%x", salt)))
	serverChallenge := h.Sum(nil)
	for b := 0; b < _serverChallengeLen; b++ {
		if b < len(serverChallenge) {
			cm.Fields.ServerChallenge[b] = serverChallenge[b]
		}
	}

	ft := uint64(time.Now().UnixNano()) / 100
	ft += 116444736000000000
	timestamp := make([]byte, _timestampLen)
	binary.LittleEndian.PutUint64(timestamp, ft)
	cm.TargetInfo = make(map[avID][]byte)
	cm.TargetInfo[avIDMsvAvTimestamp] = timestamp
	return nil
}
