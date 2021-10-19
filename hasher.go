/*
 * File: hasher.go
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
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"
)

type avID uint16

const (
	avIDMsvAvEOL avID = iota
	avIDMsvAvTimestamp
)

var _hasherZBlob = []byte{1, 1, 0, 0}
var _hasherZReserved = []byte{0, 0, 0, 0}

type ChallengeFields struct {
	HasherZ         [16]byte
	Blob            [4]byte
	Reserved        [4]byte
	Timestamp       [8]byte
	ClientChallenge [_clientChallengeLen]byte
}

type HasherZ struct {
	Field ChallengeFields
}

func NewHasherZ() *HasherZ {
	return &HasherZ{}
}

func (z *HasherZ) Parse(data []byte) error {
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.LittleEndian, &z.Field)
	if err != nil {
		return err
	}
	return nil
}

func (z *HasherZ) CreateHash(key []byte, userName string, hostName string, folderName string) []byte {
	data := toUnicode(strings.ToUpper(userName) + strings.ToUpper(hostName) + folderName)
	return z.hmacMd5(key, data)
}

func (z *HasherZ) CreateResponse(hash, serverChallenge []byte, clientChallenge []byte, timestamp []byte) []byte {
	var temp []byte
	//z.printData("serverChallenge", serverChallenge)
	//z.printData("clientChallenge", clientChallenge)
	//z.printData("timestamp", timestamp)

	temp = append(temp, _hasherZBlob...)
	temp = append(temp, _hasherZReserved...)
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, _hasherZReserved...)

	res := z.hmacMd5(hash, serverChallenge, temp)
	return append(res, temp...)
}

func (z *HasherZ) hmacMd5(key []byte, data ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, d := range data {
		mac.Write(d)
	}
	return mac.Sum(nil)
}

func (z *HasherZ) printData(id string, buffer []byte) {
	fmt.Printf("----- %s --------------------------\n", id)
	fmt.Printf("%x\n", buffer)
	fmt.Printf("-----------------------------------\n")
}
