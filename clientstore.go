/*
 * File: clientStore.go
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

import "time"

const ClientStoreFile = "zclient.store"

type ClientStore struct {
	User            string `json:"user"`
	HostName        string `json:"hostName"`
	Path            string `json:"path"`
	ClientChallenge string `json:"clientChallenge"`
	Epoch           int64  `json:"epoch"`
}

func NewClientStore() *ClientStore {
	return &ClientStore{
		User:            "",
		HostName:        "",
		Path:            "",
		ClientChallenge: "",
		Epoch:           time.Now().Unix() / int64(time.Millisecond),
	}
}
