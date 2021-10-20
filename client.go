/*
 * File: client.go
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
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

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

/*
func getIps() ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				out = append(out, ipNet.IP.String())
			}
		}
	}
	return out, nil
}
*/

type Client struct {
	urlChallenge    string
	urlRetrieve     string
	path            string
	storeFile       string
	serverStoreFile string
}

func NewClient(server string, path string, clientStoreFile string, serverStoreFilePath string) *Client {
	if len(clientStoreFile) == 0 {
		clientStoreFile = ClientStoreFile
	}

	return &Client{
		urlChallenge:    server + apiChallenge,
		urlRetrieve:     server + apiRetrieve,
		path:            path,
		storeFile:       path + string(os.PathSeparator) + clientStoreFile,
		serverStoreFile: serverStoreFilePath + string(os.PathSeparator) + clientStoreFile,
	}
}

func (c *Client) Generate(user string, _ string, hostname string) error {
	reqNegotiate := NewMessageNegotiate()
	reqNegotiate.UserName = user
	reqNegotiate.HostName = hostname
	reqNegotiate.FolderName = c.path

	out := NewClientStore()
	out.User = user
	out.HostName = hostname
	out.Path = c.path
	out.ClientChallenge = reqNegotiate.ClientChallenge

	if err := c.saveStore(out); err != nil {
		return err
	}

	folderHash, err := c.createFolderHash()
	if err != nil {
		_ = os.Remove(c.storeFile)
		return err
	}

	reqNegotiate.Hash = folderHash

	reqNegotiateBody, err := reqNegotiate.Marshal()
	if err != nil {
		_ = os.Remove(c.storeFile)
		return err
	}

	buf := bytes.NewReader(reqNegotiateBody)
	resp, err := http.Post(c.urlChallenge, "application/octet-stream", buf)
	if err != nil {
		_ = os.Remove(c.storeFile)
		return err
	}
	var reqChallengeBody []byte
	if resp.Body != nil {
		if reqChallengeBody, err = ioutil.ReadAll(resp.Body); err != nil {
			_ = os.Remove(c.storeFile)
			return err
		}
	}
	if resp.StatusCode != 200 {
		_ = os.Remove(c.storeFile)
		if resp.StatusCode == 409 {
			return errors.New("already exists")
		}
		return errors.New("invalid status code: " + string(reqChallengeBody))
	}
	return nil
}

func (c *Client) Exists() bool {
	exists := false
	if a, e := os.Stat(c.storeFile); e == nil {
		if !a.IsDir() {
			exists = true
		}
	}
	return exists
}

func (c *Client) Restore() error {
	store, err := c.loadStore()
	if err != nil {
		return err
	}
	folderHash, err := c.createFolderHash()
	if err != nil {
		return err
	}
	reqNegotiate := NewMessageNegotiate()
	reqNegotiate.UserName = store.User
	reqNegotiate.HostName = store.HostName
	reqNegotiate.FolderName = store.Path
	reqNegotiate.Hash = folderHash
	reqNegotiate.ClientChallenge = store.ClientChallenge

	reqNegotiateBody, err := reqNegotiate.Marshal()
	if err != nil {
		return err
	}
	buf := bytes.NewReader(reqNegotiateBody)
	resp, err := http.Post(c.urlRetrieve, "application/octet-stream", buf)
	if err != nil {
		return err
	}
	var reqChallengeBody []byte
	if resp.Body != nil {
		if reqChallengeBody, err = ioutil.ReadAll(resp.Body); err != nil {
			return err
		}
	}
	if resp.StatusCode != 200 {
		return errors.New("invalid status code: " + string(reqChallengeBody))
	}
	return nil
}

func (c *Client) saveStore(store *ClientStore) error {
	pr, _ := json.MarshalIndent(store, "", "\t")
	return ioutil.WriteFile(c.storeFile, pr, 0644)
}

func (c *Client) loadStore() (*ClientStore, error) {
	body, err := ioutil.ReadFile(c.storeFile)
	if err != nil {
		return nil, err
	}
	store := NewClientStore()
	err = json.Unmarshal(body, store)
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (c *Client) createFolderHash() (string, error) {
	return HashDir(c.path, "", []string{c.serverStoreFile}, Hash256)
}
