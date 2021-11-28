/*
 * File: server.go
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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	apiChallenge = "/v1/api/challenge"
	apiRetrieve  = "/v1/api/retrieve/"
)

type Server struct {
	server          *http.Server
	cfg             *Config
	users           map[string]UserConfig
	mutex           sync.RWMutex
	store           map[string]string
	serverStoreFile string
}

func NewServer(cfg *Config) *Server {
	fmt.Println("FolderName:", cfg.ServerStoreFilePath)
	var mux = http.NewServeMux()
	var s = &Server{
		cfg:             cfg,
		store:           make(map[string]string),
		serverStoreFile: cfg.ServerStoreFilePath + string(os.PathSeparator) + ServerStoreFile,
	}
	s.server = &http.Server{
		Addr:    cfg.Listen,
		Handler: mux,

		//WriteTimeout: time.Duration(writeTimeout) * time.Second,
		//ReadTimeout:  time.Duration(readTimeout) * time.Second,
	}

	var authenticator = s.noAuthHandler
	if s.cfg.Users.Enable {
		authenticator = s.basicAuthHandler
		s.users = make(map[string]UserConfig)
		for _, user := range cfg.Users.Accounts {
			s.users[user.User] = user
		}
	}

	mux.HandleFunc(apiChallenge, authenticator(s.challengeHandler))
	mux.HandleFunc(apiRetrieve, authenticator(s.retrieveHandler))
	if r, err := ioutil.ReadFile(s.serverStoreFile); err == nil {
		_ = json.Unmarshal(r, &s.store)
	}

	return s
}

func (api *Server) Start() error {
	var err error
	if api.cfg.Secure.Enable {
		err = api.server.ListenAndServeTLS(api.cfg.Secure.Cert, api.cfg.Secure.Key)
	} else {
		err = api.server.ListenAndServe()
	}
	return err
}

func (api *Server) serveHTTP(h http.HandlerFunc, w http.ResponseWriter, r *http.Request) {
	var err error

	defer func() {
		var r = recover()
		if r != nil {
			switch t := r.(type) {
			case string:
				err = errors.New(t)
			case error:
				err = t
			default:
				err = errors.New("unknown error")
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}()
	h.ServeHTTP(w, r)
}

func (api *Server) verifyAccount(account string, password string) bool {
	var ret = false
	if user, ok := api.users[account]; ok {
		var hash = GenerateHash(password)
		if user.Hash == hash {
			ret = true
		}
	}
	return ret
}

func (api *Server) noAuthHandler(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		api.serveHTTP(h, w, r)
	}
}

func (api *Server) basicAuthHandler(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		var username, password, ok = r.BasicAuth()
		if !ok {
			http.Error(w, "unsupported authorization", http.StatusUnauthorized)
			return
		}
		if ok = api.verifyAccount(username, password); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		api.serveHTTP(h, w, r)
	}
}

func (api *Server) challengeHandler(w http.ResponseWriter, request *http.Request) {
	reqNegotiateBody, err := ioutil.ReadAll(request.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resNegotiate := NewMessageNegotiate()
	err = resNegotiate.Unmarshal(reqNegotiateBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var store ServerStore
	store.Key = resNegotiate.CreateKey()
	if _, ok := api.retrieve(store.Key); ok {
		http.Error(w, "already exists", http.StatusConflict)
		return
	}
	store.User = resNegotiate.UserName
	store.HostName = resNegotiate.HostName
	store.Path = resNegotiate.FolderName
	store.Timestamp = api.createTimestamp()
	store.ServerChallenge = api.createChallenge(_serverChallengeLen)

	hasher := NewHasherZ()

	hash := hasher.CreateHash([]byte(resNegotiate.Hash), resNegotiate.UserName, resNegotiate.HostName, resNegotiate.FolderName)

	store.Result = hasher.CreateResponse(hash, []byte(store.ServerChallenge), []byte(resNegotiate.ClientChallenge), []byte(store.Timestamp))

	fmt.Println("--------------------------------")
	fmt.Println("Hash:", resNegotiate.Hash)
	fmt.Println("UserName:", resNegotiate.UserName)
	fmt.Println("HostName:", resNegotiate.HostName)
	fmt.Println("FolderName:", resNegotiate.FolderName)
	fmt.Println("hash:", hex.EncodeToString(hash))
	fmt.Println("FolderName:", api.serverStoreFile)

	api.save(store.Key, store)
}

func (api *Server) retrieveHandler(w http.ResponseWriter, request *http.Request) {
	reqNegotiateBody, err := ioutil.ReadAll(request.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resNegotiate := NewMessageNegotiate()
	err = resNegotiate.Unmarshal(reqNegotiateBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := resNegotiate.CreateKey()
	store, ok := api.retrieve(key)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	hasher := NewHasherZ()
	hash := hasher.CreateHash([]byte(resNegotiate.Hash), resNegotiate.UserName, resNegotiate.HostName, resNegotiate.FolderName)
	result := hasher.CreateResponse(hash, []byte(store.ServerChallenge), []byte(resNegotiate.ClientChallenge), []byte(store.Timestamp))

	//fmt.Println("--------------------------------")
	//fmt.Println("Hash:", resNegotiate.Hash)
	//fmt.Println("UserName:", resNegotiate.UserName)
	//fmt.Println("HostName:", resNegotiate.HostName)
	//fmt.Println("FolderName:", resNegotiate.FolderName)
	//fmt.Println("hash:", hex.EncodeToString(hash))

	if bytes.Compare(result, store.Result) != 0 {
		http.Error(w, "different signature", http.StatusForbidden)
		return
	}
}

func (api *Server) save(key string, store ServerStore) {
	data, _ := json.Marshal(store)
	api.mutex.Lock()
	api.store[key] = string(data)
	out, _ := json.Marshal(api.store)
	fmt.Println("FolderName:", api.serverStoreFile)
	_ = ioutil.WriteFile(api.serverStoreFile, out, 0644)
	api.mutex.Unlock()
}

func (api *Server) retrieve(key string) (ServerStore, bool) {
	var store ServerStore
	api.mutex.RLock()
	data, ok := api.store[key]
	if ok {
		_ = json.Unmarshal([]byte(data), &store)
	}
	api.mutex.RUnlock()
	return store, ok
}

func (api *Server) createTimestamp() string {
	ft := uint64(time.Now().UnixNano()) / 100
	ft += 116444736000000000
	timestamp := make([]byte, _timestampLen)
	binary.LittleEndian.PutUint64(timestamp, ft)
	return hex.EncodeToString(timestamp)
}

func (api *Server) createChallenge(len int) string {
	challenge := make([]byte, len)
	_, _ = rand.Reader.Read(challenge)
	return hex.EncodeToString(challenge)
}
