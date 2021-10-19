/*
 * File: main.go
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
	"flag"
	"fmt"
	"os"
	"strings"
)

const defaultPort = "8123"
const defaultServer = "127.0.0.1:" + defaultPort
const defaultUrl = "http://" + defaultServer

func acquireFromStdin(label string) string {
	var def string
	fmt.Print(label)
	_, _ = fmt.Scan(&def)
	def = strings.Replace(def, "\r", "", -1)
	def = strings.Replace(def, "\n", "", -1)
	def = strings.Replace(def, "\t", "", -1)
	def = strings.TrimSpace(def)
	return def
}

func main() {
	var showHelp bool
	var showVersion bool
	var configFilePath string
	var generateHash string
	var generateKey bool
	var logFilePath string
	var challengeUrl string
	var serverStoreFilePath string
	var user string
	var host string
	var server bool
	var path string
	var clientStoreFile string

	flag.StringVar(&configFilePath, "c", "config.json", "config file")
	flag.BoolVar(&generateKey, "k", false, "generate key")
	flag.StringVar(&generateHash, "g", "", "generate hash")
	flag.StringVar(&logFilePath, "l", "", "logfile path")
	flag.BoolVar(&showHelp, "h", false, "show this help")
	flag.BoolVar(&showVersion, "v", false, "show version")
	flag.BoolVar(&server, "s", false, "start local server")
	flag.StringVar(&challengeUrl, "r", defaultUrl, "server url")
	flag.StringVar(&user, "u", "", "client user")
	flag.StringVar(&host, "t", "", "client host")
	flag.StringVar(&path, "p", "", "client path")
	flag.StringVar(&clientStoreFile, "f", "", "client store filename")
	flag.StringVar(&serverStoreFilePath, "sp", "", "server path")
	flag.Parse()

	if showHelp {
		flag.Usage()
		return
	}

	if showVersion {
		fmt.Println(MinorVersion, MinorVersion)
		return
	}

	if server {
		loader := NewLoader()
		cfg, _ := loader.Load(configFilePath)
		if len(cfg.Listen) == 0 {
			cfg.Listen = defaultServer
		}
		fmt.Printf("starting server %s\n", cfg.Listen)
		s := NewServer(cfg)
		if err := s.Start(); err != nil {
			fmt.Println(err.Error())
			return
		}
		return
	}

	if len(path) == 0 {
		path, _ = os.Getwd()
	}

	c := NewClient(challengeUrl, path, clientStoreFile, serverStoreFilePath)

	if c.Exists() {
		err := c.Restore()
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Println("Same signature")
		}
		return
	}

	if len(user) == 0 {
		fmt.Println("missing client username")
		return
	}

	if len(host) == 0 {
		fmt.Println("missing client host")
		return
	}

	//user := acquireFromStdin("Enter user: ")
	//hostname := acquireFromStdin("Enter hostname: ")
	err := c.Generate(user, "", host)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("Signature generated")
	}
}
