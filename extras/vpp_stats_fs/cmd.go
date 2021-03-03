/*
 * Copyright (c) 2021 Cisco Systems and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright 2016 the Go-FUSE Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

// This file is the main program driver to mount the stats segment filesystem.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"git.fd.io/govpp.git/adapter/statsclient"
	"git.fd.io/govpp.git/core"
	"github.com/hanwen/go-fuse/v2/fs"
)

func main() {
	statsSocket := flag.String("socket", statsclient.DefaultSocketName, "Path to VPP stats socket")
	debug := flag.Bool("debug", false, "print debugging messages.")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s MOUNTPOINT\n", os.Args[0])
		os.Exit(2)
	}
	//Conection to the stat segment socket.
	sc := statsclient.NewStatsClient(*statsSocket)
	fmt.Printf("Waiting for the VPP socket to be available. Be sure a VPP instance is running.\n")
	c, err := core.ConnectStats(sc)
	if err != nil {
		fmt.Printf("error : %v\n", err)
		fmt.Fprintf(os.Stderr, "Failed to connect to the stats socket: %v\n", err)
		os.Exit(1)
	}
	defer c.Disconnect()
	fmt.Printf("Connected to the socket\n")
	//Creating the filesystem instance
	root, err := NewStatsFileSystem(sc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewStatsFileSystem failed: %v\n", err)
		os.Exit(1)
	}

	//Mounting the filesystem.
	opts := &fs.Options{}
	opts.Debug = *debug
	opts.AllowOther = true
	server, err := fs.Mount(flag.Arg(0), root, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Mount fail: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully mounted the file system in directory: %s\n", flag.Arg(0))
	runtime.GC()
	server.Wait()
}
