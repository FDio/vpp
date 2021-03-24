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
	"log"
	"log/syslog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"git.fd.io/govpp.git/adapter/statsclient"
	"git.fd.io/govpp.git/core"
	"github.com/hanwen/go-fuse/v2/fs"
)

func main() {
	syslogger, err := syslog.New(syslog.LOG_ERR|syslog.LOG_DAEMON, "statsfs")
	if err != nil {
		log.Fatalln(err)
	}
	log.SetOutput(syslogger)

	statsSocket := flag.String("socket", statsclient.DefaultSocketName, "Path to VPP stats socket")
	debug := flag.Bool("debug", false, "print debugging messages.")
	flag.Parse()

	if flag.NArg() < 1 {
		msg := fmt.Sprintf("usage: %s MOUNTPOINT\n", os.Args[0])
		fmt.Fprint(os.Stderr, msg)
		log.Print(msg)
		os.Exit(2)
	}
	//Conection to the stat segment socket.
	sc := statsclient.NewStatsClient(*statsSocket)
	fmt.Println("Waiting for the VPP socket to be available. Be sure a VPP instance is running.")
	c, err := core.ConnectStats(sc)
	if err != nil {
		msg := fmt.Sprintf("Failed to connect to the stats socket: %v\n", err)
		fmt.Fprint(os.Stderr, msg)
		log.Print(msg)
		os.Exit(1)
	}
	defer c.Disconnect()
	fmt.Printf("Connected to the socket\n")
	//Creating the filesystem instance
	root, err := NewStatsFileSystem(sc)
	if err != nil {
		msg := fmt.Sprintf("NewStatsFileSystem failed: %v\n", err)
		fmt.Fprint(os.Stderr, msg)
		log.Print(msg)
		os.Exit(1)
	}

	//Mounting the filesystem.
	opts := &fs.Options{}
	opts.Debug = *debug
	opts.AllowOther = true
	server, err := fs.Mount(flag.Arg(0), root, opts)
	if err != nil {
		msg := fmt.Sprintf("Mount fail: %v\n", err)
		fmt.Fprint(os.Stderr, msg)
		log.Print(msg)
		os.Exit(1)
	}

	sigs := make(chan os.Signal)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("Successfully mounted the file system in directory: %s\n", flag.Arg(0))
	runtime.GC()

	for {
		go server.Wait()

		<-sigs
		fmt.Println("Unmounting...")
		err := server.Unmount()
		if err == nil || !strings.Contains(err.Error(), "Device or resource busy") {
			break
		}
		msg := fmt.Sprintf("Unmount fail: %v\n", err)
		log.Print(msg)
		fmt.Fprint(os.Stderr, msg)
	}
}
