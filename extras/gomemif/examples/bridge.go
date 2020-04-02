/*
 *------------------------------------------------------------------
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/profile"
	"memif"
)

func Disconnected(i *memif.Interface) error {
	fmt.Println("Disconnected: ", i.GetName())

	data, ok := i.GetPrivateData().(*interfaceData)
	if !ok {
		return fmt.Errorf("Invalid private data")
	}
	close(data.quitChan) // stop polling
	close(data.errChan)
	data.wg.Wait() // wait until polling stops, then continue disconnect

	return nil
}

func Connected(i *memif.Interface) error {
	fmt.Println("Connected: ", i.GetName())

	data, ok := i.GetPrivateData().(*interfaceData)
	if !ok {
		return fmt.Errorf("Invalid private data")
	}
	data.errChan = make(chan error, 1)
	data.quitChan = make(chan struct{}, 1)
	data.wg.Add(1)

	go func(errChan chan<- error, quitChan <-chan struct{}, wg *sync.WaitGroup) {
		defer wg.Done()
		// allocate packet buffer
		pkt := make([]byte, 2048)
		// get rx queue
		rxq0, err := i.GetRxQueue(0)
		if err != nil {
			errChan <- err
			return
		}

		// wait until both interfaces are connected
		for !data.bri.IsConnected() {
			time.Sleep(100 * time.Millisecond)
		}

		// get bridged interfaces tx queue
		txq0, err := data.bri.GetTxQueue(0)
		if err != nil {
			errChan <- err
			return
		}
		for {
			select {
			case <-quitChan: // channel closed
				return
			default:
				// read packet from shared memory
				pktLen, err := rxq0.ReadPacket(pkt)
				if pktLen > 0 {
					// FIXME: prevent packet write if interface is disconencted
					// write packet to shared memory
					txq0.WritePacket(pkt[:pktLen])
				} else if err != nil {
					errChan <- err
					return
				}
			}
		}
	}(data.errChan, data.quitChan, &data.wg)

	return nil
}

type interfaceData struct {
	errChan  chan error
	quitChan chan struct{}
	wg       sync.WaitGroup
	// bridged interface
	bri *memif.Interface
}

func interractiveHelp() {
	fmt.Println("help - print this help")
	fmt.Println("start - start connecting loop")
	fmt.Println("show - print interface details")
	fmt.Println("exit - exit the application")
}

func newMemifInterface(socket *memif.Socket, id uint32, isMaster bool, name string) (*memif.Interface, *interfaceData, error) {
	data := &interfaceData{}
	args := &memif.Arguments{
		Id:               id,
		IsMaster:         isMaster,
		ConnectedFunc:    Connected,
		DisconnectedFunc: Disconnected,
		PrivateData:      data,
		Name:             name,
	}

	i, err := socket.NewInterface(args)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to create interface on socket %s: %s", socket.GetFilename(), err)
	}

	// slave attempts to connect to control socket
	// to handle control communication call socket.StartPolling()
	if !i.IsMaster() {
		fmt.Println(args.Name, ": Connecting to control socket...")
		for !i.IsConnecting() {
			err = i.RequestConnection()
			if err != nil {
				/* TODO: check for ECONNREFUSED errno
				 * if error is ECONNREFUSED it may simply mean that master
				 * interface is not up yet, use i.RequestConnection()
				 */
				return nil, nil, fmt.Errorf("Faild to connect: ", err)
			}
		}
	}

	return i, data, nil
}

func printMemifInterfaceDetails(i *memif.Interface) {
	fmt.Println(i.GetName(), ":")
	fmt.Println("\trole: ", memif.RoleToString(i.IsMaster()))
	fmt.Println("\tid: ", i.GetId())
	link := "down"
	if i.IsConnected() {
		link = "up"
	}
	fmt.Println("\tlink: ", link)
	fmt.Println("\tremote: ", i.GetRemoteName())
	fmt.Println("\tpeer: ", i.GetPeerName())
	if i.IsConnected() {
		mc := i.GetMemoryConfig()
		fmt.Println("queue pairs: ", mc.NumQueuePairs)
		fmt.Println("ring size: ", (1 << mc.Log2RingSize))
		fmt.Println("buffer size: ", mc.PacketBufferSize)
	}
}

func main() {
	memifErrChan := make(chan error)
	exitChan := make(chan struct{})
	var i0, i1 *memif.Interface
	var d0, d1 *interfaceData

	cpuprof := flag.String("cpuprof", "", "cpu profiling output file")
	memprof := flag.String("memprof", "", "mem profiling output file")
	role := flag.String("role", "slave", "interface role")
	name := flag.String("name", "gomemif", "interface name")
	socketName := flag.String("socket", "", "control socket filename")

	flag.Parse()

	// profiling options
	if *cpuprof != "" {
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(*cpuprof)).Stop()
	}
	if *memprof != "" {
		defer profile.Start(profile.MemProfile, profile.ProfilePath(*memprof)).Stop()
	}

	// memif options
	var isMaster bool
	switch *role {
	case "slave":
		isMaster = false
	case "master":
		isMaster = true
	default:
		fmt.Println("Invalid role")
		return
	}

	// create memif socket
	socket, err := memif.NewSocket("gomemif_example", *socketName)
	if err != nil {
		fmt.Println("Failed to create socket: ", err)
		return
	}

	i0, d0, err = newMemifInterface(socket, 0, isMaster, *name)
	if err != nil {
		fmt.Println(err)
		goto exit
	}

	// TODO: update name
	i1, d1, err = newMemifInterface(socket, 1, isMaster, *name)
	if err != nil {
		fmt.Println(err)
		goto exit
	}

	// set up bridge
	d0.bri = i1
	d1.bri = i0

	// user input goroutine
	go func(exitChan chan<- struct{}) {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("GoMemif: Responder")
		fmt.Println("-----------------------")
		for {
			fmt.Print("gomemif# ")
			text, _ := reader.ReadString('\n')
			// convert CRLF to LF
			text = strings.Replace(text, "\n", "", -1)
			switch text {
			case "help":
				interractiveHelp()
			case "start":
				// start polling for events on this socket
				socket.StartPolling(memifErrChan)
			case "show":
				printMemifInterfaceDetails(i0)
				printMemifInterfaceDetails(i1)
			case "exit":
				err = socket.StopPolling()
				if err != nil {
					fmt.Println("Failed to stop polling: ", err)
				}
				close(exitChan)
				return
			default:
				fmt.Println("Unknown input")
			}
		}
	}(exitChan)

	// main loop
	for {
		select {
		case <-exitChan:
			goto exit
		case err, ok := <-memifErrChan:
			if ok {
				fmt.Println(err)
			}
		case err, ok := <-d0.errChan:
			if ok {
				fmt.Println(err)
			}
		case err, ok := <-d1.errChan:
			if ok {
				fmt.Println(err)
			}
		default:
			continue
		}
	}

exit:
	socket.Delete()
	close(memifErrChan)
}
