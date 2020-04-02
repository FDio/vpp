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
        "fmt"
        "bufio"
        "os"
        "strings"
        "flag"
        "sync"

        "memif"
        "github.com/pkg/profile"
)

/* TODO: Interface status
 *       1. notify goroutine that interface was disconnected
 *       2. wait for the goroutine to finish (maybe timeout)
 *       3. munmap memory
 *       4. hope it won't crash...
 */

func Disconnected(e *memif.Endpoint) error {
        fmt.Println("Disconnected: ", e.GetName())

        data, ok := e.GetPrivateData().(*data)
        if !ok {
                return fmt.Errorf("Invalid private data")
        }
        close(data.quitChan) // stop polling
        close(data.errChan)
        data.wg.Wait() // wait until polling stops, then continue disconnect

        return nil
}

func Connected(e *memif.Endpoint) error {
        fmt.Println("Connected: ", e.GetName())

        data, ok := e.GetPrivateData().(*data)
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
                rxq0, err := e.GetRxQueue(0)
                if err != nil {
                        errChan <- err
                        return
                }
                // get tx queue
                txq0, err := e.GetTxQueue(0)
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

type data struct {
        errChan chan error
        quitChan chan struct{}
        wg sync.WaitGroup
}

func main () {
        defer profile.Start(profile.CPUProfile, profile.ProfilePath("/vpp/extras/gomemif")).Stop()

        role := flag.String("role", "slave", "endpoint role")
        flag.Parse()

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

        fmt.Println("GoMemif: Ping Responder")
        fmt.Println("-----------------------")

        socket, err := memif.NewSocket("")
        if err != nil {
                fmt.Println("Failed to create socket: ", err)
                return
        }

        data := data{}
        args := &memif.Arguments{
                IsMaster: isMaster,
                ConnectedFunc: Connected,
                DisconnectedFunc: Disconnected,
                PrivateData: &data,
                Name: "gomemif",
        }
        e, err := socket.NewEndpoint(args)
        if err != nil {
                fmt.Println("Failed to create endpoint on socket %s: %s", socket.GetFilename(), err)
                return
        }

        memifErrChan := make(chan error)
        exit := make(chan struct{})
        go func(exit chan<- struct{}) {
                reader := bufio.NewReader(os.Stdin)
                for {
                        fmt.Print("gomemif# ")
                        text, _ := reader.ReadString('\n')
                        // convert CRLF to LF
            		text = strings.Replace(text, "\n", "", -1)
                        switch text {
                        case "start":
                                socket.StartPolling(memifErrChan)
        		case "show":
        			fmt.Println("remote: ", e.GetRemoteName())
                                fmt.Println("peer: ", e.GetPeerName())
        		case "exit":
                                err = socket.StopPolling()
                                if err != nil {
                                        fmt.Println("Failed to stop polling: ", err)
                                }
        			close(exit)
                                return
        		default:
        			fmt.Println("Unknown input")
        		}
                }
        }(exit)

	for {
                select {
                case <-exit:
                        goto exit
                case err, ok := <-memifErrChan:
                        if ok {
                                fmt.Println(err)
                        }
                case err, ok := <-data.errChan:
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
