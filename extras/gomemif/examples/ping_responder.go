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

        "memif"
        "github.com/pkg/profile"
)

func Connected(e *memif.Endpoint) error {
        // FIXME: imprive packet polling
        go func() {
                pkt := make([]byte, 2048)
                rxq0, err := e.GetRxQueue(0)
                if err != nil {
                        fmt.Println(e.GetName(), ": GetRxQueue: ", err)
                        return
                }
                txq0, err := e.GetTxQueue(0)
                if err != nil {
                        fmt.Println(e.GetName(), ": GetTxQueue: ", err)
                        return
                }
                for {
                        pktLen, err := rxq0.ReadPacket(pkt)
                        if pktLen > 0 {
                                txq0.WritePacket(pkt[:pktLen])
                        } else if err != nil {
                                fmt.Println(err)
                                return
                        }
                }
        }()
        return nil
}

func main () {
        defer profile.Start(profile.CPUProfile, profile.ProfilePath("/vpp/extras/gomemif")).Stop()

        fmt.Println("GoMemif: Ping Responder")
        fmt.Println("-----------------------")

        socket, err := memif.NewSocket("")
        if err != nil {
                fmt.Println("Failed to create socket: %s", err)
                return
        }

        args := &memif.Arguments{
                IsMaster: true,
                Connected: Connected,
                Name: "gomemif_endpoint",
        }
        e, err := socket.NewEndpoint(args)
        if err != nil {
                fmt.Println("Failed to create endpoint on socket %s: %s", socket.GetFilename(), err)
                return
        }

        // FIXME: improve event polling
        socket.StartPolling()

        reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("gomemif# ")
		text, _ := reader.ReadString('\n')

		// convert CRLF to LF
    		text = strings.Replace(text, "\n", "", -1)

		switch text {
		case "show":
			fmt.Println("remote: ", e.GetRemoteName())
                        fmt.Println("peer: ", e.GetPeerName())
		case "exit":
			goto exit
		default:
			fmt.Println("Unknown input")
		}
	}
exit:
        fmt.Println("Exiting")
}
