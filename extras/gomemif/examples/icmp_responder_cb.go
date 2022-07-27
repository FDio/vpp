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
	"net"
	"os"
	"strings"
	"sync"

	"memif"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pkg/profile"
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

func Responder(i *memif.Interface) error {
	data, ok := i.GetPrivateData().(*interfaceData)
	if !ok {
		return fmt.Errorf("Invalid private data")
	}
	data.errChan = make(chan error, 1)
	data.quitChan = make(chan struct{}, 1)
	data.wg.Add(1)

	// allocate packet buffer
	pkt := make([]byte, 2048)
	// get rx queue
	rxq0, err := i.GetRxQueue(0)
	if err != nil {
		return err
	}
	// get tx queue
	txq0, err := i.GetTxQueue(0)
	if err != nil {
		return err
	}
	for {

		// read packet from shared memory
		pktLen, err := rxq0.ReadPacket(pkt)
		_ = err
		if pktLen > 0 {
			fmt.Printf("pktLen: %d\n", pktLen)
			gopkt := gopacket.NewPacket(pkt[:pktLen], layers.LayerTypeEthernet, gopacket.NoCopy)
			etherLayer := gopkt.Layer(layers.LayerTypeEthernet)
			if etherLayer.(*layers.Ethernet).EthernetType == layers.EthernetTypeARP {
				rEth := layers.Ethernet{
					SrcMAC: net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
					DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},

					EthernetType: layers.EthernetTypeARP,
				}
				rArp := layers.ARP{
					AddrType:          layers.LinkTypeEthernet,
					Protocol:          layers.EthernetTypeIPv4,
					HwAddressSize:     6,
					ProtAddressSize:   4,
					Operation:         layers.ARPReply,
					SourceHwAddress:   []byte(net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}),
					SourceProtAddress: []byte("\xc0\xa8\x01\x01"),
					DstHwAddress:      []byte(net.HardwareAddr{0x02, 0xfe, 0x08, 0x88, 0x45, 0x7f}),
					DstProtAddress:    []byte("\xc0\xa8\x01\x02"),
				}
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				gopacket.SerializeLayers(buf, opts, &rEth, &rArp)
				// write packet to shared memory
				txq0.WritePacket(buf.Bytes())
			}

			if etherLayer.(*layers.Ethernet).EthernetType == layers.EthernetTypeIPv4 {
				ipLayer := gopkt.Layer(layers.LayerTypeIPv4)
				if ipLayer == nil {
					fmt.Println("Missing IPv4 layer.")

				}
				ipv4, _ := ipLayer.(*layers.IPv4)
				if ipv4.Protocol != layers.IPProtocolICMPv4 {
					fmt.Println("Not ICMPv4 protocol.")
				}
				icmpLayer := gopkt.Layer(layers.LayerTypeICMPv4)
				if icmpLayer == nil {
					fmt.Println("Missing ICMPv4 layer.")
				}
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
					fmt.Println("Not ICMPv4 echo request.")
				}
				fmt.Println("Received an ICMPv4 echo request.")

				// Build packet layers.
				ethResp := layers.Ethernet{
					DstMAC: net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
					//DstMAC: net.HardwareAddr{0x02, 0xfe, 0xa8, 0x77, 0xaf, 0x20},
					SrcMAC: []byte(net.HardwareAddr{0x02, 0xfe, 0x08, 0x88, 0x45, 0x7f}),

					EthernetType: layers.EthernetTypeIPv4,
				}
				ipv4Resp := layers.IPv4{
					Version:    4,
					IHL:        5,
					TOS:        0,
					Id:         0,
					Flags:      0,
					FragOffset: 0,
					TTL:        255,
					Protocol:   layers.IPProtocolICMPv4,
					SrcIP:      []byte("\xc0\xa8\x01\x01"),
					DstIP:      []byte("\xc0\xa8\x01\x02"),
				}
				icmpResp := layers.ICMPv4{
					TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
					Id:       icmp.Id,
					Seq:      icmp.Seq,
				}

				// Set up buffer and options for serialization.
				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				gopacket.SerializeLayers(buf, opts, &ethResp, &ipv4Resp, &icmpResp,
					gopacket.Payload(icmp.Payload))
				// write packet to shared memory
				txq0.WritePacket(buf.Bytes())
			}

		}
		return nil

	}

}
func Connected(i *memif.Interface) error {
	data, ok := i.GetPrivateData().(*interfaceData)
	if !ok {
		return fmt.Errorf("Invalid private data")
	}
	_ = data

	// allocate packet buffer
	pkt := make([]byte, 2048)
	// get rx queue
	rxq0, err := i.GetRxQueue(0)
	_ = err

	// read packet from shared memory
	pktLen, err := rxq0.ReadPacket(pkt)
	_, _ = err, pktLen

	return nil
}

type interfaceData struct {
	errChan  chan error
	quitChan chan struct{}
	wg       sync.WaitGroup
}

func interractiveHelp() {
	fmt.Println("help - print this help")
	fmt.Println("start - start connecting loop")
	fmt.Println("show - print interface details")
	fmt.Println("exit - exit the application")
}

func main() {
	cpuprof := flag.String("cpuprof", "", "cpu profiling output file")
	memprof := flag.String("memprof", "", "mem profiling output file")
	role := flag.String("role", "slave", "interface role")
	name := flag.String("name", "gomemif", "interface name")
	socketName := flag.String("socket", "/run/vpp/memif.sock", "control socket filename")

	flag.Parse()

	if *cpuprof != "" {
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(*cpuprof)).Stop()
	}
	if *memprof != "" {
		defer profile.Start(profile.MemProfile, profile.ProfilePath(*memprof)).Stop()
	}

	memifErrChan := make(chan error)
	exitChan := make(chan struct{})

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

	fmt.Println("GoMemif: Responder")
	fmt.Println("-----------------------")

	socket, err := memif.NewSocket("gomemif_example", *socketName)
	if err != nil {
		fmt.Println("Failed to create socket: ", err)
		return
	}

	data := interfaceData{}
	args := &memif.Arguments{
		IsMaster:         isMaster,
		ConnectedFunc:    Connected,
		DisconnectedFunc: Disconnected,
		PrivateData:      &data,
		Name:             *name,
		InterruptFunc:    Responder,
	}

	i, err := socket.NewInterface(args)
	if err != nil {
		fmt.Println("Failed to create interface on socket %s: %s", socket.GetFilename(), err)
		goto exit
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
				fmt.Println("Failed to connect: ", err)
				goto exit
			}
		}
	}

	go func(exitChan chan<- struct{}) {
		reader := bufio.NewReader(os.Stdin)
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
				fmt.Println("remote: ", i.GetRemoteName())
				fmt.Println("peer: ", i.GetPeerName())
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

	for {
		select {
		case <-exitChan:
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
