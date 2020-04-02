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

package memif

import (
        "fmt"
        "syscall"
        "os"
        "container/list"
)

const (
        DefaultSocketFilename = "/run/vpp/memif.sock"
        DefaultNumQueuePairs = 1
        DefaultLog2RingSize = 10
        DefaultPacketBufferSize = 2048
)

const MFD_ALLOW_SEALING = 2
const SYS_MEMFD_CREATE = 319
const F_ADD_SEALS = 1033
const F_SEAL_SHRINK = 0x0002

const EFD_NONBLOCK = 04000

type ConnectedFunc func(e *Endpoint) error

type DisconnectedFunc func(e *Endpoint) error

type MemoryConfig struct {
        NumQueuePairs      uint16
	Log2RingSize       uint8
	PacketBufferSize   uint32
}

type Arguments struct {
        Id                 uint32
	IsMaster           bool
        Name               string
        MemoryConfig       MemoryConfig
        ConnectedFunc      ConnectedFunc
        DisconnectedFunc   DisconnectedFunc
        PrivateData        interface{}
}

type memoryRegion struct {
	data []byte
	size uint64
	fd int
	packetBufferOffset uint32
}

type Queue struct {
	ring *ring

        e *Endpoint

	lastHead uint16
	lastTail uint16

	interruptFd int
}

type Endpoint struct {
        args Arguments
        run MemoryConfig

        privateData interface{}

        listRef *list.Element
        socket *Socket
        cc *controlChannel

        remoteName string

        peerName string

        regions []memoryRegion

        txQueues []Queue
        rxQueues []Queue
}

func (e *Endpoint) IsMaster() bool {
        return e.args.IsMaster
}

func (e *Endpoint) GetRemoteName() string {
        return e.remoteName
}

func (e *Endpoint) GetPeerName() string {
        return e.peerName
}

func (e *Endpoint) GetName() string {
        return e.args.Name
}

func (e *Endpoint) GetRxQueue(qid int) (*Queue, error) {
        if qid >= len(e.rxQueues) {
                return nil, fmt.Errorf("Invalid Queue index")
        }
        return &e.rxQueues[qid], nil
}

func (e *Endpoint) GetTxQueue(qid int) (*Queue, error) {
        if qid >= len(e.txQueues) {
                return nil, fmt.Errorf("Invalid Queue index")
        }
        return &e.txQueues[qid], nil
}

func (e *Endpoint) GetEventFd(qid int) (int, error) {
        if qid >= len(e.rxQueues) {
                return -1, fmt.Errorf("Invalid Queue id")
        }

        return e.rxQueues[qid].interruptFd, nil
}

func (socket *Socket) GetFilename () string {
        return socket.filename
}

func (q *Queue) disconnect() {
        syscall.Close(q.interruptFd)
        // TODO: close packet polling event chan
}

func (e *Endpoint) Disconnect() (err error) {
        if e.cc != nil {
                // close control and disconenct endpoint
                return e.cc.close(true, "Endpoint disconnected")
        }
        return nil
}

func (e *Endpoint) disconnect() (err error) {
        if e.cc == nil { // disconnected
                return nil
        }

        err = e.args.DisconnectedFunc(e)
        if err != nil {
                return fmt.Errorf("DisconnectedFunc: ", err)
        }

        for _, q := range e.txQueues {
                q.disconnect()
        }
        e.txQueues = []Queue{}

        for _, q := range e.rxQueues {
                q.disconnect()
        }
        e.rxQueues = []Queue{}

        // unmap regions
        for _, r := range e.regions {
                err = syscall.Munmap(r.data)
                if err != nil {
                        return err
                }
                err = syscall.Close(r.fd)
                if err != nil {
                        return err
                }
        }
        e.regions = nil

        e.peerName = ""
        e.remoteName = ""

        return nil
}

func (e *Endpoint) Delete() (err error) {
        e.Disconnect()

        // remove referance on socket
        e.socket.endpointList.Remove(e.listRef)
        e = nil

        return nil
}

func (e *Endpoint) GetSocket () (*Socket) {
        return e.socket
}

func (e *Endpoint) GetPrivateData () interface{} {
        return e.args.PrivateData
}

func RoleToString (isMaster bool) (string) {
        if isMaster {
                return "Master"
        }
        return "Slave"
}

func (socket *Socket) NewEndpoint (args *Arguments) (*Endpoint, error) {
        var err error
        // make sure the ID is unique on this socket
        for elt := socket.endpointList.Front(); elt != nil; elt = elt.Next() {
                e, ok := elt.Value.(*Endpoint)
                if ok {
                        if e.args.Id == args.Id && e.args.IsMaster == args.IsMaster {
                                return nil, fmt.Errorf("Endpoint with id %u role %s already exists on this socket", args.Id, RoleToString(args.IsMaster))
                        }
                }
	}

        // copy endpoint configuration
        e := Endpoint{
                args: *args,
        }
        // set default values
        if e.args.MemoryConfig.NumQueuePairs == 0 {
                e.args.MemoryConfig.NumQueuePairs = DefaultNumQueuePairs
        }
        if e.args.MemoryConfig.Log2RingSize == 0 {
                e.args.MemoryConfig.Log2RingSize = DefaultLog2RingSize
        }
        if e.args.MemoryConfig.PacketBufferSize == 0 {
                e.args.MemoryConfig.PacketBufferSize = DefaultPacketBufferSize
        }

        e.socket = socket

        // append endpoint to the list
        e.listRef = socket.endpointList.PushBack(&e)

        if !args.IsMaster {
                // create socket
                fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
                if err != nil {
                        return nil, fmt.Errorf("Failed to create UNIX domain socket: %v", err)
                }
                usa := &syscall.SockaddrUnix{Name: socket.filename}

                // Connect to listener socket
                err = syscall.Connect(fd, usa)
                if err != nil {
                        return nil, fmt.Errorf("Failed to connect socket %s : %v", socket.filename, err)
                }

                // Create control channel
                e.cc, err = socket.addControlChannel(fd, &e)
                if err != nil {
                        return nil, fmt.Errorf("Failed to create control channel: %v", err)
                }
        } else {
                if socket.listener == nil {
                        socket.listener, err = socket.newListener()
                        if err != nil {
                                return nil, fmt.Errorf("Failed to create listener channel: %s", err)
                        }
                }
        }

        return &e, nil
}

func eventFd() (efd int, err error) {
	u_efd, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(0), uintptr(EFD_NONBLOCK), 0)
	if errno != 0 {
		return -1, os.NewSyscallError("eventfd", errno)
	}
	return int(u_efd), nil
}

func (e *Endpoint) addRegion(hasPacketBuffers bool, hasRings bool) (err error) {
	var r memoryRegion

	if hasRings {
		r.packetBufferOffset = uint32((e.run.NumQueuePairs + e.run.NumQueuePairs) * (ringSize + descSize * (1 << e.run.Log2RingSize)))
	} else {
		r.packetBufferOffset = 0
	}

	if hasPacketBuffers {
		r.size = uint64(r.packetBufferOffset + e.run.PacketBufferSize * uint32(1 << e.run.Log2RingSize) * uint32(e.run.NumQueuePairs + e.run.NumQueuePairs))
	} else {
		r.size = uint64(r.packetBufferOffset)
	}

	r.fd, err = MemfdCreate()
        if err != nil {
                return err
        }

	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(r.fd), uintptr(F_ADD_SEALS), uintptr(F_SEAL_SHRINK))
	if errno != 0 {
		syscall.Close(r.fd)
		return fmt.Errorf("MemfdCreate: %s", os.NewSyscallError("fcntl", errno))
	}

	err = syscall.Ftruncate(r.fd, int64(r.size))
	if err != nil {
		syscall.Close(r.fd)
		r.fd = -1
		return fmt.Errorf("MemfdCreate: %s", err)
	}

	r.data, err = syscall.Mmap(r.fd, 0, int(r.size), syscall.PROT_READ | syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("addRegion: %s", err)
	}

	e.regions = append(e.regions, r)

	return nil
}

func (e *Endpoint) initializeRegions() (err error) {

	err = e.addRegion(true, true)
	if err != nil {
		return fmt.Errorf("initializeRegions: %s", err)
	}

	return nil
}

func (e *Endpoint) initializeQueues() (err error) {
        var q *Queue
        var desc descBuf
        var slot int

        desc = newDescBuf()
        desc.setFlags(0)
        desc.setRegion(0)
        desc.setLength(int(e.run.PacketBufferSize))

        for qid := 0; qid < int(e.run.NumQueuePairs); qid++ {
                /* TX */
                q = &Queue{
                        ring: e.newRing(0, ringTypeS2M, qid),
                        lastHead: 0,
                        lastTail: 0,
                        e: e,
                }
                q.ring.setCookie(cookie)
                q.ring.setFlags(1)
                q.interruptFd, err = eventFd()
                if err != nil {
                        return err
                }
                q.putRing()
                e.txQueues = append(e.txQueues, *q)

                for j := 0; j < q.ring.size; j++ {
                        slot = qid * q.ring.size + j
                	desc.setOffset(int(e.regions[0].packetBufferOffset + uint32(slot) * e.run.PacketBufferSize))
                        q.putDescBuf(slot, desc)
                }
        }
        for qid := 0; qid < int(e.run.NumQueuePairs); qid++ {
                /* RX */
                q = &Queue{
                        ring: e.newRing(0, ringTypeM2S, qid),
                        lastHead: 0,
                        lastTail: 0,
                        e: e,
                }
                q.ring.setCookie(cookie)
                q.ring.setFlags(1)
                q.interruptFd, err = eventFd()
                if err != nil {
                        return err
                }
                q.putRing()
                e.rxQueues = append(e.rxQueues, *q)

                for j := 0; j < q.ring.size; j++ {
                        slot = qid * q.ring.size + j
                	desc.setOffset(int(e.regions[0].packetBufferOffset + uint32(slot) * e.run.PacketBufferSize))
                        q.putDescBuf(slot, desc)
                }
        }

	return nil
}

func (e *Endpoint) connect() (err error) {
	for rid, _ := range e.regions {
                r := &e.regions[rid]
                if r.data == nil {
                        r.data, err = syscall.Mmap(r.fd, 0, int(r.size), syscall.PROT_READ | syscall.PROT_WRITE, syscall.MAP_SHARED)
        		if err != nil {
        			return fmt.Errorf("Mmap: %s", err)
        		}
                }
	}

	for _, q := range e.txQueues {
                q.updateRing()

		if q.ring.getCookie() != cookie {
			return fmt.Errorf("Wrong cookie")
		}

		q.lastHead = 0
		q.lastTail = 0
	}

	for _, q := range e.rxQueues {
                q.updateRing()

		if q.ring.getCookie() != cookie {
			return fmt.Errorf("Wrong cookie")
		}

		q.lastHead = 0
		q.lastTail = 0
	}

        return e.args.ConnectedFunc(e)
}
