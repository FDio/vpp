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

// Package memif provides the implementation of shared memory interface (memif).
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

const mfd_allow_sealing = 2
const sys_memfd_create = 319
const f_add_seals = 1033
const f_seal_shrink = 0x0002

const efd_nonblock = 04000

// ConnectedFunc is a callback called when an interface is connected
type ConnectedFunc func(i *Interface) error

// DisconnectedFunc is a callback called when an interface is disconnected
type DisconnectedFunc func(i *Interface) error

// MemoryConfig represents shared memory configuration
type MemoryConfig struct {
        NumQueuePairs      uint16
	Log2RingSize       uint8
	PacketBufferSize   uint32
}

// Arguments represent interface configuration
type Arguments struct {
        Id                 uint32
	IsMaster           bool
        Name               string
        Secret             [24]byte
        MemoryConfig       MemoryConfig
        ConnectedFunc      ConnectedFunc
        DisconnectedFunc   DisconnectedFunc
        PrivateData        interface{}
}

// memoryRegion represents a shared memory mapped file
type memoryRegion struct {
	data []byte
	size uint64
	fd int
	packetBufferOffset uint32
}

// Queue represents rx or tx queue
type Queue struct {
	ring *ring

        i *Interface

	lastHead uint16
	lastTail uint16

	interruptFd int
}

// Interface represents memif network interface
type Interface struct {
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

// IsMaster returns true if the interfaces role is master, else returns false
func (i *Interface) IsMaster() bool {
        return i.args.IsMaster
}

// GetRemoteName returns the name of the application on which the peer
// interface exists
func (i *Interface) GetRemoteName() string {
        return i.remoteName
}

// GetPeerName returns peer interfaces name
func (i *Interface) GetPeerName() string {
        return i.peerName
}

// GetName returens interfaces name
func (i *Interface) GetName() string {
        return i.args.Name
}

// GetRxQueue returns an rx queue specified by queue index
func (i *Interface) GetRxQueue(qid int) (*Queue, error) {
        if qid >= len(i.rxQueues) {
                return nil, fmt.Errorf("Invalid Queue index")
        }
        return &i.rxQueues[qid], nil
}

// GetRxQueue returns a tx queue specified by queue index
func (i *Interface) GetTxQueue(qid int) (*Queue, error) {
        if qid >= len(i.txQueues) {
                return nil, fmt.Errorf("Invalid Queue index")
        }
        return &i.txQueues[qid], nil
}

// GetEventFd returns queues interrupt event fd
func (q *Queue) GetEventFd() (int, error) {
        return q.interruptFd, nil
}

// GetFilename returns sockets filename
func (socket *Socket) GetFilename () string {
        return socket.filename
}

// close closes the queue
func (q *Queue) close() {
        syscall.Close(q.interruptFd)
}

// IsConnecting returns true if the interface is connecting
func (i *Interface) IsConnecting() bool {
        if i.cc != nil {
                return true
        }
        return false
}

// IsConnected returns true if the interface is connected
func (i *Interface) IsConnected() bool {
        if i.cc != nil && i.cc.isConnected {
                return true
        }
        return false
}

// Disconnect disconnects the interface
func (i *Interface) Disconnect() (err error) {
        if i.cc != nil {
                // close control and disconenct interface
                return i.cc.close(true, "Interface disconnected")
        }
        return nil
}

// disconnect finalizes interface disconnection
func (i *Interface) disconnect() (err error) {
        if i.cc == nil { // disconnected
                return nil
        }

        err = i.args.DisconnectedFunc(i)
        if err != nil {
                return fmt.Errorf("DisconnectedFunc: ", err)
        }

        for _, q := range i.txQueues {
                q.close()
        }
        i.txQueues = []Queue{}

        for _, q := range i.rxQueues {
                q.close()
        }
        i.rxQueues = []Queue{}

        // unmap regions
        for _, r := range i.regions {
                err = syscall.Munmap(r.data)
                if err != nil {
                        return err
                }
                err = syscall.Close(r.fd)
                if err != nil {
                        return err
                }
        }
        i.regions = nil
        i.cc = nil

        i.peerName = ""
        i.remoteName = ""

        return nil
}

// Delete deletes the interface
func (i *Interface) Delete() (err error) {
        i.Disconnect()

        // remove referance on socket
        i.socket.interfaceList.Remove(i.listRef)
        i = nil

        return nil
}

// GetSocket returns the socket the interface belongs to
func (i *Interface) GetSocket () (*Socket) {
        return i.socket
}

// GetPrivateDate returns interfaces private data
func (i *Interface) GetPrivateData () interface{} {
        return i.args.PrivateData
}

// RoleToString returns 'Master' if isMaster os true, else returns 'Slave'
func RoleToString (isMaster bool) (string) {
        if isMaster {
                return "Master"
        }
        return "Slave"
}

// RequestConnection is used by slave interface to connect to a socket and
// create a control channel
func (i *Interface) RequestConnection() (error) {
        if i.IsMaster() {
                return fmt.Errorf("Only slave can request connection")
        }
        // create socket
        fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
        if err != nil {
                return fmt.Errorf("Failed to create UNIX domain socket: %v", err)
        }
        usa := &syscall.SockaddrUnix{Name: i.socket.filename}

        // Connect to listener socket
        err = syscall.Connect(fd, usa)
        if err != nil {
                return fmt.Errorf("Failed to connect socket %s : %v", i.socket.filename, err)
        }

        // Create control channel
        i.cc, err = i.socket.addControlChannel(fd, i)
        if err != nil {
                return fmt.Errorf("Failed to create control channel: %v", err)
        }

        return nil
}

// NewInterface returns a new memif network interface
func (socket *Socket) NewInterface (args *Arguments) (*Interface, error) {
        var err error
        // make sure the ID is unique on this socket
        for elt := socket.interfaceList.Front(); elt != nil; elt = elt.Next() {
                i, ok := elt.Value.(*Interface)
                if ok {
                        if i.args.Id == args.Id && i.args.IsMaster == args.IsMaster {
                                return nil, fmt.Errorf("Interface with id %u role %s already exists on this socket", args.Id, RoleToString(args.IsMaster))
                        }
                }
	}

        // copy interface configuration
        i := Interface{
                args: *args,
        }
        // set default values
        if i.args.MemoryConfig.NumQueuePairs == 0 {
                i.args.MemoryConfig.NumQueuePairs = DefaultNumQueuePairs
        }
        if i.args.MemoryConfig.Log2RingSize == 0 {
                i.args.MemoryConfig.Log2RingSize = DefaultLog2RingSize
        }
        if i.args.MemoryConfig.PacketBufferSize == 0 {
                i.args.MemoryConfig.PacketBufferSize = DefaultPacketBufferSize
        }

        i.socket = socket

        // append interface to the list
        i.listRef = socket.interfaceList.PushBack(&i)

        if i.args.IsMaster {
                if socket.listener == nil {
                        err = socket.addListener()
                        if err != nil {
                                return nil, fmt.Errorf("Failed to create listener channel: %s", err)
                        }
                }
        }

        return &i, nil
}

// eventFd returns an eventfd (SYS_EVENTFD2)
func eventFd() (efd int, err error) {
	u_efd, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(0), uintptr(efd_nonblock), 0)
	if errno != 0 {
		return -1, os.NewSyscallError("eventfd", errno)
	}
	return int(u_efd), nil
}

// addRegions creates and adds a new memory region to the interface (slave only)
func (i *Interface) addRegion(hasPacketBuffers bool, hasRings bool) (err error) {
	var r memoryRegion

	if hasRings {
		r.packetBufferOffset = uint32((i.run.NumQueuePairs + i.run.NumQueuePairs) * (ringSize + descSize * (1 << i.run.Log2RingSize)))
	} else {
		r.packetBufferOffset = 0
	}

	if hasPacketBuffers {
		r.size = uint64(r.packetBufferOffset + i.run.PacketBufferSize * uint32(1 << i.run.Log2RingSize) * uint32(i.run.NumQueuePairs + i.run.NumQueuePairs))
	} else {
		r.size = uint64(r.packetBufferOffset)
	}

	r.fd, err = memfdCreate()
        if err != nil {
                return err
        }

	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(r.fd), uintptr(f_add_seals), uintptr(f_seal_shrink))
	if errno != 0 {
		syscall.Close(r.fd)
		return fmt.Errorf("memfdCreate: %s", os.NewSyscallError("fcntl", errno))
	}

	err = syscall.Ftruncate(r.fd, int64(r.size))
	if err != nil {
		syscall.Close(r.fd)
		r.fd = -1
		return fmt.Errorf("memfdCreate: %s", err)
	}

	r.data, err = syscall.Mmap(r.fd, 0, int(r.size), syscall.PROT_READ | syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("addRegion: %s", err)
	}

	i.regions = append(i.regions, r)

	return nil
}

// initializeRegions initializes interfaces regions (slave only)
func (i *Interface) initializeRegions() (err error) {

	err = i.addRegion(true, true)
	if err != nil {
		return fmt.Errorf("initializeRegions: %s", err)
	}

	return nil
}

// initializeQueues initializes interfaces queues (slave only)
func (i *Interface) initializeQueues() (err error) {
        var q *Queue
        var desc descBuf
        var slot int

        desc = newDescBuf()
        desc.setFlags(0)
        desc.setRegion(0)
        desc.setLength(int(i.run.PacketBufferSize))

        for qid := 0; qid < int(i.run.NumQueuePairs); qid++ {
                /* TX */
                q = &Queue{
                        ring: i.newRing(0, ringTypeS2M, qid),
                        lastHead: 0,
                        lastTail: 0,
                        i: i,
                }
                q.ring.setCookie(cookie)
                q.ring.setFlags(1)
                q.interruptFd, err = eventFd()
                if err != nil {
                        return err
                }
                q.putRing()
                i.txQueues = append(i.txQueues, *q)

                for j := 0; j < q.ring.size; j++ {
                        slot = qid * q.ring.size + j
                	desc.setOffset(int(i.regions[0].packetBufferOffset + uint32(slot) * i.run.PacketBufferSize))
                        q.putDescBuf(slot, desc)
                }
        }
        for qid := 0; qid < int(i.run.NumQueuePairs); qid++ {
                /* RX */
                q = &Queue{
                        ring: i.newRing(0, ringTypeM2S, qid),
                        lastHead: 0,
                        lastTail: 0,
                        i: i,
                }
                q.ring.setCookie(cookie)
                q.ring.setFlags(1)
                q.interruptFd, err = eventFd()
                if err != nil {
                        return err
                }
                q.putRing()
                i.rxQueues = append(i.rxQueues, *q)

                for j := 0; j < q.ring.size; j++ {
                        slot = qid * q.ring.size + j
                	desc.setOffset(int(i.regions[0].packetBufferOffset + uint32(slot) * i.run.PacketBufferSize))
                        q.putDescBuf(slot, desc)
                }
        }

	return nil
}

// connect finalizes interface connection
func (i *Interface) connect() (err error) {
	for rid, _ := range i.regions {
                r := &i.regions[rid]
                if r.data == nil {
                        r.data, err = syscall.Mmap(r.fd, 0, int(r.size), syscall.PROT_READ | syscall.PROT_WRITE, syscall.MAP_SHARED)
        		if err != nil {
        			return fmt.Errorf("Mmap: %s", err)
        		}
                }
	}

	for _, q := range i.txQueues {
                q.updateRing()

		if q.ring.getCookie() != cookie {
			return fmt.Errorf("Wrong cookie")
		}

		q.lastHead = 0
		q.lastTail = 0
	}

	for _, q := range i.rxQueues {
                q.updateRing()

		if q.ring.getCookie() != cookie {
			return fmt.Errorf("Wrong cookie")
		}

		q.lastHead = 0
		q.lastTail = 0
	}

        return i.args.ConnectedFunc(i)
}
