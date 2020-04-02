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
        "bytes"
        "encoding/binary"
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

type Connected func(e *Endpoint) error

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
        Connected          Connected
}

type MemoryRegion struct {
	data []byte
	Size uint64
	Fd int
	PacketBufferOffset uint32
}

type Queue struct {
	ringType ringType
	ringOffset int
        descHeadOffset int

	region uint16

        e *Endpoint

	lastHead uint16
	lastTail uint16

	log2RingSize uint8
        ringSize int

	interruptFd int
}

// TODO: private context
type Endpoint struct {
        args Arguments
        run MemoryConfig

        isConnected bool
        isConnecting bool

        socket *Socket

        remoteName string

        peerName string

        regions []MemoryRegion

        txQueues []Queue
        rxQueues []Queue
}

type Socket struct {
        filename string
        listener *listener
        endpointList []*Endpoint
        ccList []controlChannel
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

// FIXME: refactor polling
func (socket *Socket) StartPolling() error {
        if socket.listener != nil {
		go func() { // S/R-SAFE: See above.
                        for {
                                socket.listener.poll()
                        }
		}()
        }

        for _, cc := range socket.ccList {
		go func() { // S/R-SAFE: See above.
                        for {
                                cc.poll()
                        }
		}()
        }

        return nil
}

func NewSocket (filename string) (socket *Socket, err error) {
        // FIXME: check if socket with same filename exists
        socket = &Socket{
                filename: filename,
        }
        if socket.filename == "" {
                socket.filename = DefaultSocketFilename
        }

        return socket, nil
}

func (e *Endpoint) GetSocket () (*Socket) {
        return e.socket
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
        if socket.endpointList != nil {
                for _, e := range socket.endpointList {
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
        socket.endpointList = append(socket.endpointList, &e)

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
                _, err = socket.addControlChannel(fd, &e)
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

func EventFd() (efd int, err error) {
	u_efd, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(0), uintptr(EFD_NONBLOCK), 0)
	if errno != 0 {
		return -1, os.NewSyscallError("eventfd", errno)
	}
	return int(u_efd), nil
}

func (e *Endpoint) addRegion(hasPacketBuffers bool, hasRings bool) (err error) {
	var r MemoryRegion

	if hasRings {
		r.PacketBufferOffset = uint32((e.run.NumQueuePairs + e.run.NumQueuePairs) * (ringSize + descSize * (1 << e.run.Log2RingSize)))
	} else {
		r.PacketBufferOffset = 0
	}

	if hasPacketBuffers {
		r.Size = uint64(r.PacketBufferOffset + e.run.PacketBufferSize * uint32(1 << e.run.Log2RingSize) * uint32(e.run.NumQueuePairs + e.run.NumQueuePairs))
	} else {
		r.Size = uint64(r.PacketBufferOffset)
	}

	// Create region in New()?
	r.Fd, err = MemfdCreate()
        if err != nil {
                return err
        }

	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(r.Fd), uintptr(F_ADD_SEALS), uintptr(F_SEAL_SHRINK))
	if errno != 0 {
		syscall.Close(r.Fd)
		return fmt.Errorf("MemfdCreate: %s", os.NewSyscallError("fcntl", errno))
	}

	err = syscall.Ftruncate(r.Fd, int64(r.Size))
	if err != nil {
		syscall.Close(r.Fd)
		r.Fd = -1
		return fmt.Errorf("MemfdCreate: %s", err)
	}

	r.data, err = syscall.Mmap(r.Fd, 0, int(r.Size), syscall.PROT_READ | syscall.PROT_WRITE, syscall.MAP_SHARED)
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

func (e *Endpoint) initializeRings() (err error) {
	buf := new(bytes.Buffer)

	for i := 0; uint16(i) < e.run.NumQueuePairs; i++ {
		ring := Ring {
			Head: 0,
			Tail: 0,
			Cookie: Cookie,
			Flags: 0,
		}
		err = binary.Write(buf, binary.LittleEndian, ring)
		if err != nil {
			return fmt.Errorf("initializeRings: %s", err)
		}
	}

	for i := 0; uint16(i) < e.run.NumQueuePairs; i++ {
		ring := Ring {
			Head: 0,
			Tail: 0,
			Cookie: Cookie,
			Flags: 0,
		}
		err = binary.Write(buf, binary.LittleEndian, ring)
		if err != nil {
			return fmt.Errorf("initializeRings: %s", err)
		}
	}

	copy(e.regions[0].data[:], buf.Bytes())

	return nil
}

func (e *Endpoint) initializeQueues() (err error) {

	for qid, _ := range e.txQueues {
		q := &e.txQueues[qid]
		q.log2RingSize = e.run.Log2RingSize
                q.ringSize = (1 << q.log2RingSize)
		q.ringOffset = e.getRingOffset(0, ringTypeS2M, qid)

                for j := 0; j < q.ringSize; j++ {
                        slot := qid * q.ringSize + j
                        desc := newDescBuf()
                        desc.setFlags(0)
                	desc.setRegion(0)
                	desc.setLength(int(e.run.PacketBufferSize))
                	desc.setOffset(int(e.regions[0].PacketBufferOffset + uint32(slot) * e.run.PacketBufferSize))
                        q.putDescBuf(slot, desc)
                }
	}

	for qid, _ := range e.rxQueues {
		q := &e.rxQueues[qid]
		q.log2RingSize = e.run.Log2RingSize
                q.ringSize = (1 << q.log2RingSize)
		q.ringOffset = e.getRingOffset(0, ringTypeM2S, qid)

                for j := 0; j < q.ringSize; j++ {
                        slot := (qid + int(e.run.NumQueuePairs)) * q.ringSize + j
                        desc := newDescBuf()
                        desc.setFlags(0)
                	desc.setRegion(0)
                	desc.setLength(int(e.run.PacketBufferSize))
                	desc.setOffset(int(e.regions[0].PacketBufferOffset + uint32(slot) * e.run.PacketBufferSize))
                        q.putDescBuf(slot, desc)
                }
	}

	return nil
}

func (e *Endpoint) connect() (err error) {
	for rid, _ := range e.regions {
		r := &e.regions[rid]
		r.data, err = syscall.Mmap(r.Fd, 0, int(r.Size), syscall.PROT_READ | syscall.PROT_WRITE, syscall.MAP_SHARED)
		if err != nil {
			return fmt.Errorf("Mmap: %s", err)
		}
	}

	for qid, _ := range e.txQueues {
		q := &e.txQueues[qid]
		var ring Ring

		buf := bytes.NewReader(e.regions[0].data[q.ringOffset:q.ringOffset + ringSize])
		err = binary.Read(buf, binary.LittleEndian, &ring)
		if err != nil {
			return err
		}

		if ring.Cookie != Cookie {
			return fmt.Errorf("Wrong cookie")
		}

		q.lastHead = 0
		q.lastTail = 0
	}

	for qid, _ := range e.rxQueues {
		q := &e.rxQueues[qid]
		var ring Ring

		buf := bytes.NewReader(e.regions[0].data[q.ringOffset:q.ringOffset + ringSize])
		err = binary.Read(buf, binary.LittleEndian, &ring)
		if err != nil {
			return err
		}

		if ring.Cookie != Cookie {
			return fmt.Errorf("Wrong cookie")
		}

		q.lastHead = 0
		q.lastTail = 0
	}

        e.isConnecting = false
        e.isConnected = true

        return e.args.Connected(e)
}
