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
        "bytes"
        "encoding/binary"
)

const maxEpollEvents = 1
const maxControlLen = 256

type epoll struct {
        fd int
        epfd int
        event    syscall.EpollEvent
	events   [maxEpollEvents]syscall.EpollEvent
        timeout int
}

type controlMsg struct {
	Buffer     *bytes.Buffer
	Fd         int
}

type listener struct {
        socket *Socket
        fd int
        epoll *epoll
}

type controlChannel struct {
        fd int
        socket *Socket
        e *Endpoint

        epoll *epoll

        data       [msgSize]byte
	control    [maxControlLen]byte
	controlLen int

        msgQueue   []controlMsg
        isConnected bool
}

func newEpoll (fd int, timeout int) (*epoll, error) {
        e := &epoll{
                fd: fd,
		epfd: -1,
		event: syscall.EpollEvent{
			Events: syscall.EPOLLIN,
			Fd: int32(fd),
		},
		timeout: timeout,
        }

        e.epfd, _ = syscall.EpollCreate1(0)
        // Ready to read
	err := syscall.EpollCtl(e.epfd, syscall.EPOLL_CTL_ADD, e.fd, &e.event)
	if err != nil {
		return nil, fmt.Errorf("EpollCtl: %s", err)
	}

        return e, nil
}

func (socket *Socket) newListener () (l *listener, err error) {
        l = &listener{
                // we will need this to look up master endpoint by id
                socket: socket,
        }

        // create socket
        l.fd, err = syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
        if err != nil {
                return nil, fmt.Errorf("Failed to create UNIX domain socket")
        }
        usa := &syscall.SockaddrUnix{Name: socket.filename}

        // Bind to address and start listening
        err = syscall.SetsockoptInt(l.fd, syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
        if err != nil {
                return nil, fmt.Errorf("Failed to set socket option %s : %v", socket.filename, err)
        }
        err = syscall.Bind(l.fd, usa)
        if err != nil {
                return nil, fmt.Errorf("Failed to bind socket %s : %v", socket.filename, err)
        }
        err = syscall.Listen(l.fd, syscall.SOMAXCONN)
        if err != nil {
                return nil, fmt.Errorf("Failed to listen on socket %s : %v", socket.filename, err)
        }

        l.epoll, err = newEpoll(l.fd, -1)
        if err != nil {
                return nil, fmt.Errorf("Failed to create epoll: %s", err)
        }

        return l, nil
}

func (socket *Socket) addControlChannel (fd int, e *Endpoint) (*controlChannel, error) {
        cc := &controlChannel{
                fd: fd,
                socket: socket,
                e: e,
        }

        var err error
        cc.epoll, err = newEpoll(cc.fd, -1)
        if err != nil {
                return nil, fmt.Errorf("Failed to create epoll: %s", err)
        }

        socket.ccList = append(socket.ccList, *cc)

        return cc, nil
}

func (l *listener) poll() (error) {
        num, err := syscall.EpollWait(l.epoll.epfd, l.epoll.events[:], l.epoll.timeout)
	if err != nil {
		return err
	}

	for ev := 0; ev < num; ev++ {
		if l.epoll.events[ev].Fd == int32(l.epoll.fd) {
			newFd, _, err := syscall.Accept(l.epoll.fd)
			if err != nil {
				return fmt.Errorf("Accept: %s", err)
			}

                        cc, err := l.socket.addControlChannel(newFd, nil)
                        if err != nil {
                                return fmt.Errorf("Failed to add control channel: %s", err)
                        }

                        err = cc.msgEnqHello()
			if err != nil {
				return fmt.Errorf("msgEnqHello: %s", err)
			}

			err = cc.sendMsg()
			if err != nil {
				return err
			}

        		go func() { // S/R-SAFE: See above.
                                for {
                                        cc.poll()
                                }
        		}()
		}
	}

	return nil
}

func (cc *controlChannel) poll() (error) {
        num, err := syscall.EpollWait(cc.epoll.epfd, cc.epoll.events[:], cc.epoll.timeout)
	if err != nil {
		return err
	}

	for ev := 0; ev < num; ev++ {
		if cc.epoll.events[ev].Fd == int32(cc.epoll.fd) {
                        var size int
			size, cc.controlLen, _, _, err = syscall.Recvmsg(cc.epoll.fd, cc.data[:] ,cc.control[:], 0)
			if err != nil {
				return fmt.Errorf("recvmsg: %s", err)
			}
			if size != msgSize {
				return fmt.Errorf("invalid message size %d", size)
			}

			err = cc.parseMsg()
			if err != nil {
				return err
			}

			err = cc.sendMsg()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (cc *controlChannel) msgEnqAck() (err error) {
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAck)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	cc.msgQueue = append(cc.msgQueue, msg)

	return nil
}

func (cc *controlChannel) msgEnqHello() (err error) {
	hello := MsgHello {
		VersionMin: Version,
		VersionMax: Version,
		MaxRegion: 255,
		MaxRingM2S: 255,
		MaxRingS2M: 255,
		MaxLog2RingSize: 14,
	}

	// TODO: get container name?
	copy(hello.Name[:], []byte("gomemif"))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeHello)
	err = binary.Write(buf, binary.LittleEndian, hello)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	cc.msgQueue = append(cc.msgQueue, msg)

	return nil
}

func (cc *controlChannel) parseHello() (err error) {
	var hello MsgHello

	buf := bytes.NewReader(cc.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &hello)
	if err != nil {
		return
	}

	if hello.VersionMin > Version || hello.VersionMax < Version {
		return fmt.Errorf("Incompatible memif version")
	}

        cc.e.run = cc.e.args.MemoryConfig

	cc.e.run.NumQueuePairs = min16(cc.e.args.MemoryConfig.NumQueuePairs, hello.MaxRingS2M)
	cc.e.run.NumQueuePairs = min16(cc.e.args.MemoryConfig.NumQueuePairs, hello.MaxRingM2S)
	cc.e.run.Log2RingSize = min8(cc.e.args.MemoryConfig.Log2RingSize, hello.MaxLog2RingSize)

	cc.e.remoteName = string(hello.Name[:])
        cc.e.isConnecting = true

	return nil
}

func (cc *controlChannel) msgEnqInit() (err error) {
	init := MsgInit {
		Version: Version,
		Id: cc.e.args.Id,
		Mode: interfaceModeEthernet,
	}
	// TODO: get container name?
	copy(init.Name[:], []byte("gomemif"))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeInit)
	err = binary.Write(buf, binary.LittleEndian, init)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	cc.msgQueue = append(cc.msgQueue, msg)

	return nil
}

func (cc *controlChannel) parseInit() (err error) {
	var init MsgInit

	buf := bytes.NewReader(cc.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &init)
	if err != nil {
		return
	}

	if init.Version != Version {
		return fmt.Errorf("Incompatible memif driver version")
	}

        // find peer endpoint
        if cc.socket.endpointList != nil {
                for _, e := range cc.socket.endpointList {
                        if e.args.Id == init.Id && e.args.IsMaster && !e.isConnected && !e.isConnecting {
                                // TODO: verify secret
                                // endpoint is assigned to control channel
                                cc.e = e
                                cc.e.run = cc.e.args.MemoryConfig
                                cc.e.isConnecting = true
                                cc.e.remoteName = string(init.Name[:])

                                return nil
                        }
                }
        }

	return fmt.Errorf("Invalid interface id")
}

func (cc *controlChannel) msgEnqAddRegion(regionIndex uint16) (err error) {
	if len(cc.e.regions) <= int(regionIndex) {
		return fmt.Errorf("Invalid region index")
	}

	addRegion := MsgAddRegion {
		Index: regionIndex,
		Size: cc.e.regions[regionIndex].Size,
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAddRegion)
	err = binary.Write(buf, binary.LittleEndian, addRegion)

	msg := controlMsg {
		Buffer: buf,
		Fd: cc.e.regions[regionIndex].Fd,
	}

	cc.msgQueue = append(cc.msgQueue, msg)

	return nil
}

func (cc *controlChannel) parseAddRegion() (err error) {
	var addRegion MsgAddRegion

	buf := bytes.NewReader(cc.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &addRegion)
	if err != nil {
		return
	}

	fd, err := cc.parseControlMsg()
	if err != nil {
		return fmt.Errorf("parseControlMsg: %s", err)
	}

	if addRegion.Index > 255 {
		return fmt.Errorf("Invalid memory region index")
	}

	region := MemoryRegion{
		Size: addRegion.Size,
		Fd: fd,
	}

	cc.e.regions = append(cc.e.regions, region)

	return nil
}

func (cc *controlChannel) msgEnqAddRing(ringType ringType, ringIndex uint16) (err error) {
	var q Queue
	var flags uint16 = 0

	if ringType == ringTypeS2M {
		q = cc.e.txQueues[ringIndex]
		flags = msgAddRingFlagS2M
	} else {
		q = cc.e.rxQueues[ringIndex]
	}

	addRing := MsgAddRing {
		Index: ringIndex,
		Offset: uint32(q.ringOffset),
		Region: q.region,
		RingSizeLog2: q.log2RingSize,
		Flags: flags,
		PrivateHdrSize: 0,
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAddRing)
	err = binary.Write(buf, binary.LittleEndian, addRing)

	msg := controlMsg {
		Buffer: buf,
		Fd: q.interruptFd,
	}

	cc.msgQueue = append(cc.msgQueue, msg)

	return nil
}

func (cc *controlChannel) parseAddRing() (err error) {
	var addRing MsgAddRing

	buf := bytes.NewReader(cc.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &addRing)
	if err != nil {
		return
	}

	fd, err := cc.parseControlMsg()
	if err != nil {
		return err
	}

	if addRing.Index >= cc.e.run.NumQueuePairs {
		return fmt.Errorf("invalid ring index")
	}

	Queue := Queue{
		ringOffset: int(addRing.Offset),
                descHeadOffset: int(addRing.Offset) + descHeadOffset,
		region: addRing.Region,
		e: cc.e,
		log2RingSize: addRing.RingSizeLog2,
                ringSize: (1 << addRing.RingSizeLog2),
		interruptFd: fd,
	}

	if (addRing.Flags & msgAddRingFlagS2M) == msgAddRingFlagS2M {
		Queue.ringType = ringTypeS2M
		cc.e.rxQueues = append(cc.e.rxQueues, Queue)
	} else {
		Queue.ringType = ringTypeM2S
		cc.e.txQueues = append(cc.e.txQueues, Queue)
	}

	return nil
}

func (cc *controlChannel) msgEnqConnect() (err error) {
	var connect MsgConnect
	copy(connect.Name[:], []byte(cc.e.args.Name))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeConnect)
	err = binary.Write(buf, binary.LittleEndian, connect)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	cc.msgQueue = append(cc.msgQueue, msg)

	return nil
}

func (cc *controlChannel) parseConnect() (err error) {
	var connect MsgConnect

	buf := bytes.NewReader(cc.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &connect)
	if err != nil {
		return
	}

        cc.e.peerName = string(connect.Name[:])

	err = cc.e.connect()
	if err != nil {
		return err
	}

	return nil
}

func (cc *controlChannel) msgEnqConnected() (err error) {
	var connected MsgConnected
	copy(connected.Name[:], []byte(cc.e.args.Name))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeConnected)
	err = binary.Write(buf, binary.LittleEndian, connected)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	cc.msgQueue = append(cc.msgQueue, msg)

	return nil
}

func (cc *controlChannel) parseConnected() (err error) {
	var conn MsgConnected

	buf := bytes.NewReader(cc.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &conn)
	if err != nil {
		return
	}

        cc.e.peerName = string(conn.Name[:])

	err = cc.e.connect()
	if err != nil {
		return err
	}

	return nil
}

func (cc *controlChannel) parseDisconnect() (err error) {
	var dc MsgDisconnect

	buf := bytes.NewReader(cc.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &dc)
	if err != nil {
		return
	}

	// TODO: disconnect

	return fmt.Errorf("disconnect received: %s", string(dc.String[:]))
}

func (cc *controlChannel) parseMsg() (error) {
	var msgType msgType
	var err error

	buf := bytes.NewReader(cc.data[:])
	err = binary.Read(buf, binary.LittleEndian, &msgType)

	if msgType == msgTypeAck {
		return nil
	} else if msgType == msgTypeHello {
		// Configure
		err = cc.parseHello()
		if err != nil {
			return fmt.Errorf("parseHello: %s", err)
		}
		// Initialize slave memif
		err = cc.e.initializeRegions()
		if err != nil {
			return fmt.Errorf("initializeRegions: %s", err)
		}
		err = cc.e.initializeRings()
		if err != nil {
			return fmt.Errorf("initializeRings: %s", err)
		}
                err = cc.e.initializeQueues()
		if err != nil {
			return fmt.Errorf("initializeQueues: %s", err)
		}
		// Enqueue messages
		err = cc.msgEnqInit()
		if err != nil {
			return fmt.Errorf("msgSendInit: %s", err)
		}
		for i := 0; i < len(cc.e.regions); i++ {
			err = cc.msgEnqAddRegion(uint16(i))
			if err != nil {
				return fmt.Errorf("msgEnqAddRegion: %s", err)
			}
		}
		for i := 0; uint16(i) < cc.e.run.NumQueuePairs; i++ {
			err = cc.msgEnqAddRing(ringTypeS2M, uint16(i))
			if err != nil {
				return fmt.Errorf("msgEnqAddRing: %s", err)
			}
		}
		for i := 0; uint16(i) < cc.e.run.NumQueuePairs; i++ {
			err = cc.msgEnqAddRing(ringTypeM2S, uint16(i))
			if err != nil {
				return fmt.Errorf("msgEnqAddRing: %s", err)
			}
		}
		err = cc.msgEnqConnect()
		if err != nil {
			return fmt.Errorf("msgEnqConnect: %s", err)
		}
	} else if msgType == msgTypeInit {
		err = cc.parseInit()
		if err != nil {
			return fmt.Errorf("parseInit: %s", err)
		}

		err = cc.msgEnqAck()
		if err != nil {
			return fmt.Errorf("msgEnqAck: %s", err)
		}
	} else if msgType == msgTypeAddRegion {
		err = cc.parseAddRegion()
		if err != nil {
			return fmt.Errorf("parseAddRegion: %s", err)
		}

		err = cc.msgEnqAck()
		if err != nil {
			return fmt.Errorf("msgEnqAck: %s", err)
		}
	} else if msgType == msgTypeAddRing {
		err = cc.parseAddRing()
		if err != nil {
			return fmt.Errorf("parseAddRing: %s", err)
		}

		err = cc.msgEnqAck()
		if err != nil {
			return fmt.Errorf("msgEnqAck: %s", err)
		}
	} else if msgType == msgTypeConnect {
		err = cc.parseConnect()
		if err != nil {
			return fmt.Errorf("parseConnect: %s", err)
		}

		err = cc.msgEnqConnected()
		if err != nil {
			return fmt.Errorf("msgEnqConnected: %s", err)
		}
	} else if msgType == msgTypeConnected {
		err = cc.parseConnected()
		if err != nil {
			return fmt.Errorf("parseConnected: %s", err)
		}
	} else if msgType ==msgTypeDisconnect {
		err = cc.parseDisconnect()
		if err != nil {
			return fmt.Errorf("parseDisconnect: %s", err)
		}
	} else {
		return fmt.Errorf("unknown message %d", msgType)
	}

	return nil
}

// Parse control message and return file descriptor
func (cc *controlChannel) parseControlMsg() (fd int, err error) {
	// Assert only called when we require FD
	fd = -1

	controlMsgs, err := syscall.ParseSocketControlMessage(cc.control[:cc.controlLen])
	if err != nil {
		return -1, fmt.Errorf("syscall.ParseSocketControlMessage: %s", err)
	}

 	if len(controlMsgs) == 0 {
		return -1, fmt.Errorf("Missing control message")
	}

	for _, cmsg := range controlMsgs {
		if cmsg.Header.Level == syscall.SOL_SOCKET {
			if cmsg.Header.Type == syscall.SCM_RIGHTS {
				FDs, err := syscall.ParseUnixRights(&cmsg)
				if err != nil {
					return -1, fmt.Errorf("syscall.ParseUnixRights: %s", err)
				}
				if len(FDs) == 0 {
					continue
				}
				// Only expect single FD
				fd = FDs[0]
			}
		}
	}

	if fd == -1 {
		return -1, fmt.Errorf("Missing file descriptor")
	}

	return fd, nil
}
