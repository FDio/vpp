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
        "container/list"
        "os"
        "sync"
)

const maxEpollEvents = 1
const maxControlLen = 256

const errorFdNotFound = "fd not found"


type controlMsg struct {
	Buffer     *bytes.Buffer
	Fd         int
}

type listener struct {
        socket *Socket
        event syscall.EpollEvent
}

type controlChannel struct {
        listRef *list.Element
        socket *Socket
        e *Endpoint

        event syscall.EpollEvent

        data       [msgSize]byte
	control    [maxControlLen]byte
	controlLen int

        msgQueue   []controlMsg
        isConnected bool
}

type Socket struct {
        filename string
        listener *listener
        endpointList *list.List
        ccList *list.List

        epfd int
        wakeEvent syscall.EpollEvent

        stopPollChan chan struct{}
        wg sync.WaitGroup
}

func (socket *Socket) StopPolling() error {
        if socket.stopPollChan != nil {
                // stop polling msg
                close(socket.stopPollChan)
                // wake epoll
                buf := make([]byte, 8)
		binary.PutUvarint(buf, 1)
		n, err := syscall.Write(int(socket.wakeEvent.Fd), buf[:])
		if err != nil {
			return err
		}
		if n != 8 {
			return fmt.Errorf("Faild to write to eventfd")
		}
                // wait until polling is stopped
                socket.wg.Wait()
        }

        return nil
}

func (socket *Socket) StartPolling(errChan chan<- error) {
        socket.stopPollChan = make(chan struct{})
        socket.wg.Add(1)
        go func (){
                var events [maxEpollEvents]syscall.EpollEvent
                defer socket.wg.Done()

                for {
                        select {
                        case <-socket.stopPollChan:
                                return
                        default:
                                num, err := syscall.EpollWait(socket.epfd, events[:], -1)
                                if err != nil {
                                        errChan <- fmt.Errorf("EpollWait: ", err)
                                        return
                                }

                                for ev := 0; ev < num; ev++ {
                                        if events[0].Fd == socket.wakeEvent.Fd {
                                                continue
                                        }
                                        err = socket.handleEvent(&events[0])
                                        if err != nil {
                                                errChan <- fmt.Errorf("handleEvent: ", err)
                                                return
                                        }
                                }
                        }
                }
        }()
}

func (socket *Socket) addEvent(event *syscall.EpollEvent) error {
        err := syscall.EpollCtl(socket.epfd, syscall.EPOLL_CTL_ADD, int(event.Fd), event)
	if err != nil {
		return fmt.Errorf("EpollCtl: %s", err)
	}
        return nil
}

func (socket *Socket) delEvent(event *syscall.EpollEvent) error {
        err := syscall.EpollCtl(socket.epfd, syscall.EPOLL_CTL_DEL, int(event.Fd), event)
	if err != nil {
		return fmt.Errorf("EpollCtl: %s", err)
	}
        return nil
}

// TODO: maybe a separate function to delete all interfaces?
func (socket *Socket) Delete() (err error) {
        for elt := socket.ccList.Front(); elt != nil; elt = elt.Next() {
                cc, ok := elt.Value.(*controlChannel)
                if ok {
                        err = cc.close(true, "Socket deleted")
                        if err != nil {
                                return nil
                        }
                }
        }
        for elt := socket.endpointList.Front(); elt != nil; elt = elt.Next() {
                e, ok := elt.Value.(*Endpoint)
                if ok {
                        err = e.Delete()
                        if err != nil {
                                return err
                        }
                }
        }

        if socket.listener != nil {
                err = socket.listener.close()
                if err != nil {
                        return err
                }
                err = os.Remove(socket.filename)
                if err != nil {
                        return nil
                }
        }

        err = socket.delEvent(&socket.wakeEvent)
        if err != nil {
                return fmt.Errorf("Failed to delete event: ", err)
        }

        syscall.Close(socket.epfd)

        return nil
}

func NewSocket (filename string) (socket *Socket, err error) {
        socket = &Socket{
                filename: filename,
                endpointList: list.New(),
                ccList: list.New(),
        }
        if socket.filename == "" {
                socket.filename = DefaultSocketFilename
        }

        socket.epfd, _ = syscall.EpollCreate1(0)

        efd, err := eventFd()
        socket.wakeEvent = syscall.EpollEvent{
                Events: syscall.EPOLLIN,
                Fd: int32(efd),
        }
        err = socket.addEvent(&socket.wakeEvent)
        if err != nil {
                return nil, fmt.Errorf("Failed to add event: ", err)
        }


        return socket, nil
}

func (socket *Socket) handleEvent(event *syscall.EpollEvent) error {
        if socket.listener != nil && socket.listener.event.Fd == event.Fd {
                return socket.listener.handleEvent(event)
        }

        for elt := socket.ccList.Front(); elt != nil; elt = elt.Next() {
                cc, ok := elt.Value.(*controlChannel)
                if ok {
                        if cc.event.Fd == event.Fd {
                                return cc.handleEvent(event)
                        }
                }
        }

        return fmt.Errorf(errorFdNotFound)
}

func (l *listener) handleEvent(event *syscall.EpollEvent) error {
        if event.Events == syscall.EPOLLIN {
                newFd, _, err := syscall.Accept(int(l.event.Fd))
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

                return nil
        }

        return fmt.Errorf("Unexpected event: ", event.Events)
}

func (cc *controlChannel) handleEvent(event *syscall.EpollEvent) error {
        var size int
        var err error

        if event.Events == syscall.EPOLLIN {
                size, cc.controlLen, _, _, err = syscall.Recvmsg(int(cc.event.Fd), cc.data[:] ,cc.control[:], 0)
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

                return nil
        }

        return fmt.Errorf("Unexpected event: ", event.Events)
}

func (l* listener) close() error {
        err := l.socket.delEvent(&l.event)
        if err != nil {
                return fmt.Errorf("Failed to del event: ", err)
        }
        err = syscall.Close(int(l.event.Fd))
        if err != nil {
                return fmt.Errorf("Failed to close socket: ", err)
        }
        return nil
}

func (socket *Socket) newListener () (l *listener, err error) {
        l = &listener{
                // we will need this to look up master endpoint by id
                socket: socket,
        }

        // create socket
        fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
        if err != nil {
                return nil, fmt.Errorf("Failed to create UNIX domain socket")
        }
        usa := &syscall.SockaddrUnix{Name: socket.filename}

        // Bind to address and start listening
        err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
        if err != nil {
                return nil, fmt.Errorf("Failed to set socket option %s : %v", socket.filename, err)
        }
        err = syscall.Bind(fd, usa)
        if err != nil {
                return nil, fmt.Errorf("Failed to bind socket %s : %v", socket.filename, err)
        }
        err = syscall.Listen(fd, syscall.SOMAXCONN)
        if err != nil {
                return nil, fmt.Errorf("Failed to listen on socket %s : %v", socket.filename, err)
        }

        l.event = syscall.EpollEvent{
                Events: syscall.EPOLLIN,
                Fd: int32(fd),
        }
        err = socket.addEvent(&l.event)
        if err != nil {
                return nil, fmt.Errorf("Failed to add event: ", err)
        }

        return l, nil
}

func (cc *controlChannel) close(sendMsg bool, str string) (err error) {
        if sendMsg == true {
                // first clear message queue so that the disconnect
                // message is the only message in queue
                cc.msgQueue = []controlMsg{}
                cc.msgEnqDisconnect(str)

                err = cc.sendMsg()
                if err != nil {
                        return err
                }
        }

        err = cc.socket.delEvent(&cc.event)
        if err != nil {
                return fmt.Errorf("Failed to del event: ", err)
        }

        // remove referance form socket
        cc.socket.ccList.Remove(cc.listRef)

        if cc.e != nil {
                err = cc.e.disconnect()
                if err != nil {
                        return fmt.Errorf("Endpoint Disconnect: ", err)
                }
        }

        return nil
}

func (socket *Socket) addControlChannel (fd int, e *Endpoint) (*controlChannel, error) {
        cc := &controlChannel{
                socket: socket,
                e: e,
                isConnected: false,
        }

        var err error

        cc.event = syscall.EpollEvent{
                Events: syscall.EPOLLIN,
                Fd: int32(fd),
        }
        err = socket.addEvent(&cc.event)
        if err != nil {
                return nil, fmt.Errorf("Failed to add event: ", err)
        }

        cc.listRef = socket.ccList.PushBack(cc)

        return cc, nil
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

	return nil
}

func (cc *controlChannel) msgEnqInit() (err error) {
	init := MsgInit {
		Version: Version,
		Id: cc.e.args.Id,
		Mode: interfaceModeEthernet,
	}
	// TODO: get app name
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
        for elt := cc.socket.endpointList.Front(); elt != nil; elt = elt.Next() {
                e, ok := elt.Value.(*Endpoint)
                if ok {
                        if e.args.Id == init.Id && e.args.IsMaster && e.cc == nil {
                                // TODO: verify secret
                                // endpoint is assigned to control channel
                                cc.e = e
                                cc.e.run = cc.e.args.MemoryConfig
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
		Size: cc.e.regions[regionIndex].size,
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAddRegion)
	err = binary.Write(buf, binary.LittleEndian, addRegion)

	msg := controlMsg {
		Buffer: buf,
		Fd: cc.e.regions[regionIndex].fd,
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

	region := memoryRegion{
		size: addRegion.Size,
		fd: fd,
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
		Offset: uint32(q.ring.offset),
		Region: uint16(q.ring.region),
		RingSizeLog2: uint8(q.ring.log2Size),
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

	q := Queue{
		e: cc.e,
		interruptFd: fd,
	}

	if (addRing.Flags & msgAddRingFlagS2M) == msgAddRingFlagS2M {
                q.ring = newRing(int(addRing.Region), ringTypeS2M, int(addRing.Offset), int(addRing.RingSizeLog2))
		cc.e.rxQueues = append(cc.e.rxQueues, q)
	} else {
                q.ring = newRing(int(addRing.Region), ringTypeM2S, int(addRing.Offset), int(addRing.RingSizeLog2))
		cc.e.txQueues = append(cc.e.txQueues, q)
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

        cc.isConnected = true

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

        cc.isConnected = true

	return nil
}

func (cc *controlChannel) msgEnqDisconnect(str string) (err error) {
        dc := MsgDisconnect{
                // not implemented
                Code: 0,
        }
        copy(dc.String[:], str)

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeDisconnect)
	err = binary.Write(buf, binary.LittleEndian, dc)

	msg := controlMsg {
		Buffer: buf,
		Fd: -1,
	}

	cc.msgQueue = append(cc.msgQueue, msg)

	return nil
}

func (cc *controlChannel) parseDisconnect() (err error) {
	var dc MsgDisconnect

	buf := bytes.NewReader(cc.data[msgTypeSize:])
	err = binary.Read(buf, binary.LittleEndian, &dc)
	if err != nil {
		return
	}

	err = cc.close(false, string(dc.String[:]))
        if err != nil {
                return fmt.Errorf("Failed to disconnect control channel: ", err)
        }

	return nil
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
