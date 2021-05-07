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
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"syscall"
)

const maxEpollEvents = 1
const maxControlLen = 256

const errorFdNotFound = "fd not found"

// controlMsg represents a message used in communication between memif peers
type controlMsg struct {
	Buffer *bytes.Buffer
	Fd     int
}

// listener represents a listener functionality of UNIX domain socket
type listener struct {
	socket *Socket
	event  syscall.EpollEvent
}

// controlChannel represents a communication channel between memif peers
// backed by UNIX domain socket
type controlChannel struct {
	listRef     *list.Element
	socket      *Socket
	i           *Interface
	event       syscall.EpollEvent
	data        [msgSize]byte
	control     [maxControlLen]byte
	controlLen  int
	msgQueue    []controlMsg
	isConnected bool
}

// Socket represents a UNIX domain socket used for communication
// between memif peers
type Socket struct {
	appName       string
	filename      string
	listener      *listener
	interfaceList *list.List
	ccList        *list.List
	epfd          int
	wakeEvent     syscall.EpollEvent
	stopPollChan  chan struct{}
	wg            sync.WaitGroup
}

// StopPolling stops polling events on the socket
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

// StartPolling starts polling and handling events on the socket,
// enabling communication between memif peers
func (socket *Socket) StartPolling(errChan chan<- error) {
	socket.stopPollChan = make(chan struct{})
	socket.wg.Add(1)
	go func() {
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
					}
				}
			}
		}
	}()
}

// addEvent adds event to epoll instance associated with the socket
func (socket *Socket) addEvent(event *syscall.EpollEvent) error {
	err := syscall.EpollCtl(socket.epfd, syscall.EPOLL_CTL_ADD, int(event.Fd), event)
	if err != nil {
		return fmt.Errorf("EpollCtl: %s", err)
	}
	return nil
}

// addEvent deletes event to epoll instance associated with the socket
func (socket *Socket) delEvent(event *syscall.EpollEvent) error {
	err := syscall.EpollCtl(socket.epfd, syscall.EPOLL_CTL_DEL, int(event.Fd), event)
	if err != nil {
		return fmt.Errorf("EpollCtl: %s", err)
	}
	return nil
}

// Delete deletes the socket
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
	for elt := socket.interfaceList.Front(); elt != nil; elt = elt.Next() {
		i, ok := elt.Value.(*Interface)
		if ok {
			err = i.Delete()
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

// NewSocket returns a new Socket
func NewSocket(appName string, filename string) (socket *Socket, err error) {
	socket = &Socket{
		appName:       appName,
		filename:      filename,
		interfaceList: list.New(),
		ccList:        list.New(),
	}
	if socket.filename == "" {
		socket.filename = DefaultSocketFilename
	}

	socket.epfd, _ = syscall.EpollCreate1(0)

	efd, err := eventFd()
	socket.wakeEvent = syscall.EpollEvent{
		Events: syscall.EPOLLIN | syscall.EPOLLERR | syscall.EPOLLHUP,
		Fd:     int32(efd),
	}
	err = socket.addEvent(&socket.wakeEvent)
	if err != nil {
		return nil, fmt.Errorf("Failed to add event: ", err)
	}

	return socket, nil
}

// handleEvent handles epoll event
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

// handleEvent handles epoll event for listener
func (l *listener) handleEvent(event *syscall.EpollEvent) error {
	// hang up
	if (event.Events & syscall.EPOLLHUP) == syscall.EPOLLHUP {
		err := l.close()
		if err != nil {
			return fmt.Errorf("Failed to close listener after hang up event: ", err)
		}
		return fmt.Errorf("Hang up: ", l.socket.filename)
	}

	// error
	if (event.Events & syscall.EPOLLERR) == syscall.EPOLLERR {
		err := l.close()
		if err != nil {
			return fmt.Errorf("Failed to close listener after receiving an error event: ", err)
		}
		return fmt.Errorf("Received error event on listener ", l.socket.filename)
	}

	// read message
	if (event.Events & syscall.EPOLLIN) == syscall.EPOLLIN {
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

// handleEvent handles epoll event for control channel
func (cc *controlChannel) handleEvent(event *syscall.EpollEvent) error {
	var size int
	var err error

	// hang up
	if (event.Events & syscall.EPOLLHUP) == syscall.EPOLLHUP {
		// close cc, don't send msg
		err := cc.close(false, "")
		if err != nil {
			return fmt.Errorf("Failed to close control channel after hang up event: ", err)
		}
		return fmt.Errorf("Hang up: ", cc.i.GetName())
	}

	if (event.Events & syscall.EPOLLERR) == syscall.EPOLLERR {
		// close cc, don't send msg
		err := cc.close(false, "")
		if err != nil {
			return fmt.Errorf("Failed to close control channel after receiving an error event: ", err)
		}
		return fmt.Errorf("Received error event on control channel ", cc.i.GetName())
	}

	if (event.Events & syscall.EPOLLIN) == syscall.EPOLLIN {
		size, cc.controlLen, _, _, err = syscall.Recvmsg(int(cc.event.Fd), cc.data[:], cc.control[:], 0)
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

// close closes the listener
func (l *listener) close() error {
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

// AddListener adds a lisntener to the socket. The fd must describe a
// UNIX domain socket already bound to a UNIX domain filename and
// marked as listener
func (socket *Socket) AddListener(fd int) (err error) {
	l := &listener{
		// we will need this to look up master interface by id
		socket: socket,
	}

	l.event = syscall.EpollEvent{
		Events: syscall.EPOLLIN | syscall.EPOLLERR | syscall.EPOLLHUP,
		Fd:     int32(fd),
	}
	err = socket.addEvent(&l.event)
	if err != nil {
		return fmt.Errorf("Failed to add event: ", err)
	}

	socket.listener = l

	return nil
}

// addListener creates new UNIX domain socket, binds it to the address
// and marks it as listener
func (socket *Socket) addListener() (err error) {
	// create socket
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return fmt.Errorf("Failed to create UNIX domain socket")
	}
	usa := &syscall.SockaddrUnix{Name: socket.filename}
	// Bind to address and start listening
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PASSCRED, 1)
	if err != nil {
		return fmt.Errorf("Failed to set socket option %s : %v", socket.filename, err)
	}
	err = syscall.Bind(fd, usa)
	if err != nil {
		return fmt.Errorf("Failed to bind socket %s : %v", socket.filename, err)
	}
	err = syscall.Listen(fd, syscall.SOMAXCONN)
	if err != nil {
		return fmt.Errorf("Failed to listen on socket %s : %v", socket.filename, err)
	}

	return socket.AddListener(fd)
}

// close closes a control channel, if the control channel is assigned an
// interface, the interface is disconnected
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

	if cc.i != nil {
		err = cc.i.disconnect()
		if err != nil {
			return fmt.Errorf("Interface Disconnect: ", err)
		}
	}

	return nil
}

//addControlChannel returns a new controlChannel and adds it to the socket
func (socket *Socket) addControlChannel(fd int, i *Interface) (*controlChannel, error) {
	cc := &controlChannel{
		socket:      socket,
		i:           i,
		isConnected: false,
	}

	var err error

	cc.event = syscall.EpollEvent{
		Events: syscall.EPOLLIN | syscall.EPOLLERR | syscall.EPOLLHUP,
		Fd:     int32(fd),
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

	msg := controlMsg{
		Buffer: buf,
		Fd:     -1,
	}

	cc.msgQueue = append(cc.msgQueue, msg)

	return nil
}

func (cc *controlChannel) msgEnqHello() (err error) {
	hello := MsgHello{
		VersionMin:      Version,
		VersionMax:      Version,
		MaxRegion:       255,
		MaxRingM2S:      255,
		MaxRingS2M:      255,
		MaxLog2RingSize: 14,
	}

	copy(hello.Name[:], []byte(cc.socket.appName))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeHello)
	err = binary.Write(buf, binary.LittleEndian, hello)

	msg := controlMsg{
		Buffer: buf,
		Fd:     -1,
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

	cc.i.run = cc.i.args.MemoryConfig

	cc.i.run.NumQueuePairs = min16(cc.i.args.MemoryConfig.NumQueuePairs, hello.MaxRingS2M)
	cc.i.run.NumQueuePairs = min16(cc.i.args.MemoryConfig.NumQueuePairs, hello.MaxRingM2S)
	cc.i.run.Log2RingSize = min8(cc.i.args.MemoryConfig.Log2RingSize, hello.MaxLog2RingSize)

	cc.i.remoteName = string(hello.Name[:])

	return nil
}

func (cc *controlChannel) msgEnqInit() (err error) {
	init := MsgInit{
		Version: Version,
		Id:      cc.i.args.Id,
		Mode:    cc.i.args.Mode,
	}

	copy(init.Name[:], []byte(cc.socket.appName))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeInit)
	err = binary.Write(buf, binary.LittleEndian, init)

	msg := controlMsg{
		Buffer: buf,
		Fd:     -1,
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

	// find peer interface
	for elt := cc.socket.interfaceList.Front(); elt != nil; elt = elt.Next() {
		i, ok := elt.Value.(*Interface)
		if ok {
			if i.args.Id == init.Id && i.args.IsMaster && i.cc == nil {
				// verify secret
				if i.args.Secret != init.Secret {
					return fmt.Errorf("Invalid secret")
				}
				// interface is assigned to control channel
				i.cc = cc
				cc.i = i
				cc.i.run = cc.i.args.MemoryConfig
				cc.i.remoteName = string(init.Name[:])

				return nil
			}
		}
	}

	return fmt.Errorf("Invalid interface id")
}

func (cc *controlChannel) msgEnqAddRegion(regionIndex uint16) (err error) {
	if len(cc.i.regions) <= int(regionIndex) {
		return fmt.Errorf("Invalid region index")
	}

	addRegion := MsgAddRegion{
		Index: regionIndex,
		Size:  cc.i.regions[regionIndex].size,
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAddRegion)
	err = binary.Write(buf, binary.LittleEndian, addRegion)

	msg := controlMsg{
		Buffer: buf,
		Fd:     cc.i.regions[regionIndex].fd,
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
		fd:   fd,
	}

	cc.i.regions = append(cc.i.regions, region)

	return nil
}

func (cc *controlChannel) msgEnqAddRing(ringType ringType, ringIndex uint16) (err error) {
	var q Queue
	var flags uint16 = 0

	if ringType == ringTypeS2M {
		q = cc.i.txQueues[ringIndex]
		flags = msgAddRingFlagS2M
	} else {
		q = cc.i.rxQueues[ringIndex]
	}

	addRing := MsgAddRing{
		Index:          ringIndex,
		Offset:         uint32(q.ring.offset),
		Region:         uint16(q.ring.region),
		RingSizeLog2:   uint8(q.ring.log2Size),
		Flags:          flags,
		PrivateHdrSize: 0,
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeAddRing)
	err = binary.Write(buf, binary.LittleEndian, addRing)

	msg := controlMsg{
		Buffer: buf,
		Fd:     q.interruptFd,
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

	if addRing.Index >= cc.i.run.NumQueuePairs {
		return fmt.Errorf("invalid ring index")
	}

	q := Queue{
		i:           cc.i,
		interruptFd: fd,
	}

	if (addRing.Flags & msgAddRingFlagS2M) == msgAddRingFlagS2M {
		q.ring = newRing(int(addRing.Region), ringTypeS2M, int(addRing.Offset), int(addRing.RingSizeLog2))
		cc.i.rxQueues = append(cc.i.rxQueues, q)
	} else {
		q.ring = newRing(int(addRing.Region), ringTypeM2S, int(addRing.Offset), int(addRing.RingSizeLog2))
		cc.i.txQueues = append(cc.i.txQueues, q)
	}

	return nil
}

func (cc *controlChannel) msgEnqConnect() (err error) {
	var connect MsgConnect
	copy(connect.Name[:], []byte(cc.i.args.Name))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeConnect)
	err = binary.Write(buf, binary.LittleEndian, connect)

	msg := controlMsg{
		Buffer: buf,
		Fd:     -1,
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

	cc.i.peerName = string(connect.Name[:])

	err = cc.i.connect()
	if err != nil {
		return err
	}

	cc.isConnected = true

	return nil
}

func (cc *controlChannel) msgEnqConnected() (err error) {
	var connected MsgConnected
	copy(connected.Name[:], []byte(cc.i.args.Name))

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, msgTypeConnected)
	err = binary.Write(buf, binary.LittleEndian, connected)

	msg := controlMsg{
		Buffer: buf,
		Fd:     -1,
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

	cc.i.peerName = string(conn.Name[:])

	err = cc.i.connect()
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

	msg := controlMsg{
		Buffer: buf,
		Fd:     -1,
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

func (cc *controlChannel) parseMsg() error {
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
			goto error
		}
		// Initialize slave memif
		err = cc.i.initializeRegions()
		if err != nil {
			goto error
		}
		err = cc.i.initializeQueues()
		if err != nil {
			goto error
		}
		// Enqueue messages
		err = cc.msgEnqInit()
		if err != nil {
			goto error
		}
		for i := 0; i < len(cc.i.regions); i++ {
			err = cc.msgEnqAddRegion(uint16(i))
			if err != nil {
				goto error
			}
		}
		for i := 0; uint16(i) < cc.i.run.NumQueuePairs; i++ {
			err = cc.msgEnqAddRing(ringTypeS2M, uint16(i))
			if err != nil {
				goto error
			}
		}
		for i := 0; uint16(i) < cc.i.run.NumQueuePairs; i++ {
			err = cc.msgEnqAddRing(ringTypeM2S, uint16(i))
			if err != nil {
				goto error
			}
		}
		err = cc.msgEnqConnect()
		if err != nil {
			goto error
		}
	} else if msgType == msgTypeInit {
		err = cc.parseInit()
		if err != nil {
			goto error
		}

		err = cc.msgEnqAck()
		if err != nil {
			goto error
		}
	} else if msgType == msgTypeAddRegion {
		err = cc.parseAddRegion()
		if err != nil {
			goto error
		}

		err = cc.msgEnqAck()
		if err != nil {
			goto error
		}
	} else if msgType == msgTypeAddRing {
		err = cc.parseAddRing()
		if err != nil {
			goto error
		}

		err = cc.msgEnqAck()
		if err != nil {
			goto error
		}
	} else if msgType == msgTypeConnect {
		err = cc.parseConnect()
		if err != nil {
			goto error
		}

		err = cc.msgEnqConnected()
		if err != nil {
			goto error
		}
	} else if msgType == msgTypeConnected {
		err = cc.parseConnected()
		if err != nil {
			goto error
		}
	} else if msgType == msgTypeDisconnect {
		err = cc.parseDisconnect()
		if err != nil {
			goto error
		}
	} else {
		err = fmt.Errorf("unknown message %d", msgType)
		goto error
	}

	return nil

error:
	err1 := cc.close(true, err.Error())
	if err1 != nil {
		return fmt.Errorf(err.Error(), ": Failed to close control channel: ", err1)
	}

	return err
}

// parseControlMsg parses control message and returns file descriptor
// if any
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
