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
	"syscall"
	"fmt"
	"bytes"
	"encoding/binary"
)

const Cookie = 0x3E31F20
const VersionMajor = 2
const VersionMinor = 0
const Version = ((VersionMajor << 8) | VersionMinor)

type msgType uint16

const (
	msgTypeNone msgType = iota
	msgTypeAck
	msgTypeHello
	msgTypeInit
	msgTypeAddRegion
	msgTypeAddRing
	msgTypeConnect
	msgTypeConnected
	msgTypeDisconnect
)

type ringType uint8

const (
	ringTypeS2M ringType = iota
	ringTypeM2S
)

type interfaceMode uint8

const (
	interfaceModeEthernet interfaceMode = iota
	interfaceModeIp
	interfaceModePuntInject
)

const descSize = 16
const ringSize = 128
const msgSize = 128
const msgTypeSize = 2


// ring offsets
const ringFlagsOffset = 4
// desc offsets
const descLengthOffset = 4
const descHeadOffset = 6
const descTailOffset = 64
const descOffset = 128

const msgAddRingFlagS2M = (1 << 0)

// Descriptor flags
//
// next buffer present
const descFlagNext = (1 << 0)

// Ring flags
//
// Interrupt
const ringFlagInterrupt = 1

func min16 (a uint16, b uint16) (uint16) {
	if a < b {
		return a
	}
	return b
}

func min8 (a uint8, b uint8) (uint8) {
	if a < b {
		return a
	}
	return b
}

type MsgHello struct {
	// app name
	Name [32]byte
	VersionMin uint16
	VersionMax uint16
	MaxRegion uint16
	MaxRingM2S uint16
	MaxRingS2M uint16
	MaxLog2RingSize uint8
}

type MsgInit struct {
	Version uint16
	Id uint32
	Mode interfaceMode
	Secret [24]byte
	// app name
	Name [32]byte
}

type MsgAddRegion struct {
	Index uint16
	Size uint64
}

type MsgAddRing struct {
	Flags uint16
	Index uint16
	Region uint16
	Offset uint32
	RingSizeLog2 uint8
	PrivateHdrSize uint16
}

type MsgConnect struct {
	// interface name
	Name [32]byte
}

type MsgConnected struct {
	// interface name
	Name [32]byte
}

type MsgDisconnect struct {
	Code uint32
	String [96]byte
}

type Desc struct {
	Flags uint16
	Region uint16
	Length uint32
	Offset uint32
	Metadata uint32
}

func (e *Endpoint) getRingOffset(regionIndex int, ringType ringType, ringIndex int) (offset uintptr) {
	rSize := uintptr(ringSize) + uintptr(descSize) * uintptr(1 << e.run.Log2RingSize)
	if ringType == ringTypeS2M {
		offset = 0
	} else {
		offset = uintptr(uintptr(e.run.NumQueuePairs) * rSize)
	}
	offset += uintptr(ringIndex) * rSize
	return offset
}

// copy desc
func (q *queue) readDesc(slot uint16) (d Desc, err error) {
	buf := bytes.NewReader(q.e.regions[q.region].data[q.ringOffset + descOffset + uintptr(slot * descSize):])
	err = binary.Read(buf, binary.LittleEndian, &d)
	return
}

func (q *queue) writeDesc(slot uint16, d *Desc) (err error) {
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, d)
	if err != nil {
		return err
	}
	copy(q.e.regions[q.region].data[q.ringOffset + descOffset + uintptr(slot * descSize):], buf.Bytes())

	return nil
}

// write contents of buf into shm buffer, return number of bytes written
func (q *queue) writeBuffer(d *Desc, buf []byte, packetBufferSize uint32) (n int) {
	nBytes := copy(q.e.regions[d.Region].data[d.Offset + d.Length:d.Offset + packetBufferSize], buf)
	d.Length += uint32(nBytes)
	return nBytes
}

// TODO: investigate atomic/store barrier
func (q *queue) writeHead(value uint16) (uint16) {
	atomicstore16(&q.e.regions[q.region].data[q.ringOffset + descHeadOffset], value)
	return value
}
// TODO: investigate atomic/store barrier
func (q *queue) writeTail(value uint16) (uint16) {
	atomicstore16(&q.e.regions[q.region].data[q.ringOffset + descTailOffset], value)
	return value
}

func (q *queue) readHead() (head uint16) {
	return atomicload16(&q.e.regions[q.region].data[q.ringOffset + descHeadOffset])
}

func (q *queue) readTail() (tail uint16) {
	return atomicload16(&q.e.regions[q.region].data[q.ringOffset + descTailOffset])
}

func (q *queue) isInterrupt() (bool, error) {
	var flags uint16
	buf := bytes.NewReader(q.e.regions[q.region].data[q.ringOffset + ringFlagsOffset:])
	err := binary.Read(buf, binary.LittleEndian, &flags)
	if err != nil {
		return  false, err
	}
	return (flags & ringFlagInterrupt) == 0, nil
}

func (q *queue) interrupt() (error) {
	intr, err := q.isInterrupt()
	if err != nil {
		return err
	}

	if intr {
		buf := make([]byte, 8)
		binary.PutUvarint(buf, 1)
		n, err := syscall.Write(q.interruptFd, buf[:])
		if err != nil {
			return err
		}
		if n != 8 {
			return fmt.Errorf("Faild to write to eventfd")
		}
	}

	return nil
}

type Ring struct {
	Cookie uint32
	Flags uint16
	Head uint16
	_ [56]byte
	Tail uint16
	_ [62]byte
}
