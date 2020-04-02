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

/* DESCRIPTOR BEGIN */

// desc field offsets
const descFlagsOffset = 0
const descRegionOffset = 2
const descLengthOffset = 4
const descOffsetOffset = 8
const descMetadataOffset = 12

type descBuf []byte

func newDescBuf() descBuf {
	return make(descBuf, descSize)
}

func (q *Queue) getDescBuf(slot int, db descBuf) {
	copy(db, q.e.regions[q.region].data[q.ringOffset + descOffset + slot * descSize:])
}

func (q *Queue) putDescBuf(slot int, db descBuf) {
	copy(q.e.regions[q.region].data[q.ringOffset + descOffset + slot * descSize:], db)
}

func (db descBuf) getFlags() int {
	return (int)(binary.LittleEndian.Uint16((db)[descFlagsOffset:]))
}

func (db descBuf) getRegion() int {
	return (int)(binary.LittleEndian.Uint16((db)[descRegionOffset:]))
}

func (db descBuf) getLength() int {
	return (int)(binary.LittleEndian.Uint32((db)[descLengthOffset:]))
}

func (db descBuf) getOffset() int {
	return (int)(binary.LittleEndian.Uint32((db)[descOffsetOffset:]))
}

func (db descBuf) getMetadata() int {
	return (int)(binary.LittleEndian.Uint32((db)[descMetadataOffset:]))
}

func (db descBuf) setFlags(val int) {
	binary.LittleEndian.PutUint16((db)[descFlagsOffset:], uint16(val))
}

func (db descBuf) setRegion(val int) {
	binary.LittleEndian.PutUint16((db)[descRegionOffset:], uint16(val))
}

func (db descBuf) setLength(val int) {
	binary.LittleEndian.PutUint32((db)[descLengthOffset:], uint32(val))
}

func (db descBuf) setOffset(val int) {
	binary.LittleEndian.PutUint32((db)[descOffsetOffset:], uint32(val))
}

func (db descBuf) setMetadata(val int) {
	binary.LittleEndian.PutUint32((db)[descMetadataOffset:], uint32(val))
}

/* DESCRIPTOR END */

func (e *Endpoint) getRingOffset(regionIndex int, ringType ringType, ringIndex int) (offset int) {
	rSize := ringSize + descSize * (1 << e.run.Log2RingSize)
	if ringType == ringTypeS2M {
		offset = 0
	} else {
		offset = int(e.run.NumQueuePairs) * rSize
	}
	offset += ringIndex * rSize
	return offset
}

func (q *Queue) GetFlags() int {
	return (int)(binary.LittleEndian.Uint16(q.e.regions[q.region].data[q.ringOffset + ringFlagsOffset:]))
}

func (q *Queue) isInterrupt() (bool) {
	return (q.GetFlags() & ringFlagInterrupt) == 0
}

func (q *Queue) interrupt() (error) {
	intr := q.isInterrupt()

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
