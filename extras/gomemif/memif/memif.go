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
	"encoding/binary"
	"fmt"
	"syscall"
)

const cookie = 0x3E31F20

// VersionMajor is memif protocols major version
const VersionMajor = 2

// VersionMinor is memif protocols minor version
const VersionMinor = 0

// Version is memif protocols version as uint16
// (M-Major m-minor: MMMMMMMMmmmmmmmm)
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

type interfaceMode uint8

const (
	InterfaceModeEthernet interfaceMode = iota
	InterfaceModeIp
	InterfaceModePuntInject
)

const msgSize = 128
const msgTypeSize = 2

const msgAddRingFlagS2M = (1 << 0)

// Descriptor flags
//
// next buffer present
const descFlagNext = (1 << 0)

// Ring flags
//
// Interrupt
const ringFlagInterrupt = 1

func min16(a uint16, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}

func min8(a uint8, b uint8) uint8 {
	if a < b {
		return a
	}
	return b
}

type MsgHello struct {
	// app name
	Name            [32]byte
	VersionMin      uint16
	VersionMax      uint16
	MaxRegion       uint16
	MaxRingM2S      uint16
	MaxRingS2M      uint16
	MaxLog2RingSize uint8
}

type MsgInit struct {
	Version uint16
	Id      uint32
	Mode    interfaceMode
	Secret  [24]byte
	// app name
	Name [32]byte
}

type MsgAddRegion struct {
	Index uint16
	Size  uint64
}

type MsgAddRing struct {
	Flags          uint16
	Index          uint16
	Region         uint16
	Offset         uint32
	RingSizeLog2   uint8
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
	Code   uint32
	String [96]byte
}

/* DESCRIPTOR BEGIN */

const descSize = 16

// desc field offsets
const descFlagsOffset = 0
const descRegionOffset = 2
const descLengthOffset = 4
const descOffsetOffset = 8
const descMetadataOffset = 12

// descBuf represents a memif descriptor as array of bytes
type descBuf []byte

// newDescBuf returns new descriptor buffer
func newDescBuf() descBuf {
	return make(descBuf, descSize)
}

// getDescBuff copies descriptor from shared memory to descBuf
func (q *Queue) getDescBuf(slot int, db descBuf) {
	copy(db, q.i.regions[q.ring.region].data[q.ring.offset+ringSize+slot*descSize:])
}

// putDescBuf copies contents of descriptor buffer into shared memory
func (q *Queue) putDescBuf(slot int, db descBuf) {
	copy(q.i.regions[q.ring.region].data[q.ring.offset+ringSize+slot*descSize:], db)
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

/* RING BEGIN */

type ringType uint8

const (
	ringTypeS2M ringType = iota
	ringTypeM2S
)

const ringSize = 128

// ring field offsets
const ringCookieOffset = 0
const ringFlagsOffset = 4
const ringHeadOffset = 6
const ringTailOffset = 64

// ringBuf represents a memif ring as array of bytes
type ringBuf []byte

type ring struct {
	ringType ringType
	size     int
	log2Size int
	region   int
	rb       ringBuf
	offset   int
}

// newRing returns new memif ring based on data received in msgAddRing (master only)
func newRing(regionIndex int, ringType ringType, ringOffset int, log2RingSize int) *ring {
	r := &ring{
		ringType: ringType,
		size:     (1 << log2RingSize),
		log2Size: log2RingSize,
		rb:       make(ringBuf, ringSize),
		offset:   ringOffset,
	}

	return r
}

// newRing returns a new memif ring
func (i *Interface) newRing(regionIndex int, ringType ringType, ringIndex int) *ring {
	r := &ring{
		ringType: ringType,
		size:     (1 << i.run.Log2RingSize),
		log2Size: int(i.run.Log2RingSize),
		rb:       make(ringBuf, ringSize),
	}

	rSize := ringSize + descSize*r.size
	if r.ringType == ringTypeS2M {
		r.offset = 0
	} else {
		r.offset = int(i.run.NumQueuePairs) * rSize
	}
	r.offset += ringIndex * rSize

	return r
}

// putRing put the ring to the shared memory
func (q *Queue) putRing() {
	copy(q.i.regions[q.ring.region].data[q.ring.offset:], q.ring.rb)
}

// updateRing updates ring with data from shared memory
func (q *Queue) updateRing() {
	copy(q.ring.rb, q.i.regions[q.ring.region].data[q.ring.offset:])
}

func (r *ring) getCookie() int {
	return (int)(binary.LittleEndian.Uint32((r.rb)[ringCookieOffset:]))
}

// getFlags returns the flags value from ring buffer
// Use Queue.getFlags in fast-path to avoid updating the whole ring.
func (r *ring) getFlags() int {
	return (int)(binary.LittleEndian.Uint16((r.rb)[ringFlagsOffset:]))
}

// getHead returns the head pointer value from ring buffer.
// Use readHead in fast-path to avoid updating the whole ring.
func (r *ring) getHead() int {
	return (int)(binary.LittleEndian.Uint16((r.rb)[ringHeadOffset:]))
}

// getTail returns the tail pointer value from ring buffer.
// Use readTail in fast-path to avoid updating the whole ring.
func (r *ring) getTail() int {
	return (int)(binary.LittleEndian.Uint16((r.rb)[ringTailOffset:]))
}

func (r *ring) setCookie(val int) {
	binary.LittleEndian.PutUint32((r.rb)[ringCookieOffset:], uint32(val))
}

func (r *ring) setFlags(val int) {
	binary.LittleEndian.PutUint16((r.rb)[ringFlagsOffset:], uint16(val))
}

// setHead set the head pointer value int the ring buffer.
// Use writeHead in fast-path to avoid putting the whole ring into shared memory.
func (r *ring) setHead(val int) {
	binary.LittleEndian.PutUint16((r.rb)[ringHeadOffset:], uint16(val))
}

// setTail set the tail pointer value int the ring buffer.
// Use writeTail in fast-path to avoid putting the whole ring into shared memory.
func (r *ring) setTail(val int) {
	binary.LittleEndian.PutUint16((r.rb)[ringTailOffset:], uint16(val))
}

/* RING END */

// isInterrupt returns true if the queue is in interrupt mode
func (q *Queue) isInterrupt() bool {
	return (q.getFlags() & ringFlagInterrupt) == 0
}

// interrupt performs an interrupt if the queue is in interrupt mode
func (q *Queue) interrupt() error {
	if q.isInterrupt() {
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
