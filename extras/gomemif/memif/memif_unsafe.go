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
	"unsafe"
)

// readHead reads ring head directly form the shared memory
func (q *Queue) readHead() (head int) {
	return (int)(*(*uint16)(unsafe.Pointer(&q.i.regions[q.ring.region].data[q.ring.offset+ringHeadOffset])))
	// return atomicload16(&q.i.regions[q.region].data[q.offset + descHeadOffset])
}

// readTail reads ring tail directly form the shared memory
func (q *Queue) readTail() (tail int) {
	return (int)(*(*uint16)(unsafe.Pointer(&q.i.regions[q.ring.region].data[q.ring.offset+ringTailOffset])))
	// return atomicload16(&q.i.regions[q.region].data[q.offset + descTailOffset])
}

// writeHead writes ring head directly to the shared memory
func (q *Queue) writeHead(value int) {
	*(*uint16)(unsafe.Pointer(&q.i.regions[q.ring.region].data[q.ring.offset+ringHeadOffset])) = *(*uint16)(unsafe.Pointer(&value))
	//atomicstore16(&q.i.regions[q.region].data[q.offset + descHeadOffset], value)
}

// writeTail writes ring tail directly to the shared memory
func (q *Queue) writeTail(value int) {
	*(*uint16)(unsafe.Pointer(&q.i.regions[q.ring.region].data[q.ring.offset+ringTailOffset])) = *(*uint16)(unsafe.Pointer(&value))
	//atomicstore16(&q.i.regions[q.region].data[q.offset + descTailOffset], value)
}

func (q *Queue) setDescLength(slot int, length int) {
	*(*uint16)(unsafe.Pointer(&q.i.regions[q.ring.region].data[q.ring.offset+ringSize+slot*descSize+descLengthOffset])) = *(*uint16)(unsafe.Pointer(&length))
}

// getFlags reads ring flags directly from the shared memory
func (q *Queue) getFlags() int {
	return (int)(*(*uint16)(unsafe.Pointer(&q.i.regions[q.ring.region].data[q.ring.offset+ringFlagsOffset])))
}
