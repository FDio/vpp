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

import "fmt"

func (q *Queue) ReadPacket(pkt []byte) (int, error) {
	var mask int = q.ringSize - 1
	var slot int
	var lastSlot int
        var length int
        var offset int
        var pktOffset int = 0
        var nSlots int

	if q.e.args.IsMaster {
		slot = int(q.lastHead)
		lastSlot = q.readHead()
	} else {
		slot = int(q.lastTail)
		lastSlot = q.readTail()
	}

	nSlots = lastSlot - slot
        if nSlots == 0 {
                return 0, nil
        }

	// copy descriptor from shm
        desc := newDescBuf()
	q.getDescBuf(slot & mask, desc)
        length = desc.getLength()
        offset = desc.getOffset()

        copy(pkt[:], q.e.regions[desc.getRegion()].data[offset:offset + length])
        pktOffset += length

	slot++
	nSlots--

	for (desc.getFlags() & descFlagNext) == descFlagNext {
		if nSlots == 0 {
                        //FIXME: this should report error as this may indicate
                        //       a problem with peer endpoint
			return 0, fmt.Errorf("Incomplete chained buffer, may suggest peer error.")
		}

		q.getDescBuf(slot & mask, desc)
                length = desc.getLength()
                offset = desc.getOffset()

                copy(pkt[pktOffset:], q.e.regions[desc.getRegion()].data[offset:offset + length])
                pktOffset += length

		slot++
		nSlots--
	}

	if q.e.args.IsMaster {
		q.lastHead = uint16(slot)
		q.writeTail(slot)
	} else {
		q.lastTail = uint16(slot)

		head := q.readHead()
		nSlots = q.ringSize - head + int(q.lastTail);

		for nSlots > 0 {
			q.getDescBuf(head & mask, desc)
			desc.setLength(int(q.e.run.PacketBufferSize))
			q.putDescBuf(head & mask, desc)
			head++
			nSlots--
		}
		q.writeHead(head)
	}

	return pktOffset, nil
}
