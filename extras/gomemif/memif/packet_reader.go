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
)

type copyOp struct {
        region *MemoryRegion
        // from/start/begin/first
        begin uint32
        // to/end/end/last
        end uint32
}

// dispatch reads packets from the shm and dispatches them.
func (e *Endpoint) ReadPacket(qid int) ([]byte, error) {
        if qid >= len(e.rxQueues) {
                return nil, fmt.Errorf("Invalid queue id")
        }

        q := &e.rxQueues[qid]
	rSize := uint16(1 << q.log2RingSize)
	mask := rSize - 1
	var slot uint16
	var lastSlot uint16
        var length uint64
        var offset uint64 = 0
        var cops []copyOp

	if e.args.IsMaster {
		slot = q.lastHead
		lastSlot = q.readHead()
	} else {
		slot = q.lastTail
		lastSlot = q.readTail()
	}

	nSlots := lastSlot - slot
        if nSlots == 0 {
                return []byte{}, nil
        }

	// copy descriptor from shm
	desc, _ := q.readDesc(slot & mask)
        length = uint64(desc.Length)
        cops = append(cops, copyOp{
                region: &e.regions[desc.Region],
                begin: desc.Offset,
                end: desc.Offset + desc.Length,
        })

	slot++
	nSlots--

	for (desc.Flags & descFlagNext) == descFlagNext {
		if nSlots == 0 {
			return nil, fmt.Errorf("Incomplete packet")
		}

		desc, _ = q.readDesc(slot & mask)
                length += uint64(desc.Length)
                cops = append(cops, copyOp{
                        region: &e.regions[desc.Region],
                        begin: desc.Offset,
                        end: desc.Offset + desc.Length,
                })

		slot++
		nSlots--
	}

        buf := make([]byte, length)
	for _, cop := range(cops) {
                copy(buf[offset:], cop.region.data[cop.begin:cop.end])
                offset += length
        }

	if e.args.IsMaster {
		q.lastHead = slot
		q.writeTail(slot)
	} else {
		q.lastTail = slot

		head := q.readHead()
		nSlots = rSize - head + q.lastTail;

		for nSlots > 0 {
			desc, _ := q.readDesc(head & mask)
			desc.Length = e.run.PacketBufferSize
			q.writeDesc(head & mask, &desc)
			head++
			nSlots--
		}
		q.writeHead(head)
	}

	return buf, nil
}
