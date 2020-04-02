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

func (e *Endpoint) WritePacket(qid int, pkt []byte) error {
        if qid >= len(e.txQueues) {
                return fmt.Errorf("Invalid queue id")
        }
	q := e.txQueues[qid]

	rSize := uint16(1 << q.log2RingSize)
	mask := rSize - 1
	n := 0
	var err error = nil
	var d Desc
	var slot uint16
	var nFree uint16
	var packetBufferSize uint32 = e.run.PacketBufferSize

retry:
	// block until packet is transmitted
	// timeout?
	for {
		if e.args.IsMaster {
			slot = q.readTail()
			nFree = q.readHead() - slot
		} else {
			slot = q.readHead()
			nFree = rSize - slot + q.readTail()
		}

		// make sure there are enough buffers available
		if nFree == 0 {
			q.interrupt()
			continue
		}

		// copy descriptor from shm
		d, err = q.readDesc(slot & mask)
		if err != nil {
			return err
		}
		// reset flags
		d.Flags = 0
		// reset length
		if e.args.IsMaster {
			packetBufferSize = d.Length
		}
		d.Length = 0

		// write packet into memif buffer
		n = q.writeBuffer(&d, pkt, packetBufferSize)
		for n < len(pkt) {
			nFree--
			if nFree == 0 {
				q.interrupt()
                                // FIXME: dont copy data already in shm
				goto retry
			}
			d.Flags |= descFlagNext
			q.writeDesc(slot & mask, &d)
			slot++

			// copy descriptor from shm
			d, err = q.readDesc(slot & mask)
			if err != nil {
				return err
			}
			// reset flags
			d.Flags = 0
			// reset length
			if e.args.IsMaster {
				packetBufferSize = d.Length
			}
			d.Length = 0

			n += q.writeBuffer(&d, pkt[n:], packetBufferSize)
		}

		// copy descriptor to shm
		q.writeDesc(slot & mask, &d)

		// increment counters
		slot++

		if e.args.IsMaster {
			q.writeTail(slot)
		} else {
			q.writeHead(slot)
		}

		q.interrupt()

		return nil
	}
}
