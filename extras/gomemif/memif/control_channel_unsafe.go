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
	"os"
	"syscall"
	"unsafe"
)

// sendMsg sends a control message from contorl channels message queue
func (cc *controlChannel) sendMsg() (err error) {
	if len(cc.msgQueue) < 1 {
		return nil
	}
	// Get message buffer
	msg := cc.msgQueue[0]
	// Dequeue
	cc.msgQueue = cc.msgQueue[1:]

	iov := &syscall.Iovec{
		Base: &msg.Buffer.Bytes()[0],
		Len:  msgSize,
	}

	msgh := syscall.Msghdr{
		Iov:    iov,
		Iovlen: 1,
	}

	if msg.Fd > 0 {
		oob := syscall.UnixRights(msg.Fd)
		msgh.Control = &oob[0]
		msgh.Controllen = uint64(syscall.CmsgSpace(4))
	}

	_, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(cc.event.Fd), uintptr(unsafe.Pointer(&msgh)), uintptr(0))
	if errno != 0 {
		err = os.NewSyscallError("sendmsg", errno)
		return fmt.Errorf("SYS_SENDMSG: %s", errno)
	}

	return nil
}
