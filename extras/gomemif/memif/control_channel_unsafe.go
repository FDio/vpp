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
	"unsafe"
	"os"
	//"bytes"
	//"encoding/binary"
)

// Sends queued message
func (cc *controlChannel) sendMsg() (err error) {
	if len(cc.msgQueue) < 1 {
		return nil
	}
	// Get message buffer
	msg := cc.msgQueue[0]
	// Dequeue
	cc.msgQueue = cc.msgQueue[1:]

	iov := &syscall.Iovec {
		Base: &msg.Buffer.Bytes()[0],
		Len: msgSize,
	}

	msgh := syscall.Msghdr {
		Iov: iov,
		Iovlen: 1,
	}

	if msg.Fd > 0 {
		oob := syscall.UnixRights(msg.Fd)

		/*
		cmsg := syscall.Cmsghdr {
			Len: uint64(syscall.CmsgLen(4)),
			Level: syscall.SOL_SOCKET,
			Type: syscall.SCM_RIGHTS,
		}

		scm := syscall.SocketControlMessage {
			Header: cmsg,
			Data: oob,
		}
		*/

		// first file descriptor to be sent
		// using this function is received by peer each time
		// this function is called
		/*
		buf := new(bytes.Buffer)
		err = binary.Write(buf, binary.LittleEndian, scm.Header)
		if err != nil {
			return fmt.Errorf("msgSend: %s", err)
		}
		err = binary.Write(buf, binary.LittleEndian, scm.Data)
		if err != nil {
			return fmt.Errorf("msgSend: %s", err)
		}

		msgh.Control = (*byte)(unsafe.Pointer(&buf.Bytes()[0]))
		msgh.Controllen = uint64(syscall.CmsgSpace(4))
		*/
		msgh.Control = &oob[0]
		msgh.Controllen = uint64(syscall.CmsgSpace(4))
	}

	_, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(cc.fd), uintptr(unsafe.Pointer(&msgh)), uintptr(0))
	if errno != 0 {
		err = os.NewSyscallError("sendmsg", errno)
                return fmt.Errorf("SYS_SENDMSG: %s", errno)
	}

	return nil
}
