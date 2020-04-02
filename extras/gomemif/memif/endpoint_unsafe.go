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
)

func MemfdCreate() (mfd int, err error) {
	p0, err := syscall.BytePtrFromString("memif_region_0")
	if err != nil {
		return -1, fmt.Errorf("MemfdCreate: %s", err)
	}

	u_mfd, _, errno := syscall.Syscall(SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(p0)), uintptr(MFD_ALLOW_SEALING), uintptr(0))
	if errno != 0 {
		return -1, fmt.Errorf("MemfdCreate: %s", os.NewSyscallError("memfd_create", errno))
	}

	return int(u_mfd), nil
}
