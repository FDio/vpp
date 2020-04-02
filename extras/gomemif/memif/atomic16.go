// Copyright 2020 Cisco Systems Inc.

package memif

//go:noescape
func atomicstore16(ptr *uint8, val uint16)

//go:nosplit
//go:noinline
func atomicload16(ptr *uint8) (ret uint16)
