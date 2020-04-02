// Copyright 2020 Cisco Systems Inc.

#include "textflag.h"

// uint16 atomicload16(uint64 volatile* addr);
TEXT ·atomicload16(SB), NOSPLIT, $0-10
	MOVQ	ptr+0(FP), BX
	MOVW	0(BX), AX
	MOVW    AX, ret+8(FP)
	RET

// atomicstore16(uint64 volatile* ptr, uint16 *val)
TEXT ·atomicstore16(SB), NOSPLIT, $0-10
	MOVQ	ptr+0(FP), BX
	MOVW	val+8(FP), AX
	XCHGW	AX, 0(BX)
	RET
