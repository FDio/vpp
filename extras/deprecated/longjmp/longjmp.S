/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 */
/*
  Copyright (c) 2005 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#if defined(__APPLE__)
# define cdecl(s) _##s
#else
# define cdecl(s) s
#endif

#if defined(__x86_64__)
	.global cdecl(clib_setjmp)
	.align 4
#ifndef __APPLE__
	.type cdecl(clib_setjmp), @function
#endif

cdecl(clib_setjmp):
	movq %rbx, 8*0(%rdi)
	movq %rbp, 8*1(%rdi)
	movq %r12, 8*2(%rdi)
	movq %r13, 8*3(%rdi)
	movq %r14, 8*4(%rdi)
	movq %r15, 8*5(%rdi)

	/* Save SP after return. */
	leaq 8(%rsp), %rdx
	movq %rdx, 8*6(%rdi)

	/* Save PC we are returning to from stack frame. */
	movq 0(%rsp), %rax
	movq %rax, 8*7(%rdi)

	/* Give back user's return value. */
	movq %rsi, %rax
	ret

	.global cdecl(clib_longjmp)
	.align 4
#ifndef __APPLE__
	.type cdecl(clib_longjmp), @function
#endif
cdecl(clib_longjmp):
        /* Restore regs. */
	movq 8*0(%rdi), %rbx
	movq 8*1(%rdi), %rbp
	movq 8*2(%rdi), %r12
	movq 8*3(%rdi), %r13
	movq 8*4(%rdi), %r14
	movq 8*5(%rdi), %r15
	movq 8*6(%rdi), %rsp
	movq 8*7(%rdi), %rdx

	/* Give back user's return value. */
	movq %rsi, %rax

	/* Away we go. */
	jmpq *%rdx

#elif defined(i386)
	.global cdecl(clib_setjmp)
	.align 4
	.type cdecl(clib_setjmp), @function
cdecl(clib_setjmp):
	movl 4(%esp), %ecx

	movl %ebp, 4*0(%ecx)
	movl %ebx, 4*1(%ecx)
	movl %edi, 4*2(%ecx)
	movl %esi, 4*3(%ecx)

	/* Save SP after return. */
	leal 4(%esp), %edx
	movl %edx, 4*4(%ecx)

	/* Save PC we are returning to from stack frame. */
	movl 0(%esp), %eax
	movl %eax, 4*5(%ecx)

	/* Give back user's return value. */
	movl 8(%esp), %eax
	ret

	.global cdecl(clib_longjmp)
	.align 4
	.type cdecl(clib_longjmp), @function
cdecl(clib_longjmp):
	movl 4(%esp), %ecx

	/* Give back user's return value. */
	movl 8(%esp), %eax

        /* Restore regs. */
	movl 4*0(%ecx), %ebp
	movl 4*1(%ecx), %ebx
	movl 4*2(%ecx), %edi
	movl 4*3(%ecx), %esi
	movl 4*4(%ecx), %esp
	movl 4*5(%ecx), %edx

	/* Away we go. */
	jmp *%edx

#elif defined(__SPU__)

#elif defined(__powerpc64__)

	.text

#define _prologue(n)				\
    .align 2 ;					\
    .globl n, .##n ;				\
    .section ".opd", "aw" ;			\
    .align 3 ;					\
n:  .quad .##n, .TOC.@tocbase, 0 ;		\
    .previous ;					\
    .size n, 24 ;				\
    .type .##n, @function ;			\
.##n:

#define _foreach_14_31							\
_ (14, 0)  _ (15, 1)  _ (16, 2)  _ (17, 3)  _ (18, 4)  _ (19, 5)	\
_ (20, 6)  _ (21, 7)  _ (22, 8)  _ (23, 9)  _ (24, 10) _ (25, 11)	\
_ (26, 12) _ (27, 13) _ (28, 14) _ (29, 15) _ (30, 16) _ (31, 17)

#define _foreach_20_31						\
_ (20, 0) _ (21, 1) _ (22, 2) _ (23, 3) _ (24, 4)  _ (25, 5)	\
_ (26, 6) _ (27, 7) _ (28, 8) _ (29, 9) _ (30, 10) _ (31, 11)

#ifdef __ALTIVEC__
#define CLIB_POWERPC_ALTIVEC_N_REGS 12
#else
#define CLIB_POWERPC_ALTIVEC_N_REGS 0
#endif

_prologue (cdecl(clib_setjmp))
	mflr 0
	std 0, 8*0(3)
	std 1, 8*1(3)
	std 2, 8*2(3)
	mfcr 0
	std 0, 8*3(3)
	mfspr 0, 256
	stw 0, 8*4(3)

	/* gprs 14 - 31 */
#define _(a,b) std a, 8*((b) + 4 + 18*0)(3) ;
	_foreach_14_31
#undef _

	/* fprs 14 - 31 */
#define _(a,b) stfd a, 8*((b) + 4 + 18*1)(3) ;
	_foreach_14_31
#undef _

#if CLIB_POWERPC_ALTIVEC_N_REGS > 0
	/* vrs 20 - 31 */
	li 5, 8*(4 + 18*2)
#define _(a,b) stvx a, 5, 3 ; addi 5, 5, 16 ;
	_foreach_20_31
#undef _
#endif /* CLIB_POWERPC_ALTIVEC_N_REGS > 0 */

	/* Return value. */
	mr 3, 4

	blr

_prologue (cdecl(clib_longjmp))
	ld 0, 8*0(3)
	mtlr 0
	ld 1, 8*1(3)
	ld 2, 8*2(3)
	ld 0, 8*3(3)
	mtcrf 0xff, 0
	lwz 0, 8*3(3)
	mtspr 256, 0

	/* gprs 14 - 31 */
#define _(a,b) ld a, 8*((b) + 4 + 18*0)(3) ;
	_foreach_14_31
#undef _

	/* fprs 14 - 31 */
#define _(a,b) lfd a, 8*((b) + 4 + 18*1)(3) ;
	_foreach_14_31
#undef _

#if CLIB_POWERPC_ALTIVEC_N_REGS > 0
	/* vrs 20 - 31 */
	li 5, 8*(4 + 18*2)
#define _(a,b) lvx a, 5, 3 ; addi 5, 5, 16 ;
	_foreach_20_31
#undef _
#endif /* CLIB_POWERPC_ALTIVEC_N_REGS > 0 */

	/* Return value. */
	mr 3, 4

	blr

#elif defined(__powerpc__)

#define _foreach_14_31							\
_ (14, 0)  _ (15, 1)  _ (16, 2)  _ (17, 3)  _ (18, 4)  _ (19, 5)	\
_ (20, 6)  _ (21, 7)  _ (22, 8)  _ (23, 9)  _ (24, 10) _ (25, 11)	\
_ (26, 12) _ (27, 13) _ (28, 14) _ (29, 15) _ (30, 16) _ (31, 17)

#define _foreach_20_31						\
_ (20, 0) _ (21, 1) _ (22, 2) _ (23, 3) _ (24, 4)  _ (25, 5)	\
_ (26, 6) _ (27, 7) _ (28, 8) _ (29, 9) _ (30, 10) _ (31, 11)

#ifdef __ALTIVEC__
#define CLIB_POWERPC_ALTIVEC_N_REGS 12
#else
#define CLIB_POWERPC_ALTIVEC_N_REGS 0
#endif

	.global cdecl(clib_setjmp)
	.align 4
	.type cdecl(clib_setjmp), @function
cdecl(clib_setjmp):
	mflr 0
	stw 0, 4*0(3)
	stw 1, 4*1(3)
	mfcr 0
	stw 0, 4*2(3)
#if CLIB_POWERPC_ALTIVEC_N_REGS > 0
	mfspr 0, 256
#endif
	stw 0, 4*3(3)

#if CLIB_POWERPC_ALTIVEC_N_REGS > 0
	li 5, 4*4
#define _(a,b) stvx a, 3, 5 ; addi 5, 5, 16 ;
	_foreach_20_31
#undef _
#endif /* CLIB_POWERPC_ALTIVEC_N_REGS > 0 */

	/* gp 14 - 31 */
#define _(a,b) stw a,  4*(1*(b) + 4 + 4*CLIB_POWERPC_ALTIVEC_N_REGS + 0*18)(3) ;
	_foreach_14_31
#undef _

	/* fp 14 - 31 */
#define _(a,b) stfd a, 4*(2*(b) + 4 + 4*CLIB_POWERPC_ALTIVEC_N_REGS + 1*18)(3) ;
	_foreach_14_31
#undef _

	/* Return value. */
	mr 3, 4

	blr

	.global cdecl(clib_longjmp)
	.align 4
	.type cdecl(clib_longjmp), @function
cdecl(clib_longjmp):

	lwz 0, 4*0(3)
	mtlr 0
	lwz 1, 4*1(3)
	lwz 0, 4*2(3)
	mtcr 0
	lwz 0, 4*3(3)
#if CLIB_POWERPC_ALTIVEC_N_REGS > 0
	mtspr 256, 0
#endif

#if CLIB_POWERPC_ALTIVEC_N_REGS > 0
	li 5, 4*4
#define _(a,b) lvx a, 3, 5 ; addi 5, 5, 16 ;
	_foreach_20_31
#undef _
#endif /* CLIB_POWERPC_ALTIVEC_N_REGS > 0 */

	/* gp 14 - 31 */
#define _(a,b) lwz a, 4*(1*(b) + 4 + 4*CLIB_POWERPC_ALTIVEC_N_REGS + 0*18)(3) ;
	_foreach_14_31
#undef _

	/* fp 14 - 31 */
#define _(a,b) lfd a, 4*(2*(b) + 4 + 4*CLIB_POWERPC_ALTIVEC_N_REGS + 1*18)(3) ;
	_foreach_14_31
#undef _

	/* Return value. */
	mr 3, 4

	blr

#elif defined(__arm__)

	.global cdecl(clib_setjmp)
	.align 4
	.type cdecl(clib_setjmp), %function
cdecl(clib_setjmp):
	mov ip, r0		/* jmp buffer */

	/* Save integer registers */
	stmia ip!, {v1-v6, sl, fp, sp, lr}

#ifdef __IWMMXT__
	/* Save the call-preserved iWMMXt registers.  */
	wstrd wr10, [ip], #8
	wstrd wr11, [ip], #8
	wstrd wr12, [ip], #8
	wstrd wr13, [ip], #8
	wstrd wr14, [ip], #8
	wstrd wr15, [ip], #8
#endif

	/* Give back user's return value. */
	mov r0, r1
	bx lr

	.global cdecl(clib_longjmp)
	.align 4
	.type cdecl(clib_longjmp), %function
cdecl(clib_longjmp):
	mov ip, r0		/* jmp buffer */

	/* Restore integer registers. */
	ldmia     ip!,  {v1-v6, sl, fp, sp, lr}

#ifdef __IWMMXT__
	/* Save the call-preserved iWMMXt registers.  */
	wldrd wr10, [ip], #8
	wldrd wr11, [ip], #8
	wldrd wr12, [ip], #8
	wldrd wr13, [ip], #8
	wldrd wr14, [ip], #8
	wldrd wr15, [ip], #8
#endif

	/* Give back user's return value. */
	mov r0, r1
	bx lr

#elif defined(__xtensa__)

	/* FIXME implement if needed. */
	.global cdecl(clib_setjmp)
	.align 4
	.type cdecl(clib_setjmp), %function
cdecl(clib_setjmp):
1:	j 1b

	.global cdecl(clib_longjmp)
	.align 4
	.type cdecl(clib_longjmp), @function
cdecl(clib_longjmp):
1:	j 1b

#elif defined(__TMS320C6X__)

	/* FIXME implement if needed. */
	.global cdecl(clib_setjmp)
	.align 4
	.type cdecl(clib_setjmp), %function
cdecl(clib_setjmp):
1:	B	.S1     1b

	.global cdecl(clib_longjmp)
	.align 4
	.type cdecl(clib_longjmp), @function
cdecl(clib_longjmp):
1:	B	.S1     1b

#elif defined(_mips) && __mips == 64

	.global cdecl(clib_setjmp)
	.align 8
	.type cdecl(clib_setjmp), %function
cdecl(clib_setjmp):
	sd $ra, 0($a0)
	sd $sp, 8($a0)
	sd $gp, 16($a0)
	sd $16, 24($a0)
	sd $17, 32($a0)
	sd $18, 40($a0)
	sd $19, 48($a0)
	sd $20, 56($a0)
	sd $21, 64($a0)
	sd $22, 72($a0)
	sd $23, 80($a0)
	sd $30, 88($a0)
	move $v0, $a1
	jr $ra
	nop

	.global cdecl(clib_longjmp)
	.align 8
	.type cdecl(clib_longjmp), @function
cdecl(clib_longjmp):
	move $v0, $a1
	bne $v0, $0, 1f
	nop
	daddu $v0, $v0, 1
1:
	ld $ra, 0($a0)
	ld $sp, 8($a0)
	ld $gp, 16($a0)
	ld $16, 24($a0)
	ld $17, 32($a0)
	ld $18, 40($a0)
	ld $19, 48($a0)
	ld $20, 56($a0)
	ld $21, 64($a0)
	ld $22, 72($a0)
	ld $23, 80($a0)
	ld $30, 88($a0)
	jr $ra
	nop

#elif defined (__aarch64__)
/*
   Copyright (c) 2011, 2012 ARM Ltd
   All rights reserved.
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. The name of the company may not be used to endorse or promote
      products derived from this software without specific prior written
      permission.
   THIS SOFTWARE IS PROVIDED BY ARM LTD ``AS IS'' AND ANY EXPRESS OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL ARM LTD BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#define GPR_LAYOUT			\
	REG_PAIR (x19, x20,  0);	\
	REG_PAIR (x21, x22, 16);	\
	REG_PAIR (x23, x24, 32);	\
	REG_PAIR (x25, x26, 48);	\
	REG_PAIR (x27, x28, 64);	\
	REG_PAIR (x29, x30, 80);	\
	REG_ONE (x16,      96)
#define FPR_LAYOUT			\
	REG_PAIR ( d8,  d9, 112);	\
	REG_PAIR (d10, d11, 128);	\
	REG_PAIR (d12, d13, 144);	\
	REG_PAIR (d14, d15, 160);
// int cdecl(clib_setjmp) (jmp_buf)
	.global	cdecl(clib_setjmp)
	.type	cdecl(clib_setjmp), %function
cdecl(clib_setjmp):
	mov	x16, sp
#define REG_PAIR(REG1, REG2, OFFS)	stp REG1, REG2, [x0, OFFS]
#define REG_ONE(REG1, OFFS)		str REG1, [x0, OFFS]
	GPR_LAYOUT
	FPR_LAYOUT
#undef REG_PAIR
#undef REG_ONE
	mov	x0, x1
	ret
	.size	cdecl(clib_setjmp), .-cdecl(clib_setjmp)
// void cdecl(clib_longjmp) (jmp_buf, int) __attribute__ ((noreturn))
	.global	cdecl(clib_longjmp)
	.type	cdecl(clib_longjmp), %function
cdecl(clib_longjmp):
#define REG_PAIR(REG1, REG2, OFFS)	ldp REG1, REG2, [x0, OFFS]
#define REG_ONE(REG1, OFFS)		ldr REG1, [x0, OFFS]
	GPR_LAYOUT
	FPR_LAYOUT
#undef REG_PAIR
#undef REG_ONE
	mov	sp, x16
	mov     x0, x1
	// cmp	w1, #0
	// cinc	w0, w1, eq
	// use br not ret, as ret is guaranteed to mispredict
	br	x30
	.size	cdecl(clib_longjmp), .-cdecl(clib_longjmp)

#else
#error "unknown machine"
#endif

#ifndef __APPLE__
.section .note.GNU-stack,"",%progbits
#endif
