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
	.global cdecl(clib_calljmp)
	.align 4
#ifndef __APPLE__
	.type cdecl(clib_calljmp), @function
#endif
cdecl(clib_calljmp):
	/* Make sure stack is 16-byte aligned. */
	movq %rdx, %rax
	andq $0xf, %rax
	subq %rax, %rdx

	/* Get return address. */
	pop %rax

	/* Switch to new stack. */
	xchgq %rsp, %rdx

	/* Save return address on new stack. */
	push %rax

	/* Save old stack pointer on new stack. */
	push %rdx

	/* Get function. */
	movq %rdi, %rdx

	/* Move argument into place. */
	movq %rsi, %rdi

	/* Away we go. */
	callq *%rdx

	/* Switch back to old stack. */
	movq 8(%rsp), %rdx
	movq 0(%rsp), %rcx
	xchgq %rcx, %rsp

	/* Return to caller. */
	jmpq *%rdx

#elif defined(i386)
	.global cdecl(clib_calljmp)
	.align 4
	.type cdecl(clib_calljmp), @function
cdecl(clib_calljmp):
	/* Get new stack pointer. */
	movl 12(%esp), %edx

	/* Switch stacks. */
	xchgl %esp, %edx

	/* Save old stack pointer on new stack. */
	sub $8, %esp
	movl %edx, 4(%esp)

	/* Put function argument in stack frame. */
	movl 8(%edx), %eax
	movl %eax, 0(%esp)

	/* Get function. */
	movl 4(%edx), %eax

	/* Away we go. */
	call *%eax

	/* Switch back to old stack. */
	movl 4(%esp), %edx
	xchgl %edx, %esp

	/* Return to caller. */
	ret

#elif defined(__SPU__)

#elif defined(__powerpc64__) && (_CALL_ELF == 2)

	.abiversion 2
	.section	".text"

	.align 2
	.p2align 4,,15
	.globl cdecl(clib_calljmp)
	.type	cdecl(clib_calljmp), @function
cdecl(clib_calljmp):
	.cfi_startproc
.L.cdecl(clib_calljmp):
0:	addis 2,12,.TOC.-.L.cdecl(clib_calljmp)@ha
	addi 2,2,.TOC.-.L.cdecl(clib_calljmp)@l
	.localentry	clib_calljmp,.-cdecl(clib_calljmp)

	/* store link register into the stack frame */
	mflr 0
	std 0,16(1)

	/* move stack pointer down for one frame */
	stdu 1,-32(1)
	.cfi_def_cfa_offset 32
	.cfi_offset 65, 16

	/* move func pointer to r12 */
	mr 12,3

	/* pass func_arg as first arg */
	mr 3,4

	/* store old stack pointer into the top of the new stack */
	std 1,-8(5)

	/* set new stack pointer to point at stack_addr - 256 */
	addi 5,5,-256
	mr 1,5

	/* put function pointer into CTR register */
	mtctr 12

	/* store TOC pointer into stack frame */
	std 2,24(1)

	/* unconditional branch to counter register */
	bctrl

	/* load TOC pointer from stack frame */
	ld 2,24(1)

	/* go back to the start of the new stack */
	addi 1,1,256

	/* load old stack pointer */
	ld 1,-8(1)

	/* move stack pointer back to previous frame */
	addi 1,1,32

	/* restore link register from the stack frame */
	.cfi_def_cfa_offset 0
	ld 0,16(1)
	mtlr 0
	.cfi_restore 65
	blr
	.long 0
	.byte 0,0,0,1,128,0,0,0
	.cfi_endproc

#elif defined(__powerpc64__)
	.text

	.globl cdecl(clib_calljmp)
	.section	".opd","aw"
	.align 3
cdecl(clib_calljmp):
	.quad	.L.cdecl(clib_calljmp),.TOC.@tocbase,0
	.previous
	.type	cdecl(clib_calljmp), @function
.L.cdecl(clib_calljmp):

	/* store link register into the stack frame */
	mflr 0
	std 0,16(1)

	/* store function pointer into r9 */
	mr 9,3

	/* move stack pointer down for one frame */
	stdu 1,-112(1)
	/* store old stack pointer into the top of the new stack */
	std 1,-8(5)

	/* set new stack pointer to point at stack_addr - 256 */
	addi 5,5,-256
	mr 1,5

	ld 10,0(9)

	/* store TOC pointer into stack */
	std 2,40(1)

	mr 3,4
	mtctr 10
	ld 11,16(9)
	ld 2,8(9)

	/* unconditional branch to counter register */
	bctrl

	/* load TOC pointer from stack */
	ld 2,40(1)

	/* go back to the start of the new stack */
	addi 1,1,256

	/* load old stack pointer */
	ld 1,-8(1)

	/* move stack pointer back to previous frame */
	addi 1,1,112

	/* restore link register from the stack frame */
	ld 0,16(1)
	mtlr 0
	blr
	.long 0
	.byte 0,0,0,1,128,0,0,0
	.size	cdecl(clib_calljmp),.-.L.cdecl(clib_calljmp)

#elif defined(__powerpc__)

	.global cdecl(clib_calljmp)
	.align 4
	.type cdecl(clib_calljmp), @function
cdecl(clib_calljmp):
	/* Make sure stack is 16 byte aligned. */
	andi. 0, 5, 0xf
	sub  5, 5, 0
	addi 5, 5, -16

	/* Save old stack/link pointer on new stack. */
	stw 1, 0(5)
	mflr 0
	stw 0, 4(5)

	/* account for (sp, lr) tuple, and keep aligned */
	addi 5, 5, -16

	/* Switch stacks. */
	mr 1, 5

	/* Move argument into place. */
	mtctr 3
	mr 3, 4

	/* Away we go. */
	bctrl

	/* back to our synthetic frame */
	addi 1,1,16

	/* Switch back to old stack. */
	lwz 0, 4(1)
	mtlr 0
	lwz 0, 0(1)
	mr 1, 0

	/* Return to caller. */
	blr

#elif defined(__arm__)

	.global cdecl(clib_calljmp)
	.align 4
	.type cdecl(clib_calljmp), %function
cdecl(clib_calljmp):
	/* Make sure stack is 8 byte aligned. */
	bic r2, r2, #7

	/* Allocate space for stack/link pointer on new stack. */
	sub r2, r2, #8

	/* Save old stack/link pointer on new stack. */
	str sp, [r2, #0]
	str lr, [r2, #4]

	/* Switch stacks. */
	mov sp, r2

	/* Save function to call. */
	mov ip, r0

	/* Move argument into place. */
	mov r0, r1

	/* Away we go. */
	bx ip

	/* Switch back to old stack. */
	ldr lr, [sp, #4]
	ldr ip, [sp, #0]
	mov sp, ip

	/* Return to caller. */
	bx lr

#elif defined(__xtensa__)

	.global cdecl(clib_calljmp)
	.align 4
	.type cdecl(clib_calljmp), %function
cdecl(clib_calljmp):
1:	j 1b

#elif defined(__TMS320C6X__)

	.global cdecl(clib_calljmp)
	.align 4
	.type cdecl(clib_calljmp), %function
cdecl(clib_calljmp):
1:	B	.S1     1b

#elif defined(_mips) && __mips == 64

	.global cdecl(clib_calljmp)
	.align 8
	.type cdecl(clib_calljmp), %function
cdecl(clib_calljmp):
	/* Force 16 byte alignment of the new stack */
	li $t1, -16
	and $t0, $a2, $t1
	/* Save old ra/gp/sp on new stack */
	daddiu $t0, $t0, (-24)
	sd $ra, 0($t0)
	sd $gp, 8($t0)
	sd $sp, 16($t0)
	/* Switch stacks */
	move $sp, $t0
	/* Away we go */
	move $t9, $a0
	move $a0, $a1
	jalr $t9
	nop
	/* Switch back to old ra/gp/sp */
	move $t0, $sp
	ld $ra, 0($t0)
	ld $gp, 8($t0)
	ld $sp, 16($t0)
	/* Return to caller */
	jr $ra
	nop

#elif defined (__aarch64__)

// void cdecl(clib_calljmp) (x0=function, x1=arg, x2=new_stack)
	.global	cdecl(clib_calljmp)
	.type	cdecl(clib_calljmp), %function
cdecl(clib_calljmp):
	// save fn ptr
	mov     x3, x0
	// set up fn arg
	mov     x0, x1
	// switch stacks
	mov     x4, sp

	// space for saved sp, lr on new stack
	sub     x2, x2, #16
	mov     sp, x2

	// save old sp and link register on new stack
        str     x4, [sp]
	str     x30,[sp,#8]
        mov     x4, sp

	// go there
        blr     x3

	// restore old sp and link register
	mov     x4, sp

	ldr     x3, [x4]
	ldr     x30,[x4, #8]
        mov     sp, x3
	ret
	.size	cdecl(clib_calljmp), .-cdecl(clib_calljmp)
#else
#error "unknown machine"
#endif

#ifndef __APPLE__
.section .note.GNU-stack,"",%progbits
#endif
