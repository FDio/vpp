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
  Copyright (c) 2004 Eliot Dresselhaus

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

#include <vppinfra/clib.h>
#include <vppinfra/error.h>

#ifdef __mips__

/* Let code below know we've defined _clib_backtrace */
#define clib_backtrace_defined

#include <vppinfra/asm_mips.h>

uword
clib_backtrace (uword * callers, uword max_callers, uword n_frames_to_skip)
{
  u32 *pc;
  void *sp;
  uword i, saved_pc;

  /* Figure current PC, saved PC and stack pointer. */
  asm volatile (".set push\n"
		".set noat\n" "move %[saved_pc], $31\n" "move %[sp], $29\n"
		/* Fetches current PC. */
		"la $at, 1f\n"
		"jalr %[pc], $at\n"
		"nop\n"
		"1:\n"
		".set pop\n":[pc] "=r" (pc),
		[saved_pc] "=r" (saved_pc),[sp] "=r" (sp));

  /* Also skip current frame. */
  n_frames_to_skip += 1;

  for (i = 0; i < max_callers + n_frames_to_skip; i++)
    {
      mips_insn_opcode_t op;
      mips_insn_special_funct_t funct;
      i32 insn, rs, rt, rd, immediate, found_saved_pc;
      u32 *start_pc;

      /* Parse instructions until we reach prologue for this
         stack frame.  We'll need to figure out where saved
         PC is and where previous stack frame lives. */
      start_pc = pc;
      found_saved_pc = 0;
      while (1)
	{
	  insn = *--pc;
	  op = mips_insn_get_op (insn);
	  funct = mips_insn_get_funct (insn);
	  rs = mips_insn_get_rs (insn);
	  rt = mips_insn_get_rt (insn);
	  rd = mips_insn_get_rd (insn);
	  immediate = mips_insn_get_immediate (insn);

	  switch (op)
	    {
	    default:
	      break;

	    case MIPS_OPCODE_sd:
	    case MIPS_OPCODE_sw:
	      /* Trace stores of return address. */
	      if (rt == MIPS_REG_RA)
		{
		  void *addr = sp + immediate;

		  /* If RA is stored somewhere other than in the
		     stack frame, give up. */
		  if (rs != MIPS_REG_SP)
		    goto backtrace_done;

		  ASSERT (immediate % 4 == 0);
		  if (op == MIPS_OPCODE_sw)
		    saved_pc = ((u32 *) addr)[0];
		  else
		    saved_pc = ((u64 *) addr)[0];
		  found_saved_pc = 1;
		}
	      break;

	    case MIPS_OPCODE_addiu:
	    case MIPS_OPCODE_daddiu:
	    case MIPS_OPCODE_addi:
	    case MIPS_OPCODE_daddi:
	      if (rt == MIPS_REG_SP)
		{
		  if (rs != MIPS_REG_SP)
		    goto backtrace_done;

		  ASSERT (immediate % 4 == 0);

		  /* Assume positive offset is part of the epilogue.
		     E.g.
		     jr ra
		     add sp,sp,100
		   */
		  if (immediate > 0)
		    continue;

		  /* Negative offset means allocate stack space.
		     This could either be the prologue or could be due to
		     alloca. */
		  sp -= immediate;

		  /* This frame will not save RA. */
		  if (i == 0)
		    goto found_prologue;

		  /* Assume that addiu sp,sp,-N without store of ra means
		     that we have not found the prologue yet. */
		  if (found_saved_pc)
		    goto found_prologue;
		}
	      break;

	    case MIPS_OPCODE_slti:
	    case MIPS_OPCODE_sltiu:
	    case MIPS_OPCODE_andi:
	    case MIPS_OPCODE_ori:
	    case MIPS_OPCODE_xori:
	    case MIPS_OPCODE_lui:
	    case MIPS_OPCODE_ldl:
	    case MIPS_OPCODE_ldr:
	    case MIPS_OPCODE_lb:
	    case MIPS_OPCODE_lh:
	    case MIPS_OPCODE_lwl:
	    case MIPS_OPCODE_lw:
	    case MIPS_OPCODE_lbu:
	    case MIPS_OPCODE_lhu:
	    case MIPS_OPCODE_lwr:
	    case MIPS_OPCODE_lwu:
	    case MIPS_OPCODE_ld:
	      /* Give up when we find anyone setting the stack pointer. */
	      if (rt == MIPS_REG_SP)
		goto backtrace_done;
	      break;

	    case MIPS_OPCODE_SPECIAL:
	      if (rd == MIPS_REG_SP)
		switch (funct)
		  {
		  default:
		    /* Give up when we find anyone setting the stack pointer. */
		    goto backtrace_done;

		  case MIPS_SPECIAL_FUNCT_break:
		  case MIPS_SPECIAL_FUNCT_jr:
		  case MIPS_SPECIAL_FUNCT_sync:
		  case MIPS_SPECIAL_FUNCT_syscall:
		  case MIPS_SPECIAL_FUNCT_tge:
		  case MIPS_SPECIAL_FUNCT_tgeu:
		  case MIPS_SPECIAL_FUNCT_tlt:
		  case MIPS_SPECIAL_FUNCT_tltu:
		  case MIPS_SPECIAL_FUNCT_teq:
		  case MIPS_SPECIAL_FUNCT_tne:
		    /* These instructions can validly have rd == MIPS_REG_SP */
		    break;
		  }
	      break;
	    }
	}

    found_prologue:
      /* Check sanity of saved pc. */
      if (saved_pc & 3)
	goto backtrace_done;
      if (saved_pc == 0)
	goto backtrace_done;

      if (i >= n_frames_to_skip)
	callers[i - n_frames_to_skip] = saved_pc;
      pc = uword_to_pointer (saved_pc, u32 *);
    }

backtrace_done:
  if (i < n_frames_to_skip)
    return 0;
  else
    return i - n_frames_to_skip;
}
#endif /* __mips__ */

#ifndef clib_backtrace_defined
#define clib_backtrace_defined

typedef struct clib_generic_stack_frame_t
{
  struct clib_generic_stack_frame_t *prev;
  void *return_address;
} clib_generic_stack_frame_t;

/* This will only work if we have a frame pointer.
   Without a frame pointer we have to parse the machine code to
   parse the stack frames. */
uword
clib_backtrace (uword * callers, uword max_callers, uword n_frames_to_skip)
{
  clib_generic_stack_frame_t *f;
  uword i;

  f = __builtin_frame_address (0);

  /* Also skip current frame. */
  n_frames_to_skip += 1;

  for (i = 0; i < max_callers + n_frames_to_skip; i++)
    {
      f = f->prev;
      if (!f)
	goto backtrace_done;
      if (clib_abs ((void *) f - (void *) f->prev) > (64 * 1024))
	goto backtrace_done;
      if (i >= n_frames_to_skip)
	callers[i - n_frames_to_skip] = pointer_to_uword (f->return_address);
    }

backtrace_done:
  if (i < n_frames_to_skip)
    return 0;
  else
    return i - n_frames_to_skip;
}
#endif /* clib_backtrace_defined */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
