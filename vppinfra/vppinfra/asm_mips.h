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

#ifndef included_asm_mips_h
#define included_asm_mips_h

/* Encoding of MIPS instructions. */
/* Encoding of opcode field (op). */
#define mips_foreach_opcode						\
  _(SPECIAL) _(REGIMM) _(j) _(jal) _(beq) _(bne) _(blez) _(bgtz)	\
  _(addi) _(addiu) _(slti) _(sltiu) _(andi) _(ori) _(xori) _(lui)	\
  _(COP0) _(COP1) _(COP2) _(COP1X) _(beql) _(bnel) _(blezl) _(bgtzl)	\
  _(daddi) _(daddiu) _(ldl) _(ldr) _(SPECIAL2) _(jalx) _(MDMX) _(O37)	\
  _(lb) _(lh) _(lwl) _(lw) _(lbu) _(lhu) _(lwr) _(lwu)			\
  _(sb) _(sh) _(swl) _(sw) _(sdl) _(sdr) _(swr) _(cache)		\
  _(ll) _(lwc1) _(lwc2) _(pref) _(lld) _(ldc1) _(ldc2) _(ld)		\
  _(sc) _(swc1) _(swc2) _(o73)  _(scd) _(sdc1) _(sdc2) _(sd)

/* Encoding of funct field. */
#define mips_foreach_special_funct					\
  _(sll) _(MOVCI) _(srl) _(sra) _(sllv) _(o05) _(srlv) _(srav)		\
  _(jr) _(jalr) _(movz) _(movn) _(syscall) _(break) _(o16) _(sync)	\
  _(mfhi) _(mthi) _(mflo) _(mtlo) _(dsllv) _(o25) _(dsrlv) _(dsrav)	\
  _(mult) _(multu) _(div) _(divu) _(dmult) _(dmultu) _(ddiv) _(ddivu)	\
  _(add) _(addu) _(sub) _(subu) _(and) _(or) _(xor) _(nor)		\
  _(o50) _(o51) _(slt) _(sltu) _(dadd) _(daddu) _(dsub) _(dsubu)	\
  _(tge) _(tgeu) _(tlt) _(tltu) _(teq) _(o65) _(tne) _(o67)		\
  _(dsll) _(o71) _(dsrl) _(dsra) _(dsll32) _(o75) _(dsrl32) _(dsra32)

/* SPECIAL2 encoding of funct field. */
#define mips_foreach_special2_funct				\
  _(madd) _(maddu) _(mul) _(o03) _(msub) _(msubu) _(o06) _(o07)	\
  _(o10) _(o11) _(o12) _(o13) _(o14) _(o15) _(o16) _(o17)	\
  _(o20) _(o21) _(o22) _(o23) _(o24) _(o25) _(o26) _(o27)	\
  _(o30) _(o31) _(o32) _(o33) _(o34) _(o35) _(o36) _(o37)	\
  _(clz) _(clo) _(o42) _(o43) _(dclz) _(dclo) _(o46) _(o47)	\
  _(o50) _(o51) _(o52) _(o53) _(o54) _(o55) _(o56) _(o57)	\
  _(o60) _(o61) _(o62) _(o63) _(o64) _(o65) _(o66) _(o67)	\
  _(o70) _(o71) _(o72) _(o73) _(o74) _(o75) _(o76) _(sdbbp)

/* REGIMM encoding of rt field. */
#define mips_foreach_regimm_rt						\
  _(bltz) _(bgez) _(bltzl) _(bgezl) _(o04) _(o05) _(o06) _(o07)		\
  _(tgei) _(tgeiu) _(tltiu) _(teqi) _(o14) _(tnei) _(o16) _(o17)	\
  _(bltzal) _(bgezal) _(bltzall) _(bgezall) _(o24) _(o25) _(o26) _(o27)	\
  _(o30) _(o31) _(o32) _(o33) _(o34) _(o35) _(o36) _(o37)

/* COP0 encoding of rs field. */
#define mips_foreach_cop0_rs					\
  _(mfc0) _(dmfc0) _(o02) _(o03) _(mtc0) _(dmtc0) _(o06) _(o07)	\
  _(o10) _(o11) _(o12) _(o13) _(o14) _(o15) _(o16) _(o17)	\
  _(C0) _(o21) _(o22) _(o23) _(o24) _(o25) _(o26) _(o27)	\
  _(o30) _(o31) _(o32) _(o33) _(o34) _(o35) _(o36) _(o37)

/* COP0 encoding of funct when rs == RS_CO */
#define mips_foreach_cop0_funct					\
  _(o00) _(tlbr) _(tlbwi) _(o03) _(o04) _(o05) _(tlbwr) _(o07)	\
  _(tlbp) _(o11) _(o12) _(o13) _(o14) _(o15) _(o16) _(o17)	\
  _(o20) _(o21) _(o22) _(o23) _(o24) _(o25) _(o26) _(o27)	\
  _(eret) _(o31) _(o32) _(o33) _(o34) _(o35) _(o36) _(deret)	\
  _(wait) _(o41) _(o42) _(o43) _(o44) _(o45) _(o46) _(o47)	\
  _(o50) _(o51) _(o52) _(o53) _(o54) _(o55) _(o56) _(o57)	\
  _(o60) _(o61) _(o62) _(o63) _(o64) _(o65) _(o66) _(o67)	\
  _(o70) _(o71) _(o72) _(o73) _(o74) _(o75) _(o76) _(o77)

/* COP1 encoding of rs field. */
#define mips_foreach_cop1_rs						\
  _(mfc1) _(dmfc1) _(cfc1) _(o03) _(mtc1) _(dmtc1) _(ctc1) _(o07)	\
  _(BC1) _(o11) _(o12) _(o13) _(o14) _(o15) _(o16) _(o17)		\
  _(S) _(D) _(o22) _(o23) _(W) _(L) _(o26) _(o27)			\
  _(o30) _(o31) _(o32) _(o33) _(o34) _(o35) _(o36) _(o37)

/* COP1 encoding of funct for S and D */
#define mips_foreach_cop1_funct								\
  _(add) _(sub) _(mul) _(div) _(sqrt) _(abs) _(mov) _(neg)				\
  _(roundl) _(truncl) _(ceill) _(floorl) _(roundw) _(truncw) _(ceilw) _(floorw) 	\
  _(o20) _(MOVCF) _(movz) _(movn) _(o24) _(recip) _(rsqrt) _(o27)			\
  _(o30) _(o31) _(o32) _(o33) _(o34) _(o35) _(o36) _(o37)				\
  _(cvts) _(cvtd) _(o42) _(o43) _(cvtw) _(cvtl) _(o46) _(o47)				\
  _(o50) _(o51) _(o52) _(o53) _(o54) _(o55) _(o56) _(o57)				\
  _(cf) _(cun) _(ceq) _(cueq) _(colt) _(cult) _(cole) _(cule)				\
  _(csf) _(cngle) _(cseq) _(cngl) _(clt) _(cnge) _(cle) _(cngt)

/* COP1X encoding of funct */
#define mips_foreach_cop1x_funct					\
  _(lwxc1) _(ldxc1) _(o02) _(o03) _(o04) _(luxc1) _(o06) _(o07)		\
  _(swxc1) _(sdxc1) _(o12) _(o13) _(o14) _(suxc1) _(o16) _(prefx)	\
  _(o20) _(o21) _(o22) _(o23) _(o24) _(o25) _(o26) _(o27)		\
  _(o30) _(o31) _(o32) _(o33) _(o34) _(o35) _(o36) _(o37)		\
  _(madds) _(maddd) _(o42) _(o43) _(o44) _(o45) _(o46) _(o47)		\
  _(msubs) _(msubd) _(o52) _(o53) _(o54) _(o55) _(o56) _(o57)		\
  _(nmadds) _(nmaddd) _(o62) _(o63) _(o64) _(o65) _(o66) _(o67)		\
  _(nmsubs) _(nmsubd) _(o72) _(o73) _(o74) _(o75) _(o76) _(o77)

#define mips_foreach_mdmx_funct						\
  _(msgn) _(ceq) _(pickf) _(pickt) _(clt) _(cle) _(min) _(max)		\
  _(o10) _(o11) _(sub) _(add) _(and) _(xor) _(or) _(nor)		\
  _(sll) _(o21) _(srl) _(sra) _(o24) _(o25) _(o26) _(o27)		\
  _(alniob) _(alnvob) _(alniqh) _(alnvqh) _(o34) _(o35) _(o36) _(shfl)	\
  _(rzu) _(rnau) _(rneu) _(o43) _(rzs) _(rnas) _(rnes) _(o47)		\
  _(o50) _(o51) _(o52) _(o53) _(o54) _(o55) _(o56) _(o57)		\
  _(mul) _(o61) _(muls) _(mula) _(o64) _(o65) _(suba) _(adda)		\
  _(o70) _(o71) _(o72) _(o73) _(o74) _(o75) _(wac) _(rac)

#define _(f) MIPS_OPCODE_##f,
typedef enum
{
  mips_foreach_opcode
} mips_insn_opcode_t;
#undef _

#define _(f) MIPS_SPECIAL_FUNCT_##f,
typedef enum
{
  mips_foreach_special_funct
} mips_insn_special_funct_t;
#undef _

#define _(f) MIPS_SPECIAL2_FUNCT_##f,
typedef enum
{
  mips_foreach_special2_funct
} mips_insn_special2_funct_t;
#undef _

#define _(f) MIPS_REGIMM_RT_##f,
typedef enum
{
  mips_foreach_regimm_rt
} mips_insn_regimm_rt_t;
#undef _

#define _(f) MIPS_COP0_RS_##f,
typedef enum
{
  mips_foreach_cop0_rs
} mips_insn_cop0_rs_t;
#undef _

#define _(f) MIPS_COP0_FUNCT_##f,
typedef enum
{
  mips_foreach_cop0_funct
} mips_insn_cop0_funct_t;
#undef _

#define _(f) MIPS_COP1_RS_##f,
typedef enum
{
  mips_foreach_cop1_rs
} mips_insn_cop1_rs_t;
#undef _

#define _(f) MIPS_COP1_FUNCT_##f,
typedef enum
{
  mips_foreach_cop1_funct
} mips_insn_cop1_funct_t;
#undef _

#define _(f) MIPS_COP1X_FUNCT_##f,
typedef enum
{
  mips_foreach_cop1x_funct
} mips_insn_cop1x_funct_t;
#undef _

#define _(f) MIPS_MDMX_FUNCT_##f,
typedef enum
{
  mips_foreach_mdmx_funct
} mips_insn_mdmx_funct_t;
#undef _

always_inline mips_insn_opcode_t
mips_insn_get_op (u32 insn)
{
  return (insn >> 26) & 0x3f;
}

always_inline u32
mips_insn_get_rs (u32 insn)
{
  return (insn >> 21) & 0x1f;
}

always_inline u32
mips_insn_get_rt (u32 insn)
{
  return (insn >> 16) & 0x1f;
}

always_inline u32
mips_insn_get_rd (u32 insn)
{
  return (insn >> 11) & 0x1f;
}

always_inline u32
mips_insn_get_sa (u32 insn)
{
  return (insn >> 6) & 0x1f;
}

always_inline u32
mips_insn_get_funct (u32 insn)
{
  return (insn >> 0) & 0x3f;
}

always_inline i32
mips_insn_get_immediate (u32 insn)
{
  return (((i32) insn) << 16) >> 16;
}

always_inline u32
mips_insn_encode_i_type (int op, int rs, int rt, int immediate)
{
  u32 insn;
  insn = immediate;
  insn |= rt << 16;
  insn |= rs << 21;
  insn |= op << 26;

  ASSERT (mips_insn_get_immediate (insn) == immediate);
  ASSERT (mips_insn_get_rt (insn) == rt);
  ASSERT (mips_insn_get_rs (insn) == rt);
  ASSERT (mips_insn_get_op (insn) == op);

  return insn;
}

always_inline u32
mips_insn_encode_j_type (int op, u32 addr)
{
  u32 insn;

  insn = (addr & ((1 << 28) - 1)) / 4;
  insn |= op << 26;

  return insn;
}

always_inline u32
mips_insn_encode_r_type (int op, int rs, int rt, int rd, int sa, int funct)
{
  u32 insn;
  insn = funct;
  insn |= sa << 6;
  insn |= rd << 11;
  insn |= rt << 16;
  insn |= rs << 21;
  insn |= op << 26;

  ASSERT (mips_insn_get_funct (insn) == funct);
  ASSERT (mips_insn_get_sa (insn) == sa);
  ASSERT (mips_insn_get_rd (insn) == rd);
  ASSERT (mips_insn_get_rt (insn) == rt);
  ASSERT (mips_insn_get_rs (insn) == rt);
  ASSERT (mips_insn_get_op (insn) == op);

  return insn;
}

#define mips_insn_r(op,funct,rd,rs,rt,sa)		\
  mips_insn_encode_r_type (MIPS_OPCODE_##op,		\
			   (rs), (rt), (rd), (sa),	\
			   MIPS_##op##_FUNCT_##funct)

#define mips_insn_i(op,rs,rt,imm) \
  mips_insn_encode_i_type (MIPS_OPCODE_##op, (rs), (rt), (imm))

#define mips_insn_j(op,target) \
  mips_insn_encode_i_type (MIPS_OPCODE_##op, (rs), (rt), (imm))

/* Generate unsigned load instructions of data of various sizes. */
always_inline u32
mips_insn_load (u32 rd, i32 offset, u32 base, u32 log2_bytes)
{
  int op;

  ASSERT (log2_bytes < 4);
  switch (log2_bytes)
    {
    case 0:
      op = MIPS_OPCODE_lbu;
      break;
    case 1:
      op = MIPS_OPCODE_lhu;
      break;
    case 2:
      op = MIPS_OPCODE_lwu;
      break;
    case 3:
      op = MIPS_OPCODE_ld;
      break;
    }

  return mips_insn_encode_i_type (op, base, rd, offset);
}

typedef enum
{
  MIPS_REG_SP = 29,
  MIPS_REG_RA = 31,
} mips_reg_t;

#endif /* included_asm_mips_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
