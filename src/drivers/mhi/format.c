/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mhi.h>
#include <mhi_regs.h>

static u8 *
_format_reg (u8 *s, u32 offset, u32 val, int no_zero, u32 mask,
	     const char *block_name, int is_bhi)
{
  u32 indent = format_get_indent (s);
  u32 rv = 0, f, v;
  u8 *s2 = 0;
  int line = 0;
  int found = 0;

#define MHI_REG_DEF(o, rn, m)                                                 \
  if (offset == o)                                                            \
    {                                                                         \
      found = 1;                                                              \
      if (line++)                                                             \
	s = format (s, "\n%U", format_white_space, indent);                   \
      vec_reset_length (s2);                                                  \
      s2 = format (s2, "[0x%02x] %s:", o, #rn);                               \
      rv = val;                                                               \
      s = format (s, "%-32v = 0x%08x", s2, rv);                               \
      f = 0;                                                                  \
      m                                                                       \
    }
#define __(l, fn)                                                             \
  v = (rv >> f) & pow2_mask (l);                                              \
  if ((pow2_mask (l) << f) & mask)                                            \
    if (v || (!no_zero && #fn[0] != '_'))                                     \
      {                                                                       \
	vec_reset_length (s2);                                                \
	s = format (s, "\n%U", format_white_space, indent + 2);               \
	s2 = format (s2, "[%2u:%2u] %s", f + l - 1, f, #fn);                  \
	s = format (s, "%-30v = ", s2);                                       \
	if (l < 3)                                                            \
	  s = format (s, "%u", v);                                            \
	else if (l <= 8)                                                      \
	  s = format (s, "0x%02x (%u)", v, v);                                \
	else if (l <= 16)                                                     \
	  s = format (s, "0x%04x", v);                                        \
	else                                                                  \
	  s = format (s, "0x%08x", v);                                        \
      }                                                                       \
  f += l;

  if (is_bhi)
    {
      foreach_bhi_reg;
    }
  else
    {
      foreach_mhi_reg;
    }

  if (!found)
    s = format (s, "[0x%02x] %s_UNKNOWN: = 0x%08x", offset, block_name, val);

#undef MHI_REG_DEF
#undef __

  vec_free (s2);

  return s;
}

u8 *
format_mhi_ee (u8 *s, va_list *args)
{
  u32 ee = va_arg (*args, u32);

  const char *mhi_ee_str[] = {
#define _(_v, _n, _d) [MHI_EE_##_n] = _d,
    foreach_mhi_ee
#undef _
  };

  if (ee < ARRAY_LEN (mhi_ee_str) && mhi_ee_str[ee])
    return format (s, "%s", mhi_ee_str[ee]);

  return format (s, "Unknown (0x%x)", ee);
}

u8 *
format_mhi_state (u8 *s, va_list *args)
{
  u32 st = va_arg (*args, u32);

  const char *mhi_st_str[] = {
#define _(_v, _n, _d) [MHI_STATE_##_n] = _d,
    foreach_mhi_state
#undef _
  };

  if (st < ARRAY_LEN (mhi_st_str) && mhi_st_str[st])
    return format (s, "%s", mhi_st_str[st]);

  return format (s, "Unknown (0x%x)", st);
}

u8 *
format_mhi_pkt_type (u8 *s, va_list *args)
{
  u32 type = va_arg (*args, u32);

  const char *mhi_pkt_type_str[] = {
#define _(_v, _n, _d) [_v] = _d,
    foreach_mhi_pkt_type
#undef _
  };

  if (type < ARRAY_LEN (mhi_pkt_type_str) && mhi_pkt_type_str[type])
    return format (s, "%s", mhi_pkt_type_str[type]);

  return format (s, "Unknown (0x%x)", type);
}

u8 *
format_mhi_chan_state (u8 *s, va_list *args)
{
  u32 st = va_arg (*args, u32);

  const char *mhi_ch_st_str[] = {
#define _(_v, _n, _d) [MHI_CH_STATE_##_n] = _d,
    foreach_mhi_ch_state
#undef _
  };

  if (st < ARRAY_LEN (mhi_ch_st_str) && mhi_ch_st_str[st])
    return format (s, "%s", mhi_ch_st_str[st]);

  return format (s, "Unknown (0x%x)", st);
}

u8 *
format_mhi_tre (u8 *s, va_list *args)
{
  mhi_tre_t *t = va_arg (*args, mhi_tre_t *);
  mhi_pkt_type_t type = t->type;
  u32 code = t->code;

  s = format (s, "%U: ", format_mhi_pkt_type, type);

  switch (type)
    {
    case MHI_PKT_TYPE_NOOP:
      break;
    case MHI_PKT_TYPE_TRANSFER:
    case MHI_PKT_TYPE_COALESCING:
      s = format (s, "ptr 0x%lx len %u flags [ %s%s%s%s]", t->ptr, t->t_len,
		  t->ieot ? "IEOT " : "", t->ieob ? "IEOB " : "",
		  t->chain ? "CHAIN " : "", t->bei ? "BEI " : "");
      break;
    case MHI_PKT_TYPE_RESET_CHAN:
    case MHI_PKT_TYPE_STOP_CHAN:
    case MHI_PKT_TYPE_START_CHAN:
      s = format (s, "chan %u", t->chid);
      break;
    case MHI_PKT_TYPE_STATE_CHANGE:
      s = format (s, "%U", format_mhi_state, (t->dword0 >> 24) & 0xFF);
      break;
    case MHI_PKT_TYPE_CMD_COMPLETION:
      s = format (s, "code %u ptr 0x%lx", code, t->ptr);
      break;
    case MHI_PKT_TYPE_TX:
    case MHI_PKT_TYPE_RSC_TX:
      s = format (s, "chan %u code %u len %u", code, code, t->len);
      break;
    case MHI_PKT_TYPE_EE:
      s = format (s, "%U", format_mhi_ee, (t->dword0 >> 24) & 0xFF);
      break;
    case MHI_PKT_TYPE_TSYNC:
    case MHI_PKT_TYPE_BW_REQ:
      s = format (s, "d0 0x%08x d1 0x%08x", t->dword0, t->dword1);
      break;
    default:
      s = format (s, "code %u ptr 0x%lx d0 0x%08x d1 0x%08x", code, t->ptr,
		  t->dword0, t->dword1);
      break;
    }
  return s;
}

u8 *
format_mhi_reg_read (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 val = va_arg (*args, u32);
  return _format_reg (s, offset, val, 0, 0xffffffff, "MHI", 0);
}

u8 *
format_mhi_reg_write (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 val = va_arg (*args, u32);
  return _format_reg (s, offset, val, 1, 0xffffffff, "MHI", 0);
}

u8 *
format_mhi_reg_diff (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 old = va_arg (*args, u32);
  u32 new = va_arg (*args, u32);
  return _format_reg (s, offset, new, 0, old ^ new, "MHI", 0);
}

u8 *
format_bhi_reg_read (u8 *s, va_list *args)
{
  u32 offset = va_arg (*args, u32);
  u32 val = va_arg (*args, u32);
  return _format_reg (s, offset, val, 0, 0xffffffff, "BHI", 1);
}
