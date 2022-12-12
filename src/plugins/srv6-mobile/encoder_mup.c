/*
 * sr_policy_rewrite.c: ipv6 sr policy use sid encoders
 *
 * Copyright (c) 2023 BBSakura Networks, Inc. and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/srv6/sr.h>
#include <vnet/ip/ip_types_api.h>

typedef struct
{
  ip6_address_t v6src_addr;
  u32 v6src_len;
  ip4_address_t v4src_addr;

  ip6_address_t v6dst_addr;
  u32 v6dst_len;
  ip4_address_t v4dst_addr;

  u8 qfi; // 6bit
  bool r; // 1bit
  bool u; // 1bit
  u32 teid;
} sid_encoder_mup_param_t;

/**
 * @brief SID encoder by mup
 */

always_inline void
alloc_sr_sid_encoder_mup (void **mem_p, const void *v6src_addr,
			  const u32 v6src_len, const void *v4src_addr,
			  const void *v6dst_addr, const u32 v6dst_len,
			  const void *v4dst_addr, const u8 qfi, const u8 r,
			  const u8 u, const u32 teid)
{
  sid_encoder_mup_param_t *ls_mem = 0;
  ls_mem = clib_mem_alloc (sizeof *ls_mem);
  clib_memset (ls_mem, 0, sizeof *ls_mem);
  *mem_p = ls_mem;

  clib_memcpy_fast (&ls_mem->v6src_addr, v6src_addr, sizeof (ip6_address_t));
  clib_memcpy_fast (&ls_mem->v6src_len, &v6src_len, sizeof (u32));
  clib_memcpy_fast (&ls_mem->v4src_addr, v4src_addr, sizeof (ip4_address_t));

  clib_memcpy_fast (&ls_mem->v6dst_addr, v6dst_addr, sizeof (ip6_address_t));
  clib_memcpy_fast (&ls_mem->v6dst_len, &v6dst_len, sizeof (u32));
  clib_memcpy_fast (&ls_mem->v4dst_addr, v4dst_addr, sizeof (ip4_address_t));

  clib_memcpy_fast (&ls_mem->qfi, &qfi, sizeof (u8));
  clib_memcpy_fast (&ls_mem->r, &r, sizeof (u8));
  clib_memcpy_fast (&ls_mem->u, &u, sizeof (u8));
  clib_memcpy_fast (&ls_mem->teid, &teid, sizeof (u32));
}

always_inline void
write_v6addr_in_pyload (ip6_address_t *v6addr, u8 *payload, u16 payload_len,
			u16 offset, u16 shift)
{
  if (shift == 0)
    {
      clib_memcpy_fast (&v6addr->as_u8[offset], payload, payload_len);
    }
  else
    {
      for (__u16 index = 0; index < sizeof (ip6_address_t); index++)
	{
	  if (payload_len <= index)
	    break;

	  u8 *v6val1 = (__u8 *) (void *) v6addr + offset + index;
	  u8 *v6val2 = (__u8 *) (void *) v6addr + offset + index + 1;
	  *v6val1 |= payload[index] >> shift;
	  *v6val2 |= payload[index] << (8 - shift);
	}
    }
}

static u8 *
sr_sid_encoder_format_mup (u8 *s, va_list *args)
{
  sid_encoder_mup_param_t *ls_mem = va_arg (*args, void *);

  s = format (s, "Flavor: Mup\n\t");
  s = format (s, "src v6 prefix: %U/%d, ", format_ip6_address,
	      &ls_mem->v6src_addr, ls_mem->v6src_len);
  s = format (s, "dst v6 prefix: %U/%d", format_ip6_address,
	      &ls_mem->v6dst_addr, ls_mem->v6dst_len);
  s = format (s, "\n\t");
  s = format (s, "src v4 addr: %U, ", format_ip4_address, &ls_mem->v4src_addr);
  s = format (s, "dst v4 addr: %U ", format_ip4_address, &ls_mem->v4dst_addr);
  s = format (s, "\n\t");
  s = format (s, "qfi: %d, ", ls_mem->qfi);
  s = format (s, "r: %d, ", ls_mem->r);
  s = format (s, "u: %d, ", ls_mem->u);
  s = format (s, "teid: %d", ls_mem->teid);
  s = format (s, "\n");

  return s;
}

static uword
sr_sid_encoder_unformat_mup (unformat_input_t *input, va_list *args)
{
  void **ls_mem = va_arg (*args, void **);
  ip6_address_t v6src_addr, v6dst_addr;
  ip4_address_t v4src_addr, v4dst_addr;
  u32 v6src_len = 0, v6dst_len = 0;
  u32 qfi = 0, r = 0, u = 0, teid = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "mup %U/%d %U %U/%d %U %d %d %d %d",
		    unformat_ip6_address, &v6src_addr, &v6src_len,
		    unformat_ip4_address, &v4src_addr, unformat_ip6_address,
		    &v6dst_addr, &v6dst_len, unformat_ip4_address, &v4dst_addr,
		    &qfi, &r, &u, &teid))
	{
	  break;
	}
      else
	return 0;
    }
  alloc_sr_sid_encoder_mup (ls_mem, &v6src_addr, v6src_len, &v4src_addr,
			    &v6dst_addr, v6dst_len, &v4dst_addr, qfi, r, u,
			    teid);

  return 1;
}

static int
sr_sid_encoder_removal_mup (ip6_sr_sid_encoder_t *encoder)
{
  sid_encoder_mup_param_t *ls_mem = encoder->plugin_mem;

  clib_mem_free (ls_mem);

  return 0;
}

static void
sr_sid_encoder_build_mup (void *mem_p, ip6_address_t *v6src_addr,
			  ip6_address_t *v6dst_addr)
{
  sid_encoder_mup_param_t *ls_mem = mem_p;
  u8 tmp_args = 0;
  u16 s_offset = 0, s_shift = 0, d_offset = 0, d_shift = 0;
  u32 teid = 0;
  s_offset = ls_mem->v6src_len / 8;
  s_shift = ls_mem->v6src_len % 8;
  d_offset = ls_mem->v6dst_len / 8;
  d_shift = ls_mem->v6dst_len % 8;

  *v6src_addr = ls_mem->v6src_addr;
  *v6dst_addr = ls_mem->v6dst_addr;

  write_v6addr_in_pyload (v6src_addr, (u8 *) &ls_mem->v4src_addr,
			  sizeof (ip4_address_t), s_offset, s_shift);
  write_v6addr_in_pyload (v6dst_addr, (u8 *) &ls_mem->v4dst_addr,
			  sizeof (ip4_address_t), d_offset, d_shift);
  d_offset += sizeof (ip4_address_t);
  tmp_args |= ls_mem->qfi << 2;
  tmp_args |= ls_mem->r << 1;
  tmp_args |= ls_mem->u;

  write_v6addr_in_pyload (v6dst_addr, &tmp_args, sizeof (u8), d_offset,
			  d_shift);
  d_offset += sizeof (u8);
  teid = htonl (ls_mem->teid);
  write_v6addr_in_pyload (v6dst_addr, (u8 *) &teid, sizeof (u32), d_offset,
			  d_shift);
}

static clib_error_t *
sr_sid_encoder_mup_init (vlib_main_t *vm)
{
  static u8 keyword_str[] = "mup";
  static u8 def_str[] = "Encoder for mup (mobile user plane)";
  static u8 param_str[] = "<src_v6prefix> <src_v4addr> <dst_v6prefix> "
			  "<src_v4addr> <qfi> <r> <u> <teid>";

  sr_sid_encoder_flavor_register_function (
    vm, keyword_str, def_str, param_str, sr_sid_encoder_format_mup,
    sr_sid_encoder_unformat_mup, sr_sid_encoder_removal_mup,
    sr_sid_encoder_build_mup);
  return 0;
}

VLIB_INIT_FUNCTION (sr_sid_encoder_mup_init);
