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

typedef struct
{
  ip6_address_t v6src_addr;
  ip6_address_t v6dst_addr;
} sid_encoder_flexible_param_t;

/**
 * @brief SID encoder by flaxible
 */

always_inline void
alloc_sr_sid_encoder_flexible (void **mem_p, const void *v6src_addr,
			       const void *v6dst_addr)
{
  sid_encoder_flexible_param_t *ls_mem = 0;
  ls_mem = clib_mem_alloc (sizeof *ls_mem);
  clib_memset (ls_mem, 0, sizeof *ls_mem);
  *mem_p = ls_mem;

  clib_memcpy_fast (&ls_mem->v6src_addr, v6src_addr, sizeof (ip6_address_t));
  clib_memcpy_fast (&ls_mem->v6dst_addr, v6dst_addr, sizeof (ip6_address_t));
}

static u8 *
sr_sid_encoder_format_flaxible (u8 *s, va_list *args)
{
  sid_encoder_flexible_param_t *ls_mem = va_arg (*args, void *);

  s = format (s, "Flavor: Flaxible\n\t");
  s = format (s, "src v6: %U, ", format_ip6_address, &ls_mem->v6src_addr);
  s = format (s, "dst v6: %U ", format_ip6_address, &ls_mem->v6dst_addr);
  s = format (s, "\n");

  return s;
}

static uword
sr_sid_encoder_unformat_flaxible (unformat_input_t *input, va_list *args)
{
  void **ls_mem = va_arg (*args, void **);
  ip6_address_t src_v6addr, dst_v6addr;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "flaxible %U %U", unformat_ip6_address, &src_v6addr,
		    unformat_ip6_address, &dst_v6addr))
	{
	  break;
	}
      else
	return 0;
    }

  alloc_sr_sid_encoder_flexible (ls_mem, &src_v6addr, &dst_v6addr);

  return 1;
}

static void
sr_sid_encoder_build_flaxible (void *mem_p, ip6_address_t *v6src_addr,
			       ip6_address_t *v6dst_addr)
{
  sid_encoder_flexible_param_t *ls_mem = mem_p;

  *v6src_addr = ls_mem->v6src_addr;
  *v6dst_addr = ls_mem->v6dst_addr;
}

static int
sr_sid_encoder_removal_flaxible (ip6_sr_sid_encoder_t *encoder)
{
  sid_encoder_flexible_param_t *ls_mem = encoder->plugin_mem;

  clib_mem_free (ls_mem);

  return 0;
}

static clib_error_t *
sr_sid_encoder_flaxible_init (vlib_main_t *vm)
{
  static u8 keyword_str[] = "flaxible";
  static u8 def_str[] = "User selected src/dst v6addr";
  static u8 param_str[] = "<src_v6addr> <dst_v6addr>";

  sr_sid_encoder_flavor_register_function (
    vm, keyword_str, def_str, param_str, sr_sid_encoder_format_flaxible,
    sr_sid_encoder_unformat_flaxible, sr_sid_encoder_removal_flaxible,
    sr_sid_encoder_build_flaxible);
  return 0;
}

VLIB_INIT_FUNCTION (sr_sid_encoder_flaxible_init);
