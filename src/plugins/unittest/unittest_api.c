/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_api.h>
#include <vnet/ip/ip_types_api.h>

#include <unittest/unittest.api_enum.h>
#include <unittest/unittest.api_types.h>

static u16 msg_id_base;
#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
increment (fib_prefix_t *pfx, u8 hostbits)
{
  if (pfx->fp_proto == FIB_PROTOCOL_IP4)
    {
      u32 x = clib_net_to_host_u32 (pfx->fp_addr.ip4.as_u32);
      x >>= hostbits;
      x++;
      x <<= hostbits;
      pfx->fp_addr.ip4.as_u32 = clib_host_to_net_u32 (x);
    }
  else if (pfx->fp_proto == FIB_PROTOCOL_IP6)
    {
      // Only support the top /64
      u64 x = clib_net_to_host_u64 (pfx->fp_addr.ip6.as_u64[0]);
      hostbits -= 64;
      x >>= hostbits;
      x++;
      x <<= hostbits;
      pfx->fp_addr.ip6.as_u64[0] = clib_host_to_net_u64 (x);
    }
}

static void
vl_api_unittest_ip_route_add_del_t_handler (
  vl_api_unittest_ip_route_add_del_t *mp)

{
  vl_api_unittest_ip_route_add_del_reply_t *rmp;

  fib_route_path_t *rpaths = NULL, *rpath;
  vl_api_fib_path_t *apath;
  fib_prefix_t aggregate_pfx;
  int rv, ii;
  fib_entry_flag_t entry_flags = FIB_ENTRY_FLAG_NONE;

  ip_prefix_decode (&mp->aggregate_prefix, &aggregate_pfx);

  if (mp->n_paths > 0)
    vec_validate (rpaths, mp->n_paths - 1);

  for (ii = 0; ii < mp->n_paths; ii++)
    {
      apath = &mp->paths[ii];
      rpath = &rpaths[ii];
      rv = fib_api_path_decode (apath, rpath);
      if (rv != 0)
	goto out;
      if ((rpath->frp_flags & FIB_ROUTE_PATH_LOCAL) &&
	  (rpath->frp_sw_if_index == ~0))
	entry_flags |= (FIB_ENTRY_FLAG_CONNECTED | FIB_ENTRY_FLAG_LOCAL);

      if (rv != 0)
	goto out;
    }

  int subnetlen = mp->subnet_prefixlen - aggregate_pfx.fp_len;
  if (subnetlen <= 0 || subnetlen > 24)
    {
      rv = -1;
      goto out;
    }

  u32 count = 0x1 << subnetlen;

  fib_source_t src = FIB_SOURCE_API;
  bool is_multipath = true;
  u32 fib_index = 0;
  u32 hostbits;
  if (aggregate_pfx.fp_proto == FIB_PROTOCOL_IP6)
    {
      // only support IPv6 prefixes <=/64
      if (mp->subnet_prefixlen > 64)
	{
	  rv = -1;
	  goto out;
	}
      hostbits = 128 - 64 - mp->subnet_prefixlen;
    }
  else
    {
      hostbits = 32 - mp->subnet_prefixlen;
    }
  aggregate_pfx.fp_len = mp->subnet_prefixlen;

  for (int i = 0; i < count; i++)
    {
      rv = fib_api_route_add_del (mp->is_add, is_multipath, fib_index,
				  &aggregate_pfx, src, entry_flags, rpaths);
      if (rv != 0)
	goto out;
      increment (&aggregate_pfx, hostbits);
    }
out:
  vec_free (rpaths);

  REPLY_MACRO (VL_API_UNITTEST_IP_ROUTE_ADD_DEL_REPLY);
}

/* Set up the API message handling tables */
/* API definitions */
#include <vnet/format_fns.h>
#include <unittest/unittest.api.c>

clib_error_t *
unittest_plugin_api_hookup (vlib_main_t *vm)
{
  msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (unittest_plugin_api_hookup);
