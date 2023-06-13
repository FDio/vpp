/*
 *------------------------------------------------------------------
 * vxlan_api.c - vxlan api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */
#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/udp/udp_local.h>
#include <vnet/format_fns.h>
#include <lawful-intercept/lawful_intercept.api_types.h>
#include <lawful-intercept/lawful_intercept.api_enum.h>

#include "lawful_intercept.h"

static u16 msg_id_base;

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_lawful_interception_add_del_t_handler (
  vl_api_lawful_interception_add_del_t *mp)
{
  vl_api_lawful_interception_add_del_reply_t *rmp;
  int rv = LAWFUL_INTERCEPTION_RETURN_VAL_TYPE__NONE;
  u32 i = 0;

  li_main_t *lm = &li_main;
  ip46_address_t collector;
  ip46_address_t src;
  u16 udp_port = 0;
  ip_address_decode (&mp->src_address, &src);
  ip_address_decode (&mp->collector_address, &collector);
  bool is_add = mp->is_add;
  udp_port = ntohs (mp->udp_port);

  if (is_add)
    {
      for (i = 0; i < vec_len (lm->collectors); i++)
	{
	  if (lm->collectors[i].as_u32 == collector.ip4.as_u32)
	    {
	      if (lm->ports[i] == udp_port)
		rv = LAWFUL_INTERCEPTION_RETURN_VAL_TYPE__COLLECTOR_PORT_ALREADY_CONFIGURED;
	      else
		rv = LAWFUL_INTERCEPTION_RETURN_VAL_TYPE__COLLECTOR_ALREADY_CONFIGURED;
	    }
	}
      vec_add1 (lm->collectors, collector.ip4);
      vec_add1 (lm->ports, udp_port);
      vec_add1 (lm->src_addrs, src.ip4);
    }
  else
    {
      for (i = 0; i < vec_len (lm->collectors); i++)
	{
	  if ((lm->collectors[i].as_u32 == collector.ip4.as_u32) &&
	      lm->ports[i] == udp_port)
	    {
	      vec_delete (lm->collectors, 1, i);
	      vec_delete (lm->ports, 1, i);
	      vec_delete (lm->src_addrs, 1, i);
	    }
	}
    rv = LAWFUL_INTERCEPTION_RETURN_VAL_TYPE__COLLECTOR_NOT_CONFIGURED;
    }

  REPLY_MACRO(VL_API_LAWFUL_INTERCEPTION_ADD_DEL_REPLY);
}

#include <lawful-intercept/lawful_intercept.api.c>
static clib_error_t *
lawful_interception_api_hookup (vlib_main_t *vm)
{
  api_main_t *am = vlibapi_get_main ();

  vl_api_increase_msg_trace_size (am, VL_API_LAWFUL_INTERCEPTION_ADD_DEL,
				  16 * sizeof (u32));

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (lawful_interception_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
