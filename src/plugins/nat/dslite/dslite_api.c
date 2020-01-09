/*
 *------------------------------------------------------------------
 * dslite_api.c - DS-Lite API
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <vnet/ip/ip_types_api.h>
#include <nat/dslite/dslite.h>
#include <nat/dslite/dslite.api_enum.h>
#include <nat/dslite/dslite.api_types.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>
#include <vlibmemory/api.h>

#define REPLY_MSG_ID_BASE dm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_dslite_set_aftr_addr_t_handler (vl_api_dslite_set_aftr_addr_t * mp)
{
  vl_api_dslite_set_aftr_addr_reply_t *rmp;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;
  ip6_address_t ip6_addr;
  ip4_address_t ip4_addr;

  memcpy (&ip6_addr.as_u8, mp->ip6_addr, 16);
  memcpy (&ip4_addr.as_u8, mp->ip4_addr, 4);

  rv = dslite_set_aftr_ip6_addr (dm, &ip6_addr);
  if (rv == 0)
    rv = dslite_set_aftr_ip4_addr (dm, &ip4_addr);

  REPLY_MACRO (VL_API_DSLITE_SET_AFTR_ADDR_REPLY);
}

static void
vl_api_dslite_get_aftr_addr_t_handler (vl_api_dslite_get_aftr_addr_t * mp)
{
  vl_api_dslite_get_aftr_addr_reply_t *rmp;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_DSLITE_GET_AFTR_ADDR_REPLY,
  ({
    memcpy (rmp->ip4_addr, &dm->aftr_ip4_addr.as_u8, 4);
    memcpy (rmp->ip6_addr, &dm->aftr_ip6_addr.as_u8, 16);
  }))
  /* *INDENT-ON* */
}

static void
vl_api_dslite_set_b4_addr_t_handler (vl_api_dslite_set_b4_addr_t * mp)
{
  vl_api_dslite_set_b4_addr_reply_t *rmp;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;
  ip6_address_t ip6_addr;
  ip4_address_t ip4_addr;

  memcpy (&ip6_addr.as_u8, mp->ip6_addr, 16);
  memcpy (&ip4_addr.as_u8, mp->ip4_addr, 4);

  rv = dslite_set_b4_ip6_addr (dm, &ip6_addr);
  if (rv == 0)
    rv = dslite_set_b4_ip4_addr (dm, &ip4_addr);

  REPLY_MACRO (VL_API_DSLITE_SET_B4_ADDR_REPLY);
}

static void
vl_api_dslite_get_b4_addr_t_handler (vl_api_dslite_get_b4_addr_t * mp)
{
  vl_api_dslite_get_b4_addr_reply_t *rmp;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_DSLITE_GET_B4_ADDR_REPLY,
  ({
    memcpy (rmp->ip4_addr, &dm->b4_ip4_addr.as_u8, 4);
    memcpy (rmp->ip6_addr, &dm->b4_ip6_addr.as_u8, 16);
  }))
  /* *INDENT-ON* */
}

static void
  vl_api_dslite_add_del_pool_addr_range_t_handler
  (vl_api_dslite_add_del_pool_addr_range_t * mp)
{
  vl_api_dslite_add_del_pool_addr_range_reply_t *rmp;
  dslite_main_t *dm = &dslite_main;
  int rv = 0;
  ip4_address_t this_addr;
  u32 start_host_order, end_host_order;
  int count;
  u32 *tmp;

  tmp = (u32 *) mp->start_addr;
  start_host_order = clib_host_to_net_u32 (tmp[0]);
  tmp = (u32 *) mp->end_addr;
  end_host_order = clib_host_to_net_u32 (tmp[0]);

  // TODO:
  // end_host_order < start_host_order

  count = (end_host_order - start_host_order) + 1;
  memcpy (&this_addr.as_u8, mp->start_addr, 4);

  rv = nat_add_del_ip4_pool_addrs (&dm->pool, this_addr, count, mp->is_add, 0);

  REPLY_MACRO (VL_API_DSLITE_ADD_DEL_POOL_ADDR_RANGE_REPLY);
}

static void
send_dslite_address_details (nat_ip4_pool_addr_t * a,
			     vl_api_registration_t * reg, u32 context)
{
  dslite_main_t *dm = &dslite_main;
  vl_api_dslite_address_details_t *rmp;

  rmp = vl_msg_api_alloc (sizeof (*rmp));

  clib_memset (rmp, 0, sizeof (*rmp));

  rmp->_vl_msg_id = ntohs (VL_API_DSLITE_ADDRESS_DETAILS + dm->msg_id_base);
  clib_memcpy (rmp->ip_address, &(a->addr), 4);
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_dslite_address_dump_t_handler (vl_api_dslite_address_dump_t * mp)
{
  vl_api_registration_t *reg;
  dslite_main_t *dm = &dslite_main;
  nat_ip4_pool_addr_t *a;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  vec_foreach (a, dm->pool.pool_addr)
    {
      send_dslite_address_details (a, reg, mp->context);
    }
  /* *INDENT-ON* */
}

/* API definitions */
#include <vnet/format_fns.h>
#include <nat/dslite/dslite.api.c>

/* Set up the API message handling tables */
clib_error_t *
dslite_api_hookup (vlib_main_t * vm)
{
  dslite_main_t *dm = &dslite_main;

  dm->msg_id_base = setup_message_id_table ();
  return 0;
}
