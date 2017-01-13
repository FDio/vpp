/*
 *------------------------------------------------------------------
 * lisp_gpe_api.c - lisp_gpe api
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
#include <vnet/lisp-gpe/lisp_gpe.h>
#include <vnet/lisp-gpe/lisp_gpe_fwd_entry.h>
#include <vnet/lisp-gpe/lisp_gpe_tenant.h>

#include <vnet/vnet_msg_enum.h>

#define vl_api_lisp_gpe_locator_pair_t_endian vl_noop_handler
#define vl_api_lisp_gpe_locator_pair_t_print vl_noop_handler
#define vl_api_lisp_gpe_add_del_fwd_entry_t_endian vl_noop_handler
#define vl_api_lisp_gpe_add_del_fwd_entry_t_print vl_noop_handler

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                             \
_(LISP_GPE_ADD_DEL_FWD_ENTRY, lisp_gpe_add_del_fwd_entry)               \
_(LISP_GPE_ENABLE_DISABLE, lisp_gpe_enable_disable)                     \
_(LISP_GPE_ADD_DEL_IFACE, lisp_gpe_add_del_iface)

static locator_pair_t *
unformat_lisp_loc_pairs (void *locs, u32 rloc_num)
{
  u32 i;
  locator_pair_t *pairs = 0, pair, *p;
  vl_api_lisp_gpe_locator_t *r;

  for (i = 0; i < rloc_num; i++)
    {
      /* local locator */
      r = &((vl_api_lisp_gpe_locator_t *) locs)[i];
      memset (&pair, 0, sizeof (pair));
      ip_address_set (&pair.lcl_loc, &r->addr, r->is_ip4 ? IP4 : IP6);

      pair.weight = r->weight;
      vec_add1 (pairs, pair);
    }

  for (i = rloc_num; i < rloc_num * 2; i++)
    {
      /* remote locators */
      r = &((vl_api_lisp_gpe_locator_t *) locs)[i];
      p = &pairs[i - rloc_num];
      ip_address_set (&p->rmt_loc, &r->addr, r->is_ip4 ? IP4 : IP6);
    }
  return pairs;
}

static int
unformat_lisp_eid_api (gid_address_t * dst, u32 vni, u8 type, void *src,
		       u8 len)
{
  switch (type)
    {
    case 0:			/* ipv4 */
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;
      gid_address_ip_set (dst, src, IP4);
      gid_address_ippref_len (dst) = len;
      ip_prefix_normalize (&gid_address_ippref (dst));
      break;
    case 1:			/* ipv6 */
      gid_address_type (dst) = GID_ADDR_IP_PREFIX;
      gid_address_ip_set (dst, src, IP6);
      gid_address_ippref_len (dst) = len;
      ip_prefix_normalize (&gid_address_ippref (dst));
      break;
    case 2:			/* l2 mac */
      gid_address_type (dst) = GID_ADDR_MAC;
      clib_memcpy (&gid_address_mac (dst), src, 6);
      break;
    default:
      /* unknown type */
      return VNET_API_ERROR_INVALID_VALUE;
    }

  gid_address_vni (dst) = vni;

  return 0;
}

static void
  lisp_gpe_add_del_fwd_entry_t_net_to_host
  (vl_api_lisp_gpe_add_del_fwd_entry_t * mp)
{
  mp->vni = clib_net_to_host_u32 (mp->vni);
  mp->dp_table = clib_net_to_host_u32 (mp->dp_table);
  mp->loc_num = clib_net_to_host_u32 (mp->loc_num);
}

static void
  vl_api_lisp_gpe_add_del_fwd_entry_t_handler
  (vl_api_lisp_gpe_add_del_fwd_entry_t * mp)
{
  vl_api_lisp_gpe_add_del_fwd_entry_reply_t *rmp;
  vnet_lisp_gpe_add_del_fwd_entry_args_t _a, *a = &_a;
  locator_pair_t *pairs = 0;
  int rv = 0;

  lisp_gpe_add_del_fwd_entry_t_net_to_host (mp);
  memset (a, 0, sizeof (a[0]));

  rv = unformat_lisp_eid_api (&a->rmt_eid, mp->vni, mp->eid_type,
			      mp->rmt_eid, mp->rmt_len);
  rv |= unformat_lisp_eid_api (&a->lcl_eid, mp->vni, mp->eid_type,
			       mp->lcl_eid, mp->lcl_len);

  if (mp->loc_num % 2 != 0)
    {
      rv = -1;
      goto send_reply;
    }
  pairs = unformat_lisp_loc_pairs (mp->locs, mp->loc_num / 2);

  if (rv || 0 == pairs)
    goto send_reply;

  a->is_add = mp->is_add;
  a->locator_pairs = pairs;
  a->dp_table = mp->dp_table;
  a->vni = mp->vni;
  a->action = mp->action;

  rv = vnet_lisp_gpe_add_del_fwd_entry (a, 0);
  vec_free (pairs);
send_reply:
  REPLY_MACRO (VL_API_LISP_GPE_ADD_DEL_FWD_ENTRY_REPLY);
}

static void
vl_api_lisp_gpe_enable_disable_t_handler (vl_api_lisp_gpe_enable_disable_t *
					  mp)
{
  vl_api_lisp_gpe_enable_disable_reply_t *rmp;
  int rv = 0;
  vnet_lisp_gpe_enable_disable_args_t _a, *a = &_a;

  a->is_en = mp->is_en;
  vnet_lisp_gpe_enable_disable (a);

  REPLY_MACRO (VL_API_LISP_GPE_ENABLE_DISABLE_REPLY);
}

static void
vl_api_lisp_gpe_add_del_iface_t_handler (vl_api_lisp_gpe_add_del_iface_t * mp)
{
  vl_api_lisp_gpe_add_del_iface_reply_t *rmp;
  int rv = 0;

  if (mp->is_l2)
    {
      if (mp->is_add)
	{
	  if (~0 ==
	      lisp_gpe_tenant_l2_iface_add_or_lock (mp->vni, mp->dp_table))
	    rv = 1;
	}
      else
	lisp_gpe_tenant_l2_iface_unlock (mp->vni);
    }
  else
    {
      if (mp->is_add)
	{
	  if (~0 ==
	      lisp_gpe_tenant_l3_iface_add_or_lock (mp->vni, mp->dp_table))
	    rv = 1;
	}
      else
	lisp_gpe_tenant_l3_iface_unlock (mp->vni);
    }

  REPLY_MACRO (VL_API_LISP_GPE_ADD_DEL_IFACE_REPLY);
}

/*
 * lisp_gpe_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_lisp_gpe;
#undef _
}

static clib_error_t *
lisp_gpe_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = &api_main;

#define _(N,n)                                                  \
    vl_msg_api_set_handlers(VL_API_##N, #n,                     \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_msg;
#undef _

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (lisp_gpe_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
