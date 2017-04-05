/*
 *------------------------------------------------------------------
 * l2_api.c - layer 2 forwarding api
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
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_vtr.h>

#include <vnet/vnet_msg_enum.h>

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

#define foreach_vpe_api_msg                                 \
_(L2_XCONNECT_DUMP, l2_xconnect_dump)                       \
_(L2_FIB_CLEAR_TABLE, l2_fib_clear_table)                   \
_(L2_FIB_TABLE_DUMP, l2_fib_table_dump)                     \
_(L2FIB_FLUSH_INT, l2fib_flush_int)                         \
_(L2FIB_FLUSH_BD, l2fib_flush_bd)                           \
_(L2FIB_ADD_DEL, l2fib_add_del)                             \
_(L2_FLAGS, l2_flags)                                       \
_(BRIDGE_DOMAIN_ADD_DEL, bridge_domain_add_del)             \
_(BRIDGE_DOMAIN_DUMP, bridge_domain_dump)                   \
_(BRIDGE_FLAGS, bridge_flags)                               \
_(L2_INTERFACE_VLAN_TAG_REWRITE, l2_interface_vlan_tag_rewrite) \
_(L2_INTERFACE_PBB_TAG_REWRITE, l2_interface_pbb_tag_rewrite) \
_(BRIDGE_DOMAIN_SET_MAC_AGE, bridge_domain_set_mac_age)

static void
send_l2_xconnect_details (unix_shared_memory_queue_t * q, u32 context,
			  u32 rx_sw_if_index, u32 tx_sw_if_index)
{
  vl_api_l2_xconnect_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_L2_XCONNECT_DETAILS);
  mp->context = context;
  mp->rx_sw_if_index = htonl (rx_sw_if_index);
  mp->tx_sw_if_index = htonl (tx_sw_if_index);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_l2_xconnect_dump_t_handler (vl_api_l2_xconnect_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  l2input_main_t *l2im = &l2input_main;
  vnet_sw_interface_t *swif;
  l2_input_config_t *config;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (swif, im->sw_interfaces,
  ({
    config = vec_elt_at_index (l2im->configs, swif->sw_if_index);
    if (config->xconnect)
      send_l2_xconnect_details (q, mp->context, swif->sw_if_index,
                                config->output_sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_l2_fib_clear_table_t_handler (vl_api_l2_fib_clear_table_t * mp)
{
  int rv = 0;
  vl_api_l2_fib_clear_table_reply_t *rmp;

  /* DAW-FIXME: This API should only clear non-static l2fib entries, but
   *            that is not currently implemented.  When that TODO is fixed
   *            this call should be changed to pass 1 instead of 0.
   */
  l2fib_clear_table (0);

  REPLY_MACRO (VL_API_L2_FIB_CLEAR_TABLE_REPLY);
}

static void
send_l2fib_table_entry (vpe_api_main_t * am,
			unix_shared_memory_queue_t * q,
			l2fib_entry_key_t * l2fe_key,
			l2fib_entry_result_t * l2fe_res, u32 context)
{
  vl_api_l2_fib_table_entry_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_L2_FIB_TABLE_ENTRY);

  mp->bd_id =
    ntohl (l2input_main.bd_configs[l2fe_key->fields.bd_index].bd_id);

  mp->mac = l2fib_make_key (l2fe_key->fields.mac, 0);
  mp->sw_if_index = ntohl (l2fe_res->fields.sw_if_index);
  mp->static_mac = l2fe_res->fields.static_mac;
  mp->filter_mac = l2fe_res->fields.filter;
  mp->bvi_mac = l2fe_res->fields.bvi;
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_l2_fib_table_dump_t_handler (vl_api_l2_fib_table_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  bd_main_t *bdm = &bd_main;
  l2fib_entry_key_t *l2fe_key = NULL;
  l2fib_entry_result_t *l2fe_res = NULL;
  u32 ni, bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  unix_shared_memory_queue_t *q;
  uword *p;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* see l2fib_table_dump: ~0 means "any" */
  if (bd_id == ~0)
    bd_index = ~0;
  else
    {
      p = hash_get (bdm->bd_index_by_bd_id, bd_id);
      if (p == 0)
	return;

      bd_index = p[0];
    }

  l2fib_table_dump (bd_index, &l2fe_key, &l2fe_res);

  vec_foreach_index (ni, l2fe_key)
  {
    send_l2fib_table_entry (am, q, vec_elt_at_index (l2fe_key, ni),
			    vec_elt_at_index (l2fe_res, ni), mp->context);
  }
  vec_free (l2fe_key);
  vec_free (l2fe_res);
}

static void
vl_api_l2fib_add_del_t_handler (vl_api_l2fib_add_del_t * mp)
{
  bd_main_t *bdm = &bd_main;
  l2input_main_t *l2im = &l2input_main;
  vl_api_l2fib_add_del_reply_t *rmp;
  int rv = 0;
  u64 mac = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  u32 static_mac;
  u32 filter_mac;
  u32 bvi_mac;
  uword *p;

  mac = mp->mac;

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto bad_sw_if_index;
    }
  bd_index = p[0];

  if (mp->is_add)
    {
      filter_mac = mp->filter_mac ? 1 : 0;
      if (filter_mac == 0)
	{
	  VALIDATE_SW_IF_INDEX (mp);
	  if (vec_len (l2im->configs) <= sw_if_index)
	    {
	      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	      goto bad_sw_if_index;
	    }
	  else
	    {
	      l2_input_config_t *config;
	      config = vec_elt_at_index (l2im->configs, sw_if_index);
	      if (config->bridge == 0)
		{
		  rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
		  goto bad_sw_if_index;
		}
	    }
	}
      static_mac = mp->static_mac ? 1 : 0;
      bvi_mac = mp->bvi_mac ? 1 : 0;
      l2fib_add_entry (mac, bd_index, sw_if_index, static_mac, filter_mac,
		       bvi_mac);
    }
  else
    {
      l2fib_del_entry (mac, bd_index);
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2FIB_ADD_DEL_REPLY);
}

static void
vl_api_l2fib_flush_int_t_handler (vl_api_l2fib_flush_int_t * mp)
{
  int rv = 0;
  vlib_main_t *vm = vlib_get_main ();
  vl_api_l2fib_flush_int_reply_t *rmp;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);
  l2fib_flush_int_mac (vm, sw_if_index);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_L2FIB_FLUSH_INT_REPLY);
}

static void
vl_api_l2fib_flush_bd_t_handler (vl_api_l2fib_flush_bd_t * mp)
{
  int rv = 0;
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_l2fib_flush_bd_reply_t *rmp;

  u32 bd_id = ntohl (mp->bd_id);
  uword *p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }
  l2fib_flush_bd_mac (vm, *p);
out:
  REPLY_MACRO (VL_API_L2FIB_FLUSH_BD_REPLY);
}

static void
vl_api_l2_flags_t_handler (vl_api_l2_flags_t * mp)
{
  vl_api_l2_flags_reply_t *rmp;
  int rv = 0;
  u32 rbm = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 flags = ntohl (mp->feature_bitmap) & L2INPUT_VALID_MASK;
  rbm = l2input_intf_bitmap_enable (sw_if_index, flags, mp->is_set);

  BAD_SW_IF_INDEX_LABEL;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_L2_FLAGS_REPLY,
  ({
    rmp->resulting_feature_bitmap = ntohl(rbm);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_bridge_domain_set_mac_age_t_handler (vl_api_bridge_domain_set_mac_age_t
					    * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_bridge_domain_set_mac_age_reply_t *rmp;
  int rv = 0;
  u32 bd_id = ntohl (mp->bd_id);
  uword *p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }
  bd_set_mac_age (vm, *p, mp->mac_age);
out:
  REPLY_MACRO (VL_API_BRIDGE_DOMAIN_SET_MAC_AGE_REPLY);
}

static void
vl_api_bridge_domain_add_del_t_handler (vl_api_bridge_domain_add_del_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_bridge_domain_add_del_reply_t *rmp;
  int rv = 0;
  u32 enable_flags = 0, disable_flags = 0;
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;

  if (mp->is_add)
    {
      bd_index = bd_find_or_add_bd_index (bdm, bd_id);

      if (mp->flood)
	enable_flags |= L2_FLOOD;
      else
	disable_flags |= L2_FLOOD;

      if (mp->uu_flood)
	enable_flags |= L2_UU_FLOOD;
      else
	disable_flags |= L2_UU_FLOOD;

      if (mp->forward)
	enable_flags |= L2_FWD;
      else
	disable_flags |= L2_FWD;

      if (mp->arp_term)
	enable_flags |= L2_ARP_TERM;
      else
	disable_flags |= L2_ARP_TERM;

      if (mp->learn)
	enable_flags |= L2_LEARN;
      else
	disable_flags |= L2_LEARN;

      if (enable_flags)
	bd_set_flags (vm, bd_index, enable_flags, 1 /* enable */ );

      if (disable_flags)
	bd_set_flags (vm, bd_index, disable_flags, 0 /* disable */ );

      bd_set_mac_age (vm, bd_index, mp->mac_age);
    }
  else
    rv = bd_delete_bd_index (bdm, bd_id);

  REPLY_MACRO (VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY);
}

static void
send_bridge_domain_details (unix_shared_memory_queue_t * q,
			    l2_bridge_domain_t * bd_config,
			    u32 n_sw_ifs, u32 context)
{
  vl_api_bridge_domain_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_BRIDGE_DOMAIN_DETAILS);
  mp->bd_id = ntohl (bd_config->bd_id);
  mp->flood = bd_feature_flood (bd_config);
  mp->uu_flood = bd_feature_uu_flood (bd_config);
  mp->forward = bd_feature_forward (bd_config);
  mp->learn = bd_feature_learn (bd_config);
  mp->arp_term = bd_feature_arp_term (bd_config);
  mp->bvi_sw_if_index = ntohl (bd_config->bvi_sw_if_index);
  mp->mac_age = bd_config->mac_age;
  mp->n_sw_ifs = ntohl (n_sw_ifs);
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
send_bd_sw_if_details (l2input_main_t * l2im,
		       unix_shared_memory_queue_t * q,
		       l2_flood_member_t * member, u32 bd_id, u32 context)
{
  vl_api_bridge_domain_sw_if_details_t *mp;
  l2_input_config_t *input_cfg;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_BRIDGE_DOMAIN_SW_IF_DETAILS);
  mp->bd_id = ntohl (bd_id);
  mp->sw_if_index = ntohl (member->sw_if_index);
  input_cfg = vec_elt_at_index (l2im->configs, member->sw_if_index);
  mp->shg = input_cfg->shg;
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_bridge_domain_dump_t_handler (vl_api_bridge_domain_dump_t * mp)
{
  bd_main_t *bdm = &bd_main;
  l2input_main_t *l2im = &l2input_main;
  unix_shared_memory_queue_t *q;
  l2_bridge_domain_t *bd_config;
  u32 bd_id, bd_index;
  u32 end;

  q = vl_api_client_index_to_input_queue (mp->client_index);

  if (q == 0)
    return;

  bd_id = ntohl (mp->bd_id);

  bd_index = (bd_id == ~0) ? 0 : bd_find_or_add_bd_index (bdm, bd_id);
  end = (bd_id == ~0) ? vec_len (l2im->bd_configs) : bd_index + 1;
  for (; bd_index < end; bd_index++)
    {
      bd_config = l2input_bd_config_from_index (l2im, bd_index);
      /* skip dummy bd_id 0 */
      if (bd_config && (bd_config->bd_id > 0))
	{
	  u32 n_sw_ifs;
	  l2_flood_member_t *m;

	  n_sw_ifs = vec_len (bd_config->members);
	  send_bridge_domain_details (q, bd_config, n_sw_ifs, mp->context);

	  vec_foreach (m, bd_config->members)
	  {
	    send_bd_sw_if_details (l2im, q, m, bd_config->bd_id, mp->context);
	  }
	}
    }
}

static void
vl_api_bridge_flags_t_handler (vl_api_bridge_flags_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_bridge_flags_reply_t *rmp;
  int rv = 0;
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  u32 flags = ntohl (mp->feature_bitmap);
  uword *p;

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }

  bd_index = p[0];

  bd_set_flags (vm, bd_index, flags, mp->is_set);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_BRIDGE_FLAGS_REPLY,
  ({
    rmp->resulting_feature_bitmap = ntohl(flags);
  }));
  /* *INDENT-ON* */
}

static void
  vl_api_l2_interface_vlan_tag_rewrite_t_handler
  (vl_api_l2_interface_vlan_tag_rewrite_t * mp)
{
  int rv = 0;
  vl_api_l2_interface_vlan_tag_rewrite_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u32 vtr_op;

  VALIDATE_SW_IF_INDEX (mp);

  vtr_op = ntohl (mp->vtr_op);

  /* The L2 code is unsuspicious */
  switch (vtr_op)
    {
    case L2_VTR_DISABLED:
    case L2_VTR_PUSH_1:
    case L2_VTR_PUSH_2:
    case L2_VTR_POP_1:
    case L2_VTR_POP_2:
    case L2_VTR_TRANSLATE_1_1:
    case L2_VTR_TRANSLATE_1_2:
    case L2_VTR_TRANSLATE_2_1:
    case L2_VTR_TRANSLATE_2_2:
      break;

    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  rv = l2vtr_configure (vm, vnm, ntohl (mp->sw_if_index), vtr_op,
			ntohl (mp->push_dot1q), ntohl (mp->tag1),
			ntohl (mp->tag2));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2_INTERFACE_VLAN_TAG_REWRITE_REPLY);
}

static void
  vl_api_l2_interface_pbb_tag_rewrite_t_handler
  (vl_api_l2_interface_pbb_tag_rewrite_t * mp)
{
  vl_api_l2_interface_pbb_tag_rewrite_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  vlib_main_t *vm = vlib_get_main ();
  u32 vtr_op;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  vtr_op = ntohl (mp->vtr_op);

  switch (vtr_op)
    {
    case L2_VTR_DISABLED:
    case L2_VTR_PUSH_2:
    case L2_VTR_POP_2:
    case L2_VTR_TRANSLATE_2_1:
      break;

    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto bad_sw_if_index;
    }

  rv = l2pbb_configure (vm, vnm, ntohl (mp->sw_if_index), vtr_op,
			mp->b_dmac, mp->b_smac, ntohs (mp->b_vlanid),
			ntohl (mp->i_sid), ntohs (mp->outer_tag));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2_INTERFACE_PBB_TAG_REWRITE_REPLY);
}

/*
 * l2_api_hookup
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
  foreach_vl_msg_name_crc_l2;
#undef _
}

static clib_error_t *
l2_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (l2_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
