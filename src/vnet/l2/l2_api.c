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
#include <vnet/l2/l2_learn.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

#define vl_api_bridge_domain_details_t_endian vl_noop_handler
#define vl_api_bridge_domain_details_t_print vl_noop_handler

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
_(L2FIB_FLUSH_ALL, l2fib_flush_all)                         \
_(L2FIB_FLUSH_INT, l2fib_flush_int)                         \
_(L2FIB_FLUSH_BD, l2fib_flush_bd)                           \
_(L2FIB_ADD_DEL, l2fib_add_del)                             \
_(WANT_L2_MACS_EVENTS, want_l2_macs_events)		    \
_(L2_FLAGS, l2_flags)                                       \
_(SW_INTERFACE_SET_L2_XCONNECT, sw_interface_set_l2_xconnect)   \
_(SW_INTERFACE_SET_L2_BRIDGE, sw_interface_set_l2_bridge)       \
_(L2_PATCH_ADD_DEL, l2_patch_add_del)				\
_(L2_INTERFACE_EFP_FILTER, l2_interface_efp_filter)             \
_(BD_IP_MAC_ADD_DEL, bd_ip_mac_add_del)                         \
_(BD_IP_MAC_DUMP, bd_ip_mac_dump)				\
_(BRIDGE_DOMAIN_ADD_DEL, bridge_domain_add_del)                 \
_(BRIDGE_DOMAIN_DUMP, bridge_domain_dump)                       \
_(BRIDGE_FLAGS, bridge_flags)                                   \
_(L2_INTERFACE_VLAN_TAG_REWRITE, l2_interface_vlan_tag_rewrite) \
_(L2_INTERFACE_PBB_TAG_REWRITE, l2_interface_pbb_tag_rewrite)   \
_(BRIDGE_DOMAIN_SET_MAC_AGE, bridge_domain_set_mac_age)         \
_(SW_INTERFACE_SET_VPATH, sw_interface_set_vpath)

static void
send_l2_xconnect_details (vl_api_registration_t * reg, u32 context,
			  u32 rx_sw_if_index, u32 tx_sw_if_index)
{
  vl_api_l2_xconnect_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_L2_XCONNECT_DETAILS);
  mp->context = context;
  mp->rx_sw_if_index = htonl (rx_sw_if_index);
  mp->tx_sw_if_index = htonl (tx_sw_if_index);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_l2_xconnect_dump_t_handler (vl_api_l2_xconnect_dump_t * mp)
{
  vl_api_registration_t *reg;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  l2input_main_t *l2im = &l2input_main;
  vnet_sw_interface_t *swif;
  l2_input_config_t *config;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* *INDENT-OFF* */
  pool_foreach (swif, im->sw_interfaces,
  ({
    config = vec_elt_at_index (l2im->configs, swif->sw_if_index);
    if (config->xconnect)
      send_l2_xconnect_details (reg, mp->context, swif->sw_if_index,
                                config->output_sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_l2_fib_clear_table_t_handler (vl_api_l2_fib_clear_table_t * mp)
{
  int rv = 0;
  vl_api_l2_fib_clear_table_reply_t *rmp;

  /* Clear all MACs including static MACs  */
  l2fib_clear_table ();

  REPLY_MACRO (VL_API_L2_FIB_CLEAR_TABLE_REPLY);
}

static void
send_l2fib_table_entry (vpe_api_main_t * am,
			vl_api_registration_t * reg,
			l2fib_entry_key_t * l2fe_key,
			l2fib_entry_result_t * l2fe_res, u32 context)
{
  vl_api_l2_fib_table_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_L2_FIB_TABLE_DETAILS);

  mp->bd_id =
    ntohl (l2input_main.bd_configs[l2fe_key->fields.bd_index].bd_id);

  clib_memcpy (mp->mac, l2fe_key->fields.mac, 6);
  mp->sw_if_index = ntohl (l2fe_res->fields.sw_if_index);
  mp->static_mac = (l2fib_entry_result_is_set_STATIC (l2fe_res) ? 1 : 0);
  mp->filter_mac = (l2fib_entry_result_is_set_FILTER (l2fe_res) ? 1 : 0);
  mp->bvi_mac = (l2fib_entry_result_is_set_BVI (l2fe_res) ? 1 : 0);
  mp->context = context;

  vl_api_send_msg (reg, (u8 *) mp);
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
  vl_api_registration_t *reg;
  uword *p;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
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
    send_l2fib_table_entry (am, reg, vec_elt_at_index (l2fe_key, ni),
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
  u32 bd_id = ntohl (mp->bd_id);
  uword *p = hash_get (bdm->bd_index_by_bd_id, bd_id);

  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto bad_sw_if_index;
    }
  u32 bd_index = p[0];

  u8 mac[6];

  clib_memcpy (mac, mp->mac, 6);
  if (mp->is_add)
    {
      if (mp->filter_mac)
	l2fib_add_filter_entry (mac, bd_index);
      else
	{
	  l2fib_entry_result_flags_t flags = L2FIB_ENTRY_RESULT_FLAG_NONE;
	  u32 sw_if_index = ntohl (mp->sw_if_index);
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
	  if (mp->static_mac)
	    flags |= L2FIB_ENTRY_RESULT_FLAG_STATIC;
	  if (mp->bvi_mac)
	    flags |= L2FIB_ENTRY_RESULT_FLAG_BVI;
	  l2fib_add_entry (mac, bd_index, sw_if_index, flags);
	}
    }
  else
    {
      u32 sw_if_index = ntohl (mp->sw_if_index);
      if (l2fib_del_entry (mac, bd_index, sw_if_index))
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2FIB_ADD_DEL_REPLY);
}

static void
vl_api_want_l2_macs_events_t_handler (vl_api_want_l2_macs_events_t * mp)
{
  int rv = 0;
  vl_api_want_l2_macs_events_reply_t *rmp;
  l2learn_main_t *lm = &l2learn_main;
  l2fib_main_t *fm = &l2fib_main;
  u32 pid = ntohl (mp->pid);
  u32 learn_limit = ntohl (mp->learn_limit);

  if (mp->enable_disable)
    {
      if (lm->client_pid == 0)
	{
	  lm->client_pid = pid;
	  lm->client_index = mp->client_index;

	  if (mp->max_macs_in_event)
	    fm->max_macs_in_event = mp->max_macs_in_event * 10;
	  else
	    fm->max_macs_in_event = L2FIB_EVENT_MAX_MACS_DEFAULT;

	  if (mp->scan_delay)
	    fm->event_scan_delay = (f64) (mp->scan_delay) * 10e-3;
	  else
	    fm->event_scan_delay = L2FIB_EVENT_SCAN_DELAY_DEFAULT;

	  /* change learn limit and flush all learned MACs */
	  if (learn_limit && (learn_limit < L2LEARN_DEFAULT_LIMIT))
	    lm->global_learn_limit = learn_limit;
	  else
	    lm->global_learn_limit = L2FIB_EVENT_LEARN_LIMIT_DEFAULT;

	  l2fib_flush_all_mac (vlib_get_main ());
	}
      else if (lm->client_pid != pid)
	{
	  rv = VNET_API_ERROR_L2_MACS_EVENT_CLINET_PRESENT;
	  goto exit;
	}
    }
  else if (lm->client_pid)
    {
      lm->client_pid = 0;
      lm->client_index = 0;
      if (learn_limit && (learn_limit < L2LEARN_DEFAULT_LIMIT))
	lm->global_learn_limit = learn_limit;
      else
	lm->global_learn_limit = L2LEARN_DEFAULT_LIMIT;
    }

exit:
  REPLY_MACRO (VL_API_WANT_L2_MACS_EVENTS_REPLY);
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
vl_api_l2fib_flush_all_t_handler (vl_api_l2fib_flush_all_t * mp)
{
  int rv = 0;
  vl_api_l2fib_flush_all_reply_t *rmp;

  l2fib_flush_all_mac (vlib_get_main ());
  REPLY_MACRO (VL_API_L2FIB_FLUSH_ALL_REPLY);
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
  u32 flags = ntohl (mp->feature_bitmap);
  u32 bitmap = 0;

  if (flags & L2_LEARN)
    bitmap |= L2INPUT_FEAT_LEARN;

  if (flags & L2_FWD)
    bitmap |= L2INPUT_FEAT_FWD;

  if (flags & L2_FLOOD)
    bitmap |= L2INPUT_FEAT_FLOOD;

  if (flags & L2_UU_FLOOD)
    bitmap |= L2INPUT_FEAT_UU_FLOOD;

  if (flags & L2_ARP_TERM)
    bitmap |= L2INPUT_FEAT_ARP_TERM;

  rbm = l2input_intf_bitmap_enable (sw_if_index, bitmap, mp->is_set);

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
  uword *p;

  if (bd_id == 0)
    {
      rv = VNET_API_ERROR_BD_NOT_MODIFIABLE;
      goto out;
    }

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
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
  l2_bridge_domain_add_del_args_t a = {
    .is_add = mp->is_add,
    .flood = mp->flood,
    .uu_flood = mp->uu_flood,
    .forward = mp->forward,
    .learn = mp->learn,
    .arp_term = mp->arp_term,
    .mac_age = mp->mac_age,
    .bd_id = ntohl (mp->bd_id),
    .bd_tag = mp->bd_tag
  };

  int rv = bd_add_del (&a);

  vl_api_bridge_domain_add_del_reply_t *rmp;
  REPLY_MACRO (VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY);
}

static void
send_bridge_domain_details (l2input_main_t * l2im,
			    vl_api_registration_t * reg,
			    l2_bridge_domain_t * bd_config,
			    u32 n_sw_ifs, u32 context)
{
  vl_api_bridge_domain_details_t *mp;
  l2_flood_member_t *m;
  vl_api_bridge_domain_sw_if_t *sw_ifs;
  l2_input_config_t *input_cfg;

  mp = vl_msg_api_alloc (sizeof (*mp) +
			 (n_sw_ifs * sizeof (vl_api_bridge_domain_sw_if_t)));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_BRIDGE_DOMAIN_DETAILS);
  mp->bd_id = ntohl (bd_config->bd_id);
  mp->flood = bd_feature_flood (bd_config);
  mp->uu_flood = bd_feature_uu_flood (bd_config);
  mp->forward = bd_feature_forward (bd_config);
  mp->learn = bd_feature_learn (bd_config);
  mp->arp_term = bd_feature_arp_term (bd_config);
  mp->bvi_sw_if_index = ntohl (bd_config->bvi_sw_if_index);
  mp->uu_fwd_sw_if_index = ntohl (bd_config->uu_fwd_sw_if_index);
  mp->mac_age = bd_config->mac_age;
  if (bd_config->bd_tag)
    {
      strncpy ((char *) mp->bd_tag, (char *) bd_config->bd_tag,
	       ARRAY_LEN (mp->bd_tag) - 1);
      mp->bd_tag[ARRAY_LEN (mp->bd_tag) - 1] = 0;
    }

  mp->context = context;

  sw_ifs = (vl_api_bridge_domain_sw_if_t *) mp->sw_if_details;
  vec_foreach (m, bd_config->members)
  {
    sw_ifs->sw_if_index = ntohl (m->sw_if_index);
    input_cfg = vec_elt_at_index (l2im->configs, m->sw_if_index);
    sw_ifs->shg = input_cfg->shg;
    sw_ifs++;
    mp->n_sw_ifs++;
  }
  mp->n_sw_ifs = htonl (mp->n_sw_ifs);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_bridge_domain_dump_t_handler (vl_api_bridge_domain_dump_t * mp)
{
  bd_main_t *bdm = &bd_main;
  l2input_main_t *l2im = &l2input_main;
  vl_api_registration_t *reg;
  u32 bd_id, bd_index, end;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  bd_id = ntohl (mp->bd_id);
  if (bd_id == 0)
    return;

  if (bd_id == ~0)
    bd_index = 0, end = vec_len (l2im->bd_configs);
  else
    {
      bd_index = bd_find_index (bdm, bd_id);
      if (bd_index == ~0)
	return;

      end = bd_index + 1;
    }

  for (; bd_index < end; bd_index++)
    {
      l2_bridge_domain_t *bd_config =
	l2input_bd_config_from_index (l2im, bd_index);
      /* skip dummy bd_id 0 */
      if (bd_config && (bd_config->bd_id > 0))
	send_bridge_domain_details (l2im, reg, bd_config,
				    vec_len (bd_config->members),
				    mp->context);
    }
}

static bd_flags_t
bd_flags_decode (vl_api_bd_flags_t v)
{
  bd_flags_t f = L2_NONE;

  v = ntohl (v);

  if (v & BRIDGE_API_FLAG_LEARN)
    f |= L2_LEARN;
  if (v & BRIDGE_API_FLAG_FWD)
    f |= L2_FWD;
  if (v & BRIDGE_API_FLAG_FLOOD)
    f |= L2_FLOOD;
  if (v & BRIDGE_API_FLAG_UU_FLOOD)
    f |= L2_UU_FLOOD;
  if (v & BRIDGE_API_FLAG_ARP_TERM)
    f |= L2_ARP_TERM;

  return (f);
}

static void
vl_api_bridge_flags_t_handler (vl_api_bridge_flags_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_bridge_flags_reply_t *rmp;
  int rv = 0;
  u32 bitmap = 0;

  bd_flags_t flags = bd_flags_decode (mp->flags);
  u32 bd_id = ntohl (mp->bd_id);
  if (bd_id == 0)
    {
      rv = VNET_API_ERROR_BD_NOT_MODIFIABLE;
      goto out;
    }

  u32 bd_index = bd_find_index (bdm, bd_id);
  if (bd_index == ~0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }

  bitmap = bd_set_flags (vm, bd_index, flags, mp->is_set);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_BRIDGE_FLAGS_REPLY,
  ({
    rmp->resulting_feature_bitmap = ntohl(bitmap);
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

static void
  vl_api_sw_interface_set_l2_xconnect_t_handler
  (vl_api_sw_interface_set_l2_xconnect_t * mp)
{
  vl_api_sw_interface_set_l2_xconnect_reply_t *rmp;
  int rv = 0;
  u32 rx_sw_if_index = ntohl (mp->rx_sw_if_index);
  u32 tx_sw_if_index = ntohl (mp->tx_sw_if_index);
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();

  VALIDATE_RX_SW_IF_INDEX (mp);

  if (mp->enable)
    {
      VALIDATE_TX_SW_IF_INDEX (mp);
      rv = set_int_l2_mode (vm, vnm, MODE_L2_XC,
			    rx_sw_if_index, 0,
			    L2_BD_PORT_TYPE_NORMAL, 0, tx_sw_if_index);
    }
  else
    {
      rv = set_int_l2_mode (vm, vnm, MODE_L3, rx_sw_if_index, 0,
			    L2_BD_PORT_TYPE_NORMAL, 0, 0);
    }

  switch (rv)
    {
    case MODE_ERROR_ETH:
      rv = VNET_API_ERROR_NON_ETHERNET;
      break;
    case MODE_ERROR_BVI_DEF:
      rv = VNET_API_ERROR_BD_ALREADY_HAS_BVI;
      break;
    }

  BAD_RX_SW_IF_INDEX_LABEL;
  BAD_TX_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_L2_XCONNECT_REPLY);
}

static int
l2_bd_port_type_decode (vl_api_l2_port_type_t v, l2_bd_port_type_t * l)
{
  v = clib_net_to_host_u32 (v);

  switch (v)
    {
    case L2_API_PORT_TYPE_NORMAL:
      *l = L2_BD_PORT_TYPE_NORMAL;
      return 0;
    case L2_API_PORT_TYPE_BVI:
      *l = L2_BD_PORT_TYPE_BVI;
      return 0;
    case L2_API_PORT_TYPE_UU_FWD:
      *l = L2_BD_PORT_TYPE_UU_FWD;
      return 0;
    }

  return (VNET_API_ERROR_INVALID_VALUE);
}

static void
  vl_api_sw_interface_set_l2_bridge_t_handler
  (vl_api_sw_interface_set_l2_bridge_t * mp)
{
  bd_main_t *bdm = &bd_main;
  vl_api_sw_interface_set_l2_bridge_reply_t *rmp;
  int rv = 0;
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  l2_bd_port_type_t pt;

  VALIDATE_RX_SW_IF_INDEX (mp);
  u32 rx_sw_if_index = ntohl (mp->rx_sw_if_index);
  rv = l2_bd_port_type_decode (mp->port_type, &pt);

  if (0 != rv)
    goto out;
  if (mp->enable)
    {
      VALIDATE_BD_ID (mp);
      u32 bd_id = ntohl (mp->bd_id);
      u32 bd_index = bd_find_or_add_bd_index (bdm, bd_id);

      rv = set_int_l2_mode (vm, vnm, MODE_L2_BRIDGE,
			    rx_sw_if_index, bd_index, pt, mp->shg, 0);
    }
  else
    {
      rv = set_int_l2_mode (vm, vnm, MODE_L3, rx_sw_if_index, 0, pt, 0, 0);
    }

  switch (rv)
    {
    case MODE_ERROR_ETH:
      rv = VNET_API_ERROR_NON_ETHERNET;
      break;
    case MODE_ERROR_BVI_DEF:
      rv = VNET_API_ERROR_BD_ALREADY_HAS_BVI;
      break;
    }

  BAD_RX_SW_IF_INDEX_LABEL;
  BAD_BD_ID_LABEL;
out:
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_L2_BRIDGE_REPLY);
}

static void
send_bd_ip_mac_entry (vpe_api_main_t * am,
		      vl_api_registration_t * reg,
		      u32 bd_id, u8 is_ipv6,
		      u8 * ip_address, u8 * mac_address, u32 context)
{
  vl_api_bd_ip_mac_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_BD_IP_MAC_DETAILS);

  mp->bd_id = ntohl (bd_id);

  clib_memcpy (mp->mac_address, mac_address, 6);
  mp->is_ipv6 = is_ipv6;
  clib_memcpy (mp->ip_address, ip_address, (is_ipv6) ? 16 : 4);
  mp->context = context;

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_bd_ip_mac_dump_t_handler (vl_api_bd_ip_mac_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  bd_main_t *bdm = &bd_main;
  l2_bridge_domain_t *bd_config;
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index, start, end;
  vl_api_registration_t *reg;
  uword *p;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  /* see bd_id: ~0 means "any" */
  if (bd_id == ~0)
    {
      start = 1;
      end = vec_len (l2input_main.bd_configs);
    }
  else
    {
      p = hash_get (bdm->bd_index_by_bd_id, bd_id);
      if (p == 0)
	return;

      bd_index = p[0];
      vec_validate (l2input_main.bd_configs, bd_index);
      start = bd_index;
      end = start + 1;
    }

  for (bd_index = start; bd_index < end; bd_index++)
    {
      bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);
      if (bd_is_valid (bd_config))
	{
	  ip4_address_t ip4_addr;
	  ip6_address_t *ip6_addr;
	  u64 mac_addr;
	  bd_id = bd_config->bd_id;

         /* *INDENT-OFF* */
         hash_foreach (ip4_addr.as_u32, mac_addr, bd_config->mac_by_ip4,
         ({
            send_bd_ip_mac_entry (am, reg, bd_id, 0, (u8 *) &(ip4_addr.as_u8), (u8 *) &mac_addr, mp->context);
         }));

         hash_foreach_mem (ip6_addr, mac_addr, bd_config->mac_by_ip6,
         ({
            send_bd_ip_mac_entry (am, reg, bd_id, 1, (u8 *) &(ip6_addr->as_u8), (u8 *) &mac_addr, mp->context);
         }));
         /* *INDENT-ON* */
	}
    }
}

static void
vl_api_bd_ip_mac_add_del_t_handler (vl_api_bd_ip_mac_add_del_t * mp)
{
  ip46_address_t ip_addr = ip46_address_initializer;
  vl_api_bd_ip_mac_add_del_reply_t *rmp;
  bd_main_t *bdm = &bd_main;
  u32 bd_index, bd_id;
  mac_address_t mac;
  ip46_type_t type;
  int rv = 0;
  uword *p;

  bd_id = ntohl (mp->bd_id);

  if (bd_id == 0)
    {
      rv = VNET_API_ERROR_BD_NOT_MODIFIABLE;
      goto out;
    }

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }
  bd_index = p[0];

  type = ip_address_decode (&mp->ip, &ip_addr);
  mac_address_decode (mp->mac, &mac);

  if (bd_add_del_ip_mac (bd_index, type, &ip_addr, &mac, mp->is_add))
    rv = VNET_API_ERROR_UNSPECIFIED;

out:
  REPLY_MACRO (VL_API_BD_IP_MAC_ADD_DEL_REPLY);
}

extern void l2_efp_filter_configure (vnet_main_t * vnet_main,
				     u32 sw_if_index, u8 enable);

static void
vl_api_l2_interface_efp_filter_t_handler (vl_api_l2_interface_efp_filter_t *
					  mp)
{
  int rv;
  vl_api_l2_interface_efp_filter_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();

  VALIDATE_SW_IF_INDEX (mp);

  // enable/disable the feature
  l2_efp_filter_configure (vnm, ntohl (mp->sw_if_index), mp->enable_disable);
  rv = vnm->api_errno;

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_L2_INTERFACE_EFP_FILTER_REPLY);
}

static void
vl_api_l2_patch_add_del_t_handler (vl_api_l2_patch_add_del_t * mp)
{
  extern int vnet_l2_patch_add_del (u32 rx_sw_if_index, u32 tx_sw_if_index,
				    int is_add);
  vl_api_l2_patch_add_del_reply_t *rmp;
  int vnet_l2_patch_add_del (u32 rx_sw_if_index, u32 tx_sw_if_index,
			     int is_add);
  int rv = 0;

  VALIDATE_RX_SW_IF_INDEX (mp);
  VALIDATE_TX_SW_IF_INDEX (mp);

  rv = vnet_l2_patch_add_del (ntohl (mp->rx_sw_if_index),
			      ntohl (mp->tx_sw_if_index),
			      (int) (mp->is_add != 0));

  BAD_RX_SW_IF_INDEX_LABEL;
  BAD_TX_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2_PATCH_ADD_DEL_REPLY);
}

static void
vl_api_sw_interface_set_vpath_t_handler (vl_api_sw_interface_set_vpath_t * mp)
{
  vl_api_sw_interface_set_vpath_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  VALIDATE_SW_IF_INDEX (mp);

  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_VPATH, mp->enable);
  vnet_feature_enable_disable ("ip4-unicast", "vpath-input-ip4",
			       sw_if_index, mp->enable, 0, 0);
  vnet_feature_enable_disable ("ip4-multicast", "vpath-input-ip4",
			       sw_if_index, mp->enable, 0, 0);
  vnet_feature_enable_disable ("ip6-unicast", "vpath-input-ip6",
			       sw_if_index, mp->enable, 0, 0);
  vnet_feature_enable_disable ("ip6-multicast", "vpath-input-ip6",
			       sw_if_index, mp->enable, 0, 0);

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_VPATH_REPLY);
}

/*
 * l2_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has already mapped shared memory and
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
