/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Copyright (c) 2022 Nordix Foundation.
 */

/*
 * l2_api.c - layer 2 forwarding api
 */

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_fib.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/l2/l2_learn.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_bvi.h>
#include <vnet/l2/l2_arp_term.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <vnet/format_fns.h>
#include <vnet/l2/l2.api_enum.h>
#include <vnet/l2/l2.api_types.h>

#define REPLY_MSG_ID_BASE l2input_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
send_l2_xconnect_details (vl_api_registration_t * reg, u32 context,
			  u32 rx_sw_if_index, u32 tx_sw_if_index)
{
  vl_api_l2_xconnect_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_L2_XCONNECT_DETAILS);
  mp->context = context;
  mp->rx_sw_if_index = htonl (rx_sw_if_index);
  mp->tx_sw_if_index = htonl (tx_sw_if_index);

  vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_l2_xconnect_dump_t_handler (vl_api_l2_xconnect_dump_t * mp)
{
  vl_api_registration_t *reg;
  l2input_main_t *l2im = &l2input_main;
  u32 sw_if_index;
  l2_input_config_t *config;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  vec_foreach_index (sw_if_index, l2im->configs)
    {
      config = vec_elt_at_index (l2im->configs, sw_if_index);
      if (l2_input_is_xconnect (config))
	send_l2_xconnect_details (reg, mp->context, sw_if_index,
				  config->output_sw_if_index);
    }
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
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_L2_FIB_TABLE_DETAILS);

  mp->bd_id =
    ntohl (l2input_main.bd_configs[l2fe_key->fields.bd_index].bd_id);

  mac_address_encode ((mac_address_t *) l2fe_key->fields.mac, mp->mac);
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

  mac_address_t mac;

  mac_address_decode (mp->mac, &mac);
  if (mp->is_add)
    {
      if (mp->filter_mac)
	l2fib_add_filter_entry (mac.bytes, bd_index);
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
	      if (!l2_input_is_bridge (config))
		{
		  rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
		  goto bad_sw_if_index;
		}
	    }
	  if (mp->static_mac)
	    flags |= L2FIB_ENTRY_RESULT_FLAG_STATIC;
	  if (mp->bvi_mac)
	    flags |= L2FIB_ENTRY_RESULT_FLAG_BVI;
	  l2fib_add_entry (mac.bytes, bd_index, sw_if_index, flags);
	}
    }
  else
    {
      u32 sw_if_index = ntohl (mp->sw_if_index);
      if (l2fib_del_entry (mac.bytes, bd_index, sw_if_index))
	rv = VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2FIB_ADD_DEL_REPLY);
}

static void
vl_api_want_l2_macs_events2_t_handler (vl_api_want_l2_macs_events2_t *mp)
{
  int rv = 0;
  vl_api_want_l2_macs_events2_reply_t *rmp;
  l2learn_main_t *lm = &l2learn_main;
  l2fib_main_t *fm = &l2fib_main;
  u32 pid = ntohl (mp->pid);

  if (mp->enable_disable)
    {
      if ((lm->client_pid == 0) || (lm->client_pid == pid))
	{
	  if (mp->max_macs_in_event)
	    fm->max_macs_in_event = mp->max_macs_in_event * 10;
	  else
	    {
	      rv = VNET_API_ERROR_INVALID_VALUE;
	      goto exit;
	    }

	  /* if scan_delay was not set before */
	  if (fm->event_scan_delay == 0.0)
	    fm->event_scan_delay = (f64) (10) * 10e-3;

	  lm->client_pid = pid;
	  lm->client_index = mp->client_index;
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
    }

exit:
  REPLY_MACRO (VL_API_WANT_L2_MACS_EVENTS2_REPLY);
}

static void
vl_api_want_l2_macs_events_t_handler (vl_api_want_l2_macs_events_t *mp)
{
  int rv = 0;
  vl_api_want_l2_macs_events_reply_t *rmp;
  l2learn_main_t *lm = &l2learn_main;
  l2fib_main_t *fm = &l2fib_main;
  u32 pid = ntohl (mp->pid);
  u32 learn_limit = ntohl (mp->learn_limit);

  if (mp->enable_disable)
    {
      if ((lm->client_pid == 0) || (lm->client_pid == pid))
	{
	  if ((mp->max_macs_in_event == 0) || (mp->scan_delay == 0) ||
	      (learn_limit == 0) || (learn_limit > L2LEARN_DEFAULT_LIMIT))
	    {
	      rv = VNET_API_ERROR_INVALID_VALUE;
	      goto exit;
	    }
	  lm->client_pid = pid;
	  lm->client_index = mp->client_index;

	  fm->max_macs_in_event = mp->max_macs_in_event * 10;
	  fm->event_scan_delay = (f64) (mp->scan_delay) * 10e-3;

	  /* change learn limit and flush all learned MACs */
	  lm->global_learn_limit = learn_limit;
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
      if (learn_limit && (learn_limit <= L2LEARN_DEFAULT_LIMIT))
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
vl_api_l2fib_set_scan_delay_t_handler (vl_api_l2fib_set_scan_delay_t *mp)
{
  int rv = 0;
  l2fib_main_t *fm = &l2fib_main;
  vl_api_l2fib_set_scan_delay_reply_t *rmp;
  u16 scan_delay = ntohs (mp->scan_delay);

  if (mp->scan_delay)
    {
      fm->event_scan_delay = (f64) (scan_delay) *10e-3;
      l2fib_flush_all_mac (vlib_get_main ());
    }
  else
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto exit;
    }

exit:
  REPLY_MACRO (VL_API_L2FIB_SET_SCAN_DELAY_REPLY);
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

  REPLY_MACRO2(VL_API_L2_FLAGS_REPLY,
  ({
    rmp->resulting_feature_bitmap = ntohl(rbm);
  }));
}

static void
vl_api_l2_flags_get_t_handler (vl_api_l2_flags_get_t *mp)
{
  vl_api_l2_flags_get_reply_t *rmp;
  int rv = 0;
  u32 feature_bitmap = 0;
  u32 out_feature_bitmap = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);
  l2_input_config_t *in_cfg = l2input_intf_config (sw_if_index);
  if (in_cfg)
    feature_bitmap = in_cfg->feature_bitmap;
  l2_output_config_t *out_cfg = l2output_intf_config (sw_if_index);
  if (out_cfg)
    out_feature_bitmap = out_cfg->feature_bitmap;

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO2 (VL_API_L2_FLAGS_GET_REPLY, ({
		  rmp->input_feature_bitmap = htonl (feature_bitmap);
		  rmp->output_feature_bitmap = htonl (out_feature_bitmap);
		}));
}

static void
vl_api_l2_flags_set_t_handler (vl_api_l2_flags_set_t *mp)
{
  vl_api_l2_flags_set_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 in_bitmap = ntohl (mp->input_feature_bitmap);
  u32 out_bitmap = ntohl (mp->output_feature_bitmap);

  if (in_bitmap)
    l2input_intf_bitmap_enable (sw_if_index, in_bitmap, mp->is_set);
  if (out_bitmap)
    l2output_intf_bitmap_enable (sw_if_index, out_bitmap, mp->is_set);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_L2_FLAGS_SET_REPLY);
}

/*
 * Translation between the stable API enum (l2_intf_feat_flags) and the
 * internal feature bitmap (L2INPUT_FEAT_*).
 *
 * NOTE: keep in sync with enum l2_intf_feat_flags in l2.api.
 * The STATIC_ASSERT below enforces that every API flag is listed here.
 */
#define foreach_l2_intf_feat_flag                                                                  \
  _ (LEARN, L2INPUT_FEAT_LEARN)                                                                    \
  _ (FWD, L2INPUT_FEAT_FWD)                                                                        \
  _ (FLOOD, L2INPUT_FEAT_FLOOD)                                                                    \
  _ (UU_FLOOD, L2INPUT_FEAT_UU_FLOOD)                                                              \
  _ (ARP_TERM, L2INPUT_FEAT_ARP_TERM)                                                              \
  _ (ARP_UFWD, L2INPUT_FEAT_ARP_UFWD)

/* Verify the translation table covers every bit defined in the API enum. */
#define _(f, i) | L2_INTF_FEAT_##f
STATIC_ASSERT ((0 foreach_l2_intf_feat_flag) ==
		 (L2_INTF_FEAT_LEARN | L2_INTF_FEAT_FWD | L2_INTF_FEAT_FLOOD |
		  L2_INTF_FEAT_UU_FLOOD | L2_INTF_FEAT_ARP_TERM | L2_INTF_FEAT_ARP_UFWD),
	       "foreach_l2_intf_feat_flag does not cover all API flags");
#undef _

static u32
l2_intf_feat_flags_to_bitmap (vl_api_l2_intf_feat_flags_t api_flags)
{
  u32 bitmap = 0;
#define _(f, i)                                                                                    \
  if (api_flags & L2_INTF_FEAT_##f)                                                                \
    bitmap |= (i);
  foreach_l2_intf_feat_flag
#undef _
    return bitmap;
}

static vl_api_l2_intf_feat_flags_t
l2_bitmap_to_intf_feat_flags (u32 bitmap)
{
  vl_api_l2_intf_feat_flags_t flags = L2_INTF_FEAT_NONE;
#define _(f, i)                                                                                    \
  if (bitmap & (i))                                                                                \
    flags |= L2_INTF_FEAT_##f;
  foreach_l2_intf_feat_flag
#undef _
    return flags;
}

static void
vl_api_l2_interface_feat_flags_get_t_handler (vl_api_l2_interface_feat_flags_get_t *mp)
{
  vl_api_l2_interface_feat_flags_get_reply_t *rmp;
  int rv = 0;
  vl_api_l2_intf_feat_flags_t flags = L2_INTF_FEAT_NONE;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);
  l2_input_config_t *cfg = l2input_intf_config (sw_if_index);
  if (cfg)
    flags = l2_bitmap_to_intf_feat_flags (cfg->feature_bitmap);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO2 (VL_API_L2_INTERFACE_FEAT_FLAGS_GET_REPLY, ({ rmp->flags = htonl (flags); }));
}

static void
vl_api_l2_interface_feat_flags_set_t_handler (vl_api_l2_interface_feat_flags_set_t *mp)
{
  vl_api_l2_interface_feat_flags_set_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 bitmap = l2_intf_feat_flags_to_bitmap (ntohl (mp->flags));
  l2input_intf_bitmap_enable (sw_if_index, bitmap, mp->is_set);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_L2_INTERFACE_FEAT_FLAGS_SET_REPLY);
}

static void
vl_api_bridge_domain_set_default_learn_limit_t_handler (
  vl_api_bridge_domain_set_default_learn_limit_t *mp)
{
  vl_api_bridge_domain_set_default_learn_limit_reply_t *rmp;
  int rv = 0;

  l2learn_main.bd_default_learn_limit = ntohl (mp->learn_limit);
  REPLY_MACRO (VL_API_BRIDGE_DOMAIN_SET_DEFAULT_LEARN_LIMIT_REPLY);
}

static void
vl_api_bridge_domain_set_learn_limit_t_handler (
  vl_api_bridge_domain_set_learn_limit_t *mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_bridge_domain_set_learn_limit_reply_t *rmp;
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
  bd_set_learn_limit (vm, *p, ntohl (mp->learn_limit));
out:
  REPLY_MACRO (VL_API_BRIDGE_DOMAIN_SET_LEARN_LIMIT_REPLY);
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
    .arp_ufwd = mp->arp_ufwd,
    .mac_age = mp->mac_age,
    .bd_id = ntohl (mp->bd_id),
    .bd_tag = mp->bd_tag
  };

  int rv = bd_add_del (&a);

  vl_api_bridge_domain_add_del_reply_t *rmp;
  REPLY_MACRO (VL_API_BRIDGE_DOMAIN_ADD_DEL_REPLY);
}

static void
vl_api_bridge_domain_add_del_v2_t_handler (
  vl_api_bridge_domain_add_del_v2_t *mp)
{
  vl_api_bridge_domain_add_del_v2_reply_t *rmp;
  u32 bd_id = ntohl (mp->bd_id);
  int rv = 0;

  if ((~0 == bd_id) && (mp->is_add))
    bd_id = bd_get_unused_id ();

  if ((~0 == bd_id) && (mp->is_add))
    rv = VNET_API_ERROR_EAGAIN;
  else
    {
      l2_bridge_domain_add_del_args_t a = { .is_add = mp->is_add,
					    .flood = mp->flood,
					    .uu_flood = mp->uu_flood,
					    .forward = mp->forward,
					    .learn = mp->learn,
					    .arp_term = mp->arp_term,
					    .arp_ufwd = mp->arp_ufwd,
					    .mac_age = mp->mac_age,
					    .bd_id = bd_id,
					    .bd_tag = mp->bd_tag };
      rv = bd_add_del (&a);
    }
  REPLY_MACRO2 (VL_API_BRIDGE_DOMAIN_ADD_DEL_V2_REPLY,
		({ rmp->bd_id = htonl (bd_id); }));
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
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_BRIDGE_DOMAIN_DETAILS);
  mp->bd_id = ntohl (bd_config->bd_id);
  mp->flood = bd_feature_flood (bd_config);
  mp->uu_flood = bd_feature_uu_flood (bd_config);
  mp->forward = bd_feature_forward (bd_config);
  mp->learn = bd_feature_learn (bd_config);
  mp->arp_term = bd_feature_arp_term (bd_config);
  mp->arp_ufwd = bd_feature_arp_ufwd (bd_config);
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
  u32 bd_id, bd_index, end, filter_sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  filter_sw_if_index = ntohl (mp->sw_if_index);
  if (filter_sw_if_index != ~0)
    return;			/* UNIMPLEMENTED */

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
      /* skip placeholder bd_id 0 */
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
  if (v & BRIDGE_API_FLAG_ARP_UFWD)
    f |= L2_ARP_UFWD;

  return (f);
}

static void
vl_api_bridge_flags_t_handler (vl_api_bridge_flags_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_bridge_flags_reply_t *rmp;
  u32 bitmap = 0;
  int rv = 0;

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
  REPLY_MACRO2(VL_API_BRIDGE_FLAGS_REPLY,
  ({
    rmp->resulting_feature_bitmap = ntohl(bitmap);
  }));
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
  mac_address_t b_dmac, b_smac;

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

  mac_address_decode (mp->b_dmac, &b_dmac);
  mac_address_decode (mp->b_smac, &b_smac);

  rv = l2pbb_configure (vm, vnm, ntohl (mp->sw_if_index), vtr_op,
			b_dmac.bytes, b_smac.bytes, ntohs (mp->b_vlanid),
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
		      u32 bd_id,
		      const ip46_address_t * ip,
		      ip46_type_t itype,
		      const mac_address_t * mac, u32 context)
{
  vl_api_bd_ip_mac_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  clib_memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_BD_IP_MAC_DETAILS);

  mp->context = context;
  mp->entry.bd_id = ntohl (bd_id);

  ip_address_encode (ip, itype, &mp->entry.ip);
  mac_address_encode (mac, mp->entry.mac);

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
	  mac_address_t mac;
	  u64 mac64;
	  bd_id = bd_config->bd_id;

         hash_foreach (ip4_addr.as_u32, mac64, bd_config->mac_by_ip4,
         ({
           ip46_address_t ip = {
             .ip4 = ip4_addr,
           };
           mac_address_from_u64(&mac, mac64);

           send_bd_ip_mac_entry (am, reg, bd_id, &ip, IP46_TYPE_IP4,
                                 &mac, mp->context);
         }));

         hash_foreach_mem (ip6_addr, mac64, bd_config->mac_by_ip6,
         ({
           ip46_address_t ip = {
             .ip6 = *ip6_addr,
           };
           mac_address_from_u64(&mac, mac64);

           send_bd_ip_mac_entry (am, reg, bd_id, &ip, IP46_TYPE_IP6,
                                 &mac, mp->context);
         }));
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

  bd_id = ntohl (mp->entry.bd_id);

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

  type = ip_address_decode (&mp->entry.ip, &ip_addr);
  mac_address_decode (mp->entry.mac, &mac);

  if (bd_add_del_ip_mac (bd_index, type, &ip_addr, &mac, mp->is_add))
    rv = VNET_API_ERROR_UNSPECIFIED;

out:
  REPLY_MACRO (VL_API_BD_IP_MAC_ADD_DEL_REPLY);
}

static void
vl_api_bd_ip_mac_flush_t_handler (vl_api_bd_ip_mac_flush_t * mp)
{
  vl_api_bd_ip_mac_flush_reply_t *rmp;
  bd_main_t *bdm = &bd_main;
  u32 bd_index, bd_id;
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

  bd_flush_ip_mac (bd_index);

out:
  REPLY_MACRO (VL_API_BD_IP_MAC_FLUSH_REPLY);
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

static void
vl_api_bvi_create_t_handler (vl_api_bvi_create_t * mp)
{
  vl_api_bvi_create_reply_t *rmp;
  mac_address_t mac;
  u32 sw_if_index;
  int rv;

  mac_address_decode (mp->mac, &mac);

  rv = l2_bvi_create (ntohl (mp->user_instance), &mac, &sw_if_index);

  REPLY_MACRO2(VL_API_BVI_CREATE_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
}

static void
vl_api_bvi_delete_t_handler (vl_api_bvi_delete_t * mp)
{
  vl_api_bvi_delete_reply_t *rmp;
  int rv;

  rv = l2_bvi_delete (ntohl (mp->sw_if_index));

  REPLY_MACRO (VL_API_BVI_DELETE_REPLY);
}

static bool
l2_arp_term_publish_event_is_equal (const l2_arp_term_publish_event_t * e1,
				    const l2_arp_term_publish_event_t * e2)
{
  if (e1 == NULL || e2 == NULL)
    return false;
  return (ip46_address_is_equal (&e1->ip, &e2->ip) &&
	  (e1->sw_if_index == e2->sw_if_index) &&
	  (mac_address_equal (&e1->mac, &e2->mac)));
}

static uword
l2_arp_term_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		     vlib_frame_t * f)
{
  /* These cross the longjmp boundary (vlib_process_wait_for_event)
   * and need to be volatile - to prevent them from being optimized into
   * a register - which could change during suspension */
  volatile f64 last = vlib_time_now (vm);
  volatile l2_arp_term_publish_event_t last_event = { };

  l2_arp_term_main_t *l2am = &l2_arp_term_main;

  while (1)
    {
      uword event_type = L2_ARP_TERM_EVENT_PUBLISH;
      vpe_client_registration_t *reg;
      f64 now;

      vlib_process_wait_for_event (vm);

      vlib_process_get_event_data (vm, &event_type);
      now = vlib_time_now (vm);

      if (event_type == L2_ARP_TERM_EVENT_PUBLISH)
	{
	  l2_arp_term_publish_event_t *event;

	  vec_foreach (event, l2am->publish_events)
	  {
	    /* dampen duplicate events - cast away volatile */
	    if (l2_arp_term_publish_event_is_equal
		(event, (l2_arp_term_publish_event_t *) & last_event) &&
		(now - last) < 10.0)
	      {
		continue;
	      }
	    last_event = *event;
	    last = now;

            pool_foreach (reg, vpe_api_main.l2_arp_term_events_registrations)
	      {
		vl_api_registration_t *vl_reg;
		vl_reg =
		  vl_api_client_index_to_registration (reg->client_index);
		ALWAYS_ASSERT (vl_reg != NULL);

		if (vl_reg && vl_api_can_send_msg (vl_reg))
		  {
		    vl_api_l2_arp_term_event_t *vevent;
		    vevent = vl_msg_api_alloc (sizeof *vevent);
		    clib_memset (vevent, 0, sizeof *vevent);
		    vevent->_vl_msg_id =
		      htons (REPLY_MSG_ID_BASE + VL_API_L2_ARP_TERM_EVENT);
		    vevent->client_index = reg->client_index;
		    vevent->pid = reg->client_pid;
		    ip_address_encode (&event->ip, event->type, &vevent->ip);
		    vevent->sw_if_index = htonl (event->sw_if_index);
		    mac_address_encode (&event->mac, vevent->mac);
		    vl_api_send_msg (vl_reg, (u8 *) vevent);
		  }
	      }
	  }
	  vec_reset_length (l2am->publish_events);
	}
    }

  return 0;
}

VLIB_REGISTER_NODE (l2_arp_term_process_node) = {
  .function = l2_arp_term_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "l2-arp-term-publisher",
};

static void
vl_api_want_l2_arp_term_events_t_handler (vl_api_want_l2_arp_term_events_t *
					  mp)
{
  vl_api_want_l2_arp_term_events_reply_t *rmp;
  vpe_api_main_t *am = &vpe_api_main;
  vpe_client_registration_t *rp;
  int rv = 0;
  uword *p;

  p = hash_get (am->l2_arp_term_events_registration_hash, mp->client_index);

  if (p)
    {
      if (mp->enable)
	{
	  clib_warning ("pid %d: already enabled...", mp->pid);
	  rv = VNET_API_ERROR_INVALID_REGISTRATION;
	  goto reply;
	}
      else
	{
	  rp = pool_elt_at_index (am->l2_arp_term_events_registrations, p[0]);
	  pool_put (am->l2_arp_term_events_registrations, rp);
	  hash_unset (am->l2_arp_term_events_registration_hash,
		      mp->client_index);
	  if (pool_elts (am->l2_arp_term_events_registrations) == 0)
	    l2_arp_term_set_publisher_node (false);
	  goto reply;
	}
    }
  if (mp->enable == 0)
    {
      clib_warning ("pid %d: already disabled...", mp->pid);
      rv = VNET_API_ERROR_INVALID_REGISTRATION;
      goto reply;
    }
  pool_get (am->l2_arp_term_events_registrations, rp);
  rp->client_index = mp->client_index;
  rp->client_pid = mp->pid;
  hash_set (am->l2_arp_term_events_registration_hash, rp->client_index,
	    rp - am->l2_arp_term_events_registrations);
  l2_arp_term_set_publisher_node (true);

reply:
  REPLY_MACRO (VL_API_WANT_L2_ARP_TERM_EVENTS_REPLY);
}

static clib_error_t *
want_l2_arp_term_events_reaper (u32 client_index)
{
  vpe_client_registration_t *rp;
  vpe_api_main_t *am;
  uword *p;

  am = &vpe_api_main;

  /* remove from the registration hash */
  p = hash_get (am->l2_arp_term_events_registration_hash, client_index);

  if (p)
    {
      rp = pool_elt_at_index (am->l2_arp_term_events_registrations, p[0]);
      pool_put (am->l2_arp_term_events_registrations, rp);
      hash_unset (am->l2_arp_term_events_registration_hash, client_index);
      if (pool_elts (am->l2_arp_term_events_registrations) == 0)
	l2_arp_term_set_publisher_node (false);
    }
  return (NULL);
}

VL_MSG_API_REAPER_FUNCTION (want_l2_arp_term_events_reaper);

#include <vnet/l2/l2.api.c>
static clib_error_t *
l2_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  /* Mark VL_API_BRIDGE_DOMAIN_DUMP as mp safe */
  vl_api_set_msg_thread_safe (
    am, REPLY_MSG_ID_BASE + VL_API_BRIDGE_DOMAIN_DUMP, 1);

  return 0;
}

VLIB_API_INIT_FUNCTION (l2_api_hookup);
