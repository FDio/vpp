/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2022 Nordix Foundation.
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp/api/types.h>
#include <inttypes.h>

#include <vnet/l2/l2_classify.h>
#include <vnet/l2/l2_vtr.h>
#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base l2_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#include <vlibmemory/vlib.api_enum.h>
#include <vlibmemory/vlib.api_types.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <vnet/l2/l2.api_enum.h>
#include <vnet/l2/l2.api_types.h>

#define vl_endianfun /* define message structures */
#include <vnet/l2/l2.api.h>
#undef vl_endianfun

#define vl_calcsizefun
#include <vnet/l2/l2.api.h>
#undef vl_calcsizefun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} l2_test_main_t;

static l2_test_main_t l2_test_main;

static void
vl_api_l2_fib_table_details_t_handler (vl_api_l2_fib_table_details_t *mp)
{
  vat_main_t *vam = l2_test_main.vat_main;

  fformat (
    vam->ofp, "%3" PRIu32 "    %U    %3" PRIu32 "       %d       %d     %d",
    ntohl (mp->bd_id), format_ethernet_address, mp->mac,
    ntohl (mp->sw_if_index), mp->static_mac, mp->filter_mac, mp->bvi_mac);
}

static int
api_l2_fib_table_dump (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2_fib_table_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 bd_id;
  u8 bd_id_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	bd_id_set = 1;
      else
	break;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  fformat (vam->ofp, "BD-ID     Mac Address      sw-ndx  Static  Filter  BVI");

  /* Get list of l2 fib entries */
  M (L2_FIB_TABLE_DUMP, mp);

  mp->bd_id = ntohl (bd_id);
  S (mp);

  /* Use a control ping for synchronization */
  PING (&l2_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_l2_xconnect_details_t_handler (vl_api_l2_xconnect_details_t *mp)
{
  vat_main_t *vam = l2_test_main.vat_main;
  fformat (vam->ofp, "%15d%15d", ntohl (mp->rx_sw_if_index),
	   ntohl (mp->tx_sw_if_index));
}

static int
api_l2_xconnect_dump (vat_main_t *vam)
{
  vl_api_l2_xconnect_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%15s%15s", "rx_sw_if_index", "tx_sw_if_index");
    }

  M (L2_XCONNECT_DUMP, mp);

  S (mp);

  /* Use a control ping for synchronization */
  PING (&l2_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_want_l2_arp_term_events (vat_main_t *vam)
{
  return -1;
}

static int
api_want_l2_macs_events (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_want_l2_macs_events_t *mp;
  u8 enable_disable = 1;
  u32 scan_delay = 0;
  u32 max_macs_in_event = 0;
  u32 learn_limit = 0;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "learn-limit %d", &learn_limit))
	;
      else if (unformat (line_input, "scan-delay %d", &scan_delay))
	;
      else if (unformat (line_input, "max-entries %d", &max_macs_in_event))
	;
      else if (unformat (line_input, "disable"))
	enable_disable = 0;
      else
	break;
    }

  M (WANT_L2_MACS_EVENTS, mp);
  mp->enable_disable = enable_disable;
  mp->pid = htonl (getpid ());
  mp->learn_limit = htonl (learn_limit);
  mp->scan_delay = (u8) scan_delay;
  mp->max_macs_in_event = (u8) (max_macs_in_event / 10);
  S (mp);
  W (ret);
  return ret;
}

static int
api_l2fib_flush_all (vat_main_t *vam)
{
  return -1;
}

static void
increment_mac_address (u8 *mac)
{
  u64 tmp = *((u64 *) mac);
  tmp = clib_net_to_host_u64 (tmp);
  tmp += 1 << 16; /* skip unused (least significant) octets */
  tmp = clib_host_to_net_u64 (tmp);

  clib_memcpy (mac, &tmp, 6);
}

static int
api_l2fib_add_del (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2fib_add_del_t *mp;
  f64 timeout;
  u8 mac[8] = { 0 };
  u8 mac_set = 0;
  u32 bd_id;
  u8 bd_id_set = 0;
  u32 sw_if_index = 0;
  u8 sw_if_index_set = 0;
  u8 is_add = 1;
  u8 static_mac = 0;
  u8 filter_mac = 0;
  u8 bvi_mac = 0;
  int count = 1;
  f64 before = 0;
  int j;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "mac %U", unformat_ethernet_address, mac))
	mac_set = 1;
      else if (unformat (i, "bd_id %d", &bd_id))
	bd_id_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm,
			    &sw_if_index))
		sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "static"))
	static_mac = 1;
      else if (unformat (i, "filter"))
	{
	  filter_mac = 1;
	  static_mac = 1;
	}
      else if (unformat (i, "bvi"))
	{
	  bvi_mac = 1;
	  static_mac = 1;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "count %d", &count))
	;
      else
	break;
    }

  if (mac_set == 0)
    {
      errmsg ("missing mac address");
      return -99;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  if (is_add && sw_if_index_set == 0 && filter_mac == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  if (count > 1)
    {
      /* Turn on async mode */
      vam->async_mode = 1;
      vam->async_errors = 0;
      before = vat_time_now (vam);
    }

  for (j = 0; j < count; j++)
    {
      M (L2FIB_ADD_DEL, mp);

      clib_memcpy (mp->mac, mac, 6);
      mp->bd_id = ntohl (bd_id);
      mp->is_add = is_add;
      mp->sw_if_index = ntohl (sw_if_index);

      if (is_add)
	{
	  mp->static_mac = static_mac;
	  mp->filter_mac = filter_mac;
	  mp->bvi_mac = bvi_mac;
	}
      increment_mac_address (mac);
      /* send it... */
      S (mp);
    }

  if (count > 1)
    {
      vl_api_control_ping_t *mp_ping;
      f64 after;

      /* Shut off async mode */
      vam->async_mode = 0;

      PING (&l2_test_main, mp_ping);
      S (mp_ping);

      timeout = vat_time_now (vam) + 1.0;
      while (vat_time_now (vam) < timeout)
	if (vam->result_ready == 1)
	  goto out;
      vam->retval = -99;

    out:
      if (vam->retval == -99)
	errmsg ("timeout");

      if (vam->async_errors > 0)
	{
	  errmsg ("%d asynchronous errors", vam->async_errors);
	  vam->retval = -98;
	}
      vam->async_errors = 0;
      after = vat_time_now (vam);

      print (vam->ofp, "%d routes in %.6f secs, %.2f routes/sec", count,
	     after - before, count / (after - before));
    }
  else
    {
      int ret;

      /* Wait for a reply... */
      W (ret);
      return ret;
    }
  /* Return the good/bad news */
  return (vam->retval);
}

static int
api_l2fib_flush_int (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2fib_flush_int_t *mp;
  u32 sw_if_index = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2FIB_FLUSH_INT, mp);

  mp->sw_if_index = ntohl (sw_if_index);

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2_fib_clear_table (vat_main_t *vam)
{
  vl_api_l2_fib_clear_table_t *mp;
  int ret;

  M (L2_FIB_CLEAR_TABLE, mp);

  S (mp);
  W (ret);
  return ret;
}

static int
api_bridge_domain_set_mac_age (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bridge_domain_set_mac_age_t *mp;
  u32 bd_id = ~0;
  u32 mac_age = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	;
      else if (unformat (i, "mac-age %d", &mac_age))
	;
      else
	break;
    }

  if (bd_id == ~0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  if (mac_age > 255)
    {
      errmsg ("mac age must be less than 256 ");
      return -99;
    }

  M (BRIDGE_DOMAIN_SET_MAC_AGE, mp);

  mp->bd_id = htonl (bd_id);
  mp->mac_age = (u8) mac_age;

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2fib_set_scan_delay (vat_main_t *vam)
{
  return -1;
}

static int
api_want_l2_macs_events2 (vat_main_t *vam)
{
  return -1;
}

static int
api_l2_flags (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2_flags_t *mp;
  u32 sw_if_index;
  u32 flags = 0;
  u8 sw_if_index_set = 0;
  u8 is_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm,
			    &sw_if_index))
		sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "learn"))
	flags |= L2_LEARN;
      else if (unformat (i, "forward"))
	flags |= L2_FWD;
      else if (unformat (i, "flood"))
	flags |= L2_FLOOD;
      else if (unformat (i, "uu-flood"))
	flags |= L2_UU_FLOOD;
      else if (unformat (i, "arp-term"))
	flags |= L2_ARP_TERM;
      else if (unformat (i, "off"))
	is_set = 0;
      else if (unformat (i, "disable"))
	is_set = 0;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2_FLAGS, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->feature_bitmap = ntohl (flags);
  mp->is_set = is_set;

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_l2_flags_get_reply_t_handler (vl_api_l2_flags_get_reply_t *mp)
{
  vat_main_t *vam = l2_test_main.vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      if (retval == 0)
	fformat (vam->ofp, "input_feature_bitmap: 0x%08x output_feature_bitmap: 0x%08x\n",
		 ntohl (mp->input_feature_bitmap), ntohl (mp->output_feature_bitmap));
      vam->result_ready = 1;
    }
}

static int
api_l2_flags_get (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2_flags_get_t *mp;
  u32 sw_if_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2_FLAGS_GET, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  S (mp);
  W (ret);
  return ret;
}

static int
api_l2_flags_set (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2_flags_set_t *mp;
  u32 sw_if_index = ~0;
  u32 in_bitmap = 0;
  u32 out_bitmap = 0;
  u8 is_set = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (i, "input 0x%x", &in_bitmap))
	;
      else if (unformat (i, "output 0x%x", &out_bitmap))
	;
      else if (unformat (i, "disable"))
	is_set = 0;
      else if (unformat (i, "enable"))
	is_set = 1;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2_FLAGS_SET, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->input_feature_bitmap = ntohl (in_bitmap);
  mp->output_feature_bitmap = ntohl (out_bitmap);
  mp->is_set = is_set;
  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_l2_flags_reply_t_handler (vl_api_l2_flags_reply_t *mp)
{
  vat_main_t *vam = l2_test_main.vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

static int
api_l2fib_flush_bd (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_l2fib_flush_bd_t *mp;
  u32 bd_id = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	;
      else
	break;
    }

  if (bd_id == ~0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  M (L2FIB_FLUSH_BD, mp);

  mp->bd_id = htonl (bd_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_bridge_domain_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bridge_domain_add_del_t *mp;
  u32 bd_id = ~0;
  u8 is_add = 1;
  u32 flood = 1, forward = 1, learn = 1, uu_flood = 1, arp_term = 0;
  u8 *bd_tag = NULL;
  u32 mac_age = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	;
      else if (unformat (i, "flood %d", &flood))
	;
      else if (unformat (i, "uu-flood %d", &uu_flood))
	;
      else if (unformat (i, "forward %d", &forward))
	;
      else if (unformat (i, "learn %d", &learn))
	;
      else if (unformat (i, "arp-term %d", &arp_term))
	;
      else if (unformat (i, "mac-age %d", &mac_age))
	;
      else if (unformat (i, "bd-tag %s", &bd_tag))
	;
      else if (unformat (i, "del"))
	{
	  is_add = 0;
	  flood = uu_flood = forward = learn = 0;
	}
      else
	break;
    }

  if (bd_id == ~0)
    {
      errmsg ("missing bridge domain");
      ret = -99;
      goto done;
    }

  if (mac_age > 255)
    {
      errmsg ("mac age must be less than 256 ");
      ret = -99;
      goto done;
    }

  if ((bd_tag) && (vec_len (bd_tag) > 63))
    {
      errmsg ("bd-tag cannot be longer than 63");
      ret = -99;
      goto done;
    }

  M (BRIDGE_DOMAIN_ADD_DEL, mp);

  mp->bd_id = ntohl (bd_id);
  mp->flood = flood;
  mp->uu_flood = uu_flood;
  mp->forward = forward;
  mp->learn = learn;
  mp->arp_term = arp_term;
  mp->is_add = is_add;
  mp->mac_age = (u8) mac_age;
  if (bd_tag)
    {
      clib_memcpy (mp->bd_tag, bd_tag, vec_len (bd_tag));
      mp->bd_tag[vec_len (bd_tag)] = 0;
    }
  S (mp);
  W (ret);

done:
  vec_free (bd_tag);
  return ret;
}

static int
api_bridge_domain_add_del_v2 (vat_main_t *vam)
{
  return -1;
}

static void
vl_api_bridge_domain_add_del_v2_reply_t_handler (
  vl_api_bridge_domain_add_del_v2_reply_t *mp)
{
}

#define foreach_pbb_vtr_op                                                    \
  _ ("disable", L2_VTR_DISABLED)                                              \
  _ ("pop", L2_VTR_POP_2)                                                     \
  _ ("push", L2_VTR_PUSH_2)

static int
api_l2_interface_pbb_tag_rewrite (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2_interface_pbb_tag_rewrite_t *mp;
  u32 sw_if_index = ~0, vtr_op = ~0;
  u16 outer_tag = ~0;
  u8 dmac[6], smac[6];
  u8 dmac_set = 0, smac_set = 0;
  u16 vlanid = 0;
  u32 sid = ~0;
  u32 tmp;
  int ret;

  /* Shut up coverity */
  clib_memset (dmac, 0, sizeof (dmac));
  clib_memset (smac, 0, sizeof (smac));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "vtr_op %d", &vtr_op))
	;
#define _(n, v)                                                               \
  else if (unformat (i, n)) { vtr_op = v; }
      foreach_pbb_vtr_op
#undef _
	else if (unformat (i, "translate_pbb_stag"))
      {
	if (unformat (i, "%d", &tmp))
	  {
	    vtr_op = L2_VTR_TRANSLATE_2_1;
	    outer_tag = tmp;
	  }
	else
	  {
	    errmsg (
	      "translate_pbb_stag operation requires outer tag definition");
	    return -99;
	  }
      }
      else if (unformat (i, "dmac %U", unformat_ethernet_address, dmac))
	dmac_set++;
      else if (unformat (i, "smac %U", unformat_ethernet_address, smac))
	smac_set++;
      else if (unformat (i, "sid %d", &sid));
      else if (unformat (i, "vlanid %d", &tmp)) vlanid = tmp;
      else
      {
	clib_warning ("parse error '%U'", format_unformat_error, i);
	return -99;
      }
    }

  if ((sw_if_index == ~0) || (vtr_op == ~0))
    {
      errmsg ("missing sw_if_index or vtr operation");
      return -99;
    }
  if (((vtr_op == L2_VTR_PUSH_2) || (vtr_op == L2_VTR_TRANSLATE_2_2)) &&
      ((dmac_set == 0) || (smac_set == 0) || (sid == ~0)))
    {
      errmsg ("push and translate_qinq operations require dmac, smac, sid and "
	      "optionally vlanid");
      return -99;
    }

  M (L2_INTERFACE_PBB_TAG_REWRITE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->vtr_op = ntohl (vtr_op);
  mp->outer_tag = ntohs (outer_tag);
  clib_memcpy (mp->b_dmac, dmac, sizeof (dmac));
  clib_memcpy (mp->b_smac, smac, sizeof (smac));
  mp->b_vlanid = ntohs (vlanid);
  mp->i_sid = ntohl (sid);

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_set_l2_xconnect (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_l2_xconnect_t *mp;
  u32 rx_sw_if_index;
  u8 rx_sw_if_index_set = 0;
  u32 tx_sw_if_index;
  u8 tx_sw_if_index_set = 0;
  u8 enable = 1;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "rx_sw_if_index %d", &rx_sw_if_index))
	rx_sw_if_index_set = 1;
      else if (unformat (i, "tx_sw_if_index %d", &tx_sw_if_index))
	tx_sw_if_index_set = 1;
      else if (unformat (i, "rx"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm,
			    &rx_sw_if_index))
		rx_sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "tx"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm,
			    &tx_sw_if_index))
		tx_sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	break;
    }

  if (rx_sw_if_index_set == 0)
    {
      errmsg ("missing rx interface name or rx_sw_if_index");
      return -99;
    }

  if (enable && (tx_sw_if_index_set == 0))
    {
      errmsg ("missing tx interface name or tx_sw_if_index");
      return -99;
    }

  M (SW_INTERFACE_SET_L2_XCONNECT, mp);

  mp->rx_sw_if_index = ntohl (rx_sw_if_index);
  mp->tx_sw_if_index = ntohl (tx_sw_if_index);
  mp->enable = enable;

  S (mp);
  W (ret);
  return ret;
}

static int
api_l2_interface_efp_filter (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2_interface_efp_filter_t *mp;
  u32 sw_if_index;
  u8 enable = 1;
  u8 sw_if_index_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing sw_if_index");
      return -99;
    }

  M (L2_INTERFACE_EFP_FILTER, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable;

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_bd_ip_mac_details_t_handler (vl_api_bd_ip_mac_details_t *mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "\n%-5d %U %U", ntohl (mp->entry.bd_id),
	 format_vl_api_mac_address, mp->entry.mac, format_vl_api_address,
	 &mp->entry.ip);
}

static void
vl_api_bvi_create_reply_t_handler (vl_api_bvi_create_reply_t *mp)
{
}

static int
api_sw_interface_set_l2_bridge (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_l2_bridge_t *mp;
  vl_api_l2_port_type_t port_type;
  u32 rx_sw_if_index;
  u8 rx_sw_if_index_set = 0;
  u32 bd_id;
  u8 bd_id_set = 0;
  u32 shg = 0;
  u8 enable = 1;
  int ret;

  port_type = L2_API_PORT_TYPE_NORMAL;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &rx_sw_if_index))
	rx_sw_if_index_set = 1;
      else if (unformat (i, "bd_id %d", &bd_id))
	bd_id_set = 1;
      else if (unformat (i, "%U", unformat_vnet_sw_interface, vnm,
			 &rx_sw_if_index))
	rx_sw_if_index_set = 1;
      else if (unformat (i, "shg %d", &shg))
	;
      else if (unformat (i, "bvi"))
	port_type = L2_API_PORT_TYPE_BVI;
      else if (unformat (i, "uu-fwd"))
	port_type = L2_API_PORT_TYPE_UU_FWD;
      else if (unformat (i, "enable"))
	enable = 1;
      else if (unformat (i, "disable"))
	enable = 0;
      else
	break;
    }

  if (rx_sw_if_index_set == 0)
    {
      errmsg ("missing rx interface name or sw_if_index");
      return -99;
    }

  if (enable && (bd_id_set == 0))
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  M (SW_INTERFACE_SET_L2_BRIDGE, mp);

  mp->rx_sw_if_index = ntohl (rx_sw_if_index);
  mp->bd_id = ntohl (bd_id);
  mp->shg = (u8) shg;
  mp->port_type = ntohl (port_type);
  mp->enable = enable;

  S (mp);
  W (ret);
  return ret;
}

static int
api_sw_interface_set_vpath (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_sw_interface_set_vpath_t *mp;
  u32 sw_if_index = 0;
  u8 sw_if_index_set = 0;
  u8 is_enable = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "enable"))
	is_enable = 1;
      else if (unformat (i, "disable"))
	is_enable = 0;
      else
	break;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  /* Construct the API message */
  M (SW_INTERFACE_SET_VPATH, mp);

  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable = is_enable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_l2_patch_add_del (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2_patch_add_del_t *mp;
  u32 rx_sw_if_index;
  u8 rx_sw_if_index_set = 0;
  u32 tx_sw_if_index;
  u8 tx_sw_if_index_set = 0;
  u8 is_add = 1;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "rx_sw_if_index %d", &rx_sw_if_index))
	rx_sw_if_index_set = 1;
      else if (unformat (i, "tx_sw_if_index %d", &tx_sw_if_index))
	tx_sw_if_index_set = 1;
      else if (unformat (i, "rx"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm,
			    &rx_sw_if_index))
		rx_sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "tx"))
	{
	  if (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm,
			    &tx_sw_if_index))
		tx_sw_if_index_set = 1;
	    }
	  else
	    break;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else
	break;
    }

  if (rx_sw_if_index_set == 0)
    {
      errmsg ("missing rx interface name or rx_sw_if_index");
      return -99;
    }

  if (tx_sw_if_index_set == 0)
    {
      errmsg ("missing tx interface name or tx_sw_if_index");
      return -99;
    }

  M (L2_PATCH_ADD_DEL, mp);

  mp->rx_sw_if_index = ntohl (rx_sw_if_index);
  mp->tx_sw_if_index = ntohl (tx_sw_if_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_bridge_flags_reply_t_handler (vl_api_bridge_flags_reply_t *mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

#define foreach_vtr_op                                                        \
  _ ("disable", L2_VTR_DISABLED)                                              \
  _ ("push-1", L2_VTR_PUSH_1)                                                 \
  _ ("push-2", L2_VTR_PUSH_2)                                                 \
  _ ("pop-1", L2_VTR_POP_1)                                                   \
  _ ("pop-2", L2_VTR_POP_2)                                                   \
  _ ("translate-1-1", L2_VTR_TRANSLATE_1_1)                                   \
  _ ("translate-1-2", L2_VTR_TRANSLATE_1_2)                                   \
  _ ("translate-2-1", L2_VTR_TRANSLATE_2_1)                                   \
  _ ("translate-2-2", L2_VTR_TRANSLATE_2_2)

static int
api_l2_interface_vlan_tag_rewrite (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2_interface_vlan_tag_rewrite_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u8 vtr_op_set = 0;
  u32 vtr_op = 0;
  u32 push_dot1q = 1;
  u32 tag1 = ~0;
  u32 tag2 = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "vtr_op %d", &vtr_op))
	vtr_op_set = 1;
#define _(n, v)                                                               \
  else if (unformat (i, n))                                                   \
  {                                                                           \
    vtr_op = v;                                                               \
    vtr_op_set = 1;                                                           \
  }
      foreach_vtr_op
#undef _
	else if (unformat (i, "push_dot1q %d", &push_dot1q));
      else if (unformat (i, "tag1 %d", &tag1));
      else if (unformat (i, "tag2 %d", &tag2));
      else
      {
	clib_warning ("parse error '%U'", format_unformat_error, i);
	return -99;
      }
    }

  if ((sw_if_index_set == 0) || (vtr_op_set == 0))
    {
      errmsg ("missing vtr operation or sw_if_index");
      return -99;
    }

  M (L2_INTERFACE_VLAN_TAG_REWRITE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->vtr_op = ntohl (vtr_op);
  mp->push_dot1q = ntohl (push_dot1q);
  mp->tag1 = ntohl (tag1);
  mp->tag2 = ntohl (tag2);

  S (mp);
  W (ret);
  return ret;
}

static int
api_bridge_domain_set_learn_limit (vat_main_t *vam)
{
  return -1;
}

static int
api_bd_ip_mac_add_del (vat_main_t *vam)
{
  vl_api_address_t ip = VL_API_ZERO_ADDRESS;
  vl_api_mac_address_t mac = { 0 };
  unformat_input_t *i = vam->input;
  vl_api_bd_ip_mac_add_del_t *mp;
  u32 bd_id;
  u8 is_add = 1;
  u8 bd_id_set = 0;
  u8 ip_set = 0;
  u8 mac_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	{
	  bd_id_set++;
	}
      else if (unformat (i, "%U", unformat_vl_api_address, &ip))
	{
	  ip_set++;
	}
      else if (unformat (i, "%U", unformat_vl_api_mac_address, &mac))
	{
	  mac_set++;
	}
      else if (unformat (i, "del"))
	is_add = 0;
      else
	break;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }
  else if (ip_set == 0)
    {
      errmsg ("missing IP address");
      return -99;
    }
  else if (mac_set == 0)
    {
      errmsg ("missing MAC address");
      return -99;
    }

  M (BD_IP_MAC_ADD_DEL, mp);

  mp->entry.bd_id = ntohl (bd_id);
  mp->is_add = is_add;

  clib_memcpy (&mp->entry.ip, &ip, sizeof (ip));
  clib_memcpy (&mp->entry.mac, &mac, sizeof (mac));

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_bridge_domain_details_t_handler (vl_api_bridge_domain_details_t *mp)
{
  vat_main_t *vam = l2_test_main.vat_main;
  u32 n_sw_ifs = ntohl (mp->n_sw_ifs);
  int i;

  print (vam->ofp, "\n%-3s %-3s %-3s %-3s %-3s %-6s %-3s", " ID", "LRN", "FWD",
	 "FLD", "BVI", "UU-FWD", "#IF");

  print (vam->ofp, "%3d %3d %3d %3d %3d %6d %3d", ntohl (mp->bd_id), mp->learn,
	 mp->forward, mp->flood, ntohl (mp->bvi_sw_if_index),
	 ntohl (mp->uu_fwd_sw_if_index), n_sw_ifs);

  if (n_sw_ifs)
    {
      vl_api_bridge_domain_sw_if_t *sw_ifs;
      print (vam->ofp, "\n\n%s %s  %s", "sw_if_index", "SHG",
	     "Interface Name");

      sw_ifs = mp->sw_if_details;
      for (i = 0; i < n_sw_ifs; i++)
	{
	  u8 *sw_if_name = 0;
	  u32 sw_if_index;
	  hash_pair_t *p;

	  sw_if_index = ntohl (sw_ifs->sw_if_index);

	  hash_foreach_pair (p, vam->sw_if_index_by_interface_name, ({
			       if ((u32) p->value[0] == sw_if_index)
				 {
				   sw_if_name = (u8 *) (p->key);
				   break;
				 }
			     }));
	  print (vam->ofp, "%7d     %3d  %s", sw_if_index, sw_ifs->shg,
		 sw_if_name ? (char *) sw_if_name : "sw_if_index not found!");

	  sw_ifs++;
	}
    }
}

static int
api_bridge_domain_dump (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bridge_domain_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 bd_id = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	;
      else
	break;
    }

  M (BRIDGE_DOMAIN_DUMP, mp);
  mp->bd_id = ntohl (bd_id);
  S (mp);

  /* Use a control ping for synchronization */
  PING (&l2_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_bridge_domain_set_default_learn_limit (vat_main_t *vam)
{
  return -1;
}

static int
api_bd_ip_mac_flush (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bd_ip_mac_flush_t *mp;
  u32 bd_id;
  u8 bd_id_set = 0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	{
	  bd_id_set++;
	}
      else
	break;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  M (BD_IP_MAC_FLUSH, mp);

  mp->bd_id = ntohl (bd_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_bd_ip_mac_dump (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bd_ip_mac_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;
  u32 bd_id;
  u8 bd_id_set = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	{
	  bd_id_set++;
	}
      else
	break;
    }

  fformat (vam->ofp, "\n%-5s %-7s %-20s %-30s", "bd_id", "is_ipv6",
	   "mac_address", "ip_address");

  /* Dump Bridge Domain Ip to Mac entries */
  M (BD_IP_MAC_DUMP, mp);

  if (bd_id_set)
    mp->bd_id = htonl (bd_id);
  else
    mp->bd_id = ~0;

  S (mp);

  /* Use a control ping for synchronization */
  PING (&l2_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static int
api_bvi_create (vat_main_t *vam)
{
  return -1;
}

static int
api_bvi_delete (vat_main_t *vam)
{
  return -1;
}

static int
api_bridge_flags (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_bridge_flags_t *mp;
  u32 bd_id;
  u8 bd_id_set = 0;
  u8 is_set = 1;
  bd_flags_t flags = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bd_id %d", &bd_id))
	bd_id_set = 1;
      else if (unformat (i, "learn"))
	flags |= BRIDGE_API_FLAG_LEARN;
      else if (unformat (i, "forward"))
	flags |= BRIDGE_API_FLAG_FWD;
      else if (unformat (i, "flood"))
	flags |= BRIDGE_API_FLAG_FLOOD;
      else if (unformat (i, "uu-flood"))
	flags |= BRIDGE_API_FLAG_UU_FLOOD;
      else if (unformat (i, "arp-term"))
	flags |= BRIDGE_API_FLAG_ARP_TERM;
      else if (unformat (i, "off"))
	is_set = 0;
      else if (unformat (i, "disable"))
	is_set = 0;
      else
	break;
    }

  if (bd_id_set == 0)
    {
      errmsg ("missing bridge domain");
      return -99;
    }

  M (BRIDGE_FLAGS, mp);

  mp->bd_id = ntohl (bd_id);
  mp->flags = ntohl (flags);
  mp->is_set = is_set;

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_l2_interface_feat_flags_get_reply_t_handler (vl_api_l2_interface_feat_flags_get_reply_t *mp)
{
  vat_main_t *vam = l2_test_main.vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      if (retval == 0)
	{
	  u32 flags = ntohl (mp->flags);
	  fformat (vam->ofp, "flags: 0x%08x%s%s%s%s%s%s\n", flags, (flags & 0x01) ? " learn" : "",
		   (flags & 0x02) ? " fwd" : "", (flags & 0x04) ? " flood" : "",
		   (flags & 0x08) ? " uu-flood" : "", (flags & 0x10) ? " arp-term" : "",
		   (flags & 0x20) ? " arp-ufwd" : "");
	}
      vam->result_ready = 1;
    }
}

static int
api_l2_interface_feat_flags_get (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2_interface_feat_flags_get_t *mp;
  u32 sw_if_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2_INTERFACE_FEAT_FLAGS_GET, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  S (mp);
  W (ret);
  return ret;
}

static int
api_l2_interface_feat_flags_set (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_l2_interface_feat_flags_set_t *mp;
  u32 sw_if_index = ~0;
  u32 flags = 0;
  u8 is_set = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (i, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (i, "learn"))
	flags |= 0x01;
      else if (unformat (i, "fwd"))
	flags |= 0x02;
      else if (unformat (i, "flood"))
	flags |= 0x04;
      else if (unformat (i, "uu-flood"))
	flags |= 0x08;
      else if (unformat (i, "arp-term"))
	flags |= 0x10;
      else if (unformat (i, "arp-ufwd"))
	flags |= 0x20;
      else if (unformat (i, "disable"))
	is_set = 0;
      else if (unformat (i, "enable"))
	is_set = 1;
      else
	break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (L2_INTERFACE_FEAT_FLAGS_SET, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->flags = ntohl (flags);
  mp->is_set = is_set;
  S (mp);
  W (ret);
  return ret;
}

#include <vnet/l2/l2.api_test.c>

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
