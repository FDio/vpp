/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp/api/types.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base ipsec_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#include <vlibmemory/vlib.api_enum.h>
#include <vlibmemory/vlib.api_types.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <vnet/ipsec/ipsec.api_enum.h>
#include <vnet/ipsec/ipsec.api_types.h>

#define vl_endianfun /* define message structures */
#include <vnet/ipsec/ipsec.api.h>
#undef vl_endianfun

#define vl_calcsizefun
#include <vnet/ipsec/ipsec.api.h>
#undef vl_calcsizefun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} ipsec_test_main_t;

static ipsec_test_main_t ipsec_test_main;

static void
vl_api_ipsec_spds_details_t_handler (vl_api_ipsec_spds_details_t *mp)
{
}

static void
vl_api_ipsec_itf_details_t_handler (vl_api_ipsec_itf_details_t *mp)
{
}

static int
api_ipsec_itf_delete (vat_main_t *vat)
{
  return -1;
}

static int
api_ipsec_itf_create (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ipsec_itf_create_reply_t_handler (vl_api_ipsec_itf_create_reply_t *vat)
{
}

static int
api_ipsec_spd_entry_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_spd_entry_add_del_t *mp;
  u8 is_add = 1, is_outbound = 0;
  u32 spd_id = 0, sa_id = 0, protocol = IPSEC_POLICY_PROTOCOL_ANY, policy = 0;
  i32 priority = 0;
  u32 rport_start = 0, rport_stop = (u32) ~0;
  u32 lport_start = 0, lport_stop = (u32) ~0;
  vl_api_address_t laddr_start = {}, laddr_stop = {}, raddr_start = {},
		   raddr_stop = {};
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      if (unformat (i, "outbound"))
	is_outbound = 1;
      if (unformat (i, "inbound"))
	is_outbound = 0;
      else if (unformat (i, "spd_id %d", &spd_id))
	;
      else if (unformat (i, "sa_id %d", &sa_id))
	;
      else if (unformat (i, "priority %d", &priority))
	;
      else if (unformat (i, "protocol %d", &protocol))
	;
      else if (unformat (i, "lport_start %d", &lport_start))
	;
      else if (unformat (i, "lport_stop %d", &lport_stop))
	;
      else if (unformat (i, "rport_start %d", &rport_start))
	;
      else if (unformat (i, "rport_stop %d", &rport_stop))
	;
      else if (unformat (i, "laddr_start %U", unformat_vl_api_address,
			 &laddr_start))
	;
      else if (unformat (i, "laddr_stop %U", unformat_vl_api_address,
			 &laddr_stop))
	;
      else if (unformat (i, "raddr_start %U", unformat_vl_api_address,
			 &raddr_start))
	;
      else if (unformat (i, "raddr_stop %U", unformat_vl_api_address,
			 &raddr_stop))
	;
      else if (unformat (i, "action %U", unformat_ipsec_policy_action,
			 &policy))
	{
	  if (policy == IPSEC_POLICY_ACTION_RESOLVE)
	    {
	      clib_warning ("unsupported action: 'resolve'");
	      return -99;
	    }
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IPSEC_SPD_ENTRY_ADD_DEL, mp);

  mp->is_add = is_add;

  mp->entry.spd_id = ntohl (spd_id);
  mp->entry.priority = ntohl (priority);
  mp->entry.is_outbound = is_outbound;

  clib_memcpy (&mp->entry.remote_address_start, &raddr_start,
	       sizeof (vl_api_address_t));
  clib_memcpy (&mp->entry.remote_address_stop, &raddr_stop,
	       sizeof (vl_api_address_t));
  clib_memcpy (&mp->entry.local_address_start, &laddr_start,
	       sizeof (vl_api_address_t));
  clib_memcpy (&mp->entry.local_address_stop, &laddr_stop,
	       sizeof (vl_api_address_t));

  mp->entry.protocol = protocol ? (u8) protocol : IPSEC_POLICY_PROTOCOL_ANY;
  mp->entry.local_port_start = ntohs ((u16) lport_start);
  mp->entry.local_port_stop = ntohs ((u16) lport_stop);
  mp->entry.remote_port_start = ntohs ((u16) rport_start);
  mp->entry.remote_port_stop = ntohs ((u16) rport_stop);
  mp->entry.policy = (u8) policy;
  mp->entry.sa_id = ntohl (sa_id);

  S (mp);
  W (ret);
  return ret;
}

static int
api_ipsec_spd_entry_add_del_v2 (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_spd_entry_add_del_t *mp;
  u8 is_add = 1, is_outbound = 0;
  u32 spd_id = 0, sa_id = 0, protocol = IPSEC_POLICY_PROTOCOL_ANY, policy = 0;
  i32 priority = 0;
  u32 rport_start = 0, rport_stop = (u32) ~0;
  u32 lport_start = 0, lport_stop = (u32) ~0;
  vl_api_address_t laddr_start = {}, laddr_stop = {}, raddr_start = {},
		   raddr_stop = {};
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      if (unformat (i, "outbound"))
	is_outbound = 1;
      if (unformat (i, "inbound"))
	is_outbound = 0;
      else if (unformat (i, "spd_id %d", &spd_id))
	;
      else if (unformat (i, "sa_id %d", &sa_id))
	;
      else if (unformat (i, "priority %d", &priority))
	;
      else if (unformat (i, "protocol %d", &protocol))
	;
      else if (unformat (i, "lport_start %d", &lport_start))
	;
      else if (unformat (i, "lport_stop %d", &lport_stop))
	;
      else if (unformat (i, "rport_start %d", &rport_start))
	;
      else if (unformat (i, "rport_stop %d", &rport_stop))
	;
      else if (unformat (i, "laddr_start %U", unformat_vl_api_address,
			 &laddr_start))
	;
      else if (unformat (i, "laddr_stop %U", unformat_vl_api_address,
			 &laddr_stop))
	;
      else if (unformat (i, "raddr_start %U", unformat_vl_api_address,
			 &raddr_start))
	;
      else if (unformat (i, "raddr_stop %U", unformat_vl_api_address,
			 &raddr_stop))
	;
      else if (unformat (i, "action %U", unformat_ipsec_policy_action,
			 &policy))
	{
	  if (policy == IPSEC_POLICY_ACTION_RESOLVE)
	    {
	      clib_warning ("unsupported action: 'resolve'");
	      return -99;
	    }
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IPSEC_SPD_ENTRY_ADD_DEL, mp);

  mp->is_add = is_add;

  mp->entry.spd_id = ntohl (spd_id);
  mp->entry.priority = ntohl (priority);
  mp->entry.is_outbound = is_outbound;

  clib_memcpy (&mp->entry.remote_address_start, &raddr_start,
	       sizeof (vl_api_address_t));
  clib_memcpy (&mp->entry.remote_address_stop, &raddr_stop,
	       sizeof (vl_api_address_t));
  clib_memcpy (&mp->entry.local_address_start, &laddr_start,
	       sizeof (vl_api_address_t));
  clib_memcpy (&mp->entry.local_address_stop, &laddr_stop,
	       sizeof (vl_api_address_t));

  mp->entry.protocol = (u8) protocol;
  mp->entry.local_port_start = ntohs ((u16) lport_start);
  mp->entry.local_port_stop = ntohs ((u16) lport_stop);
  mp->entry.remote_port_start = ntohs ((u16) rport_start);
  mp->entry.remote_port_stop = ntohs ((u16) rport_stop);
  mp->entry.policy = (u8) policy;
  mp->entry.sa_id = ntohl (sa_id);

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_ipsec_spd_details_t_handler (vl_api_ipsec_spd_details_t *mp)
{
}

static void
vl_api_ipsec_sad_entry_add_del_reply_t_handler (
  vl_api_ipsec_sad_entry_add_del_reply_t *mp)
{
}

static void
vl_api_ipsec_sad_entry_add_del_v3_reply_t_handler (
  vl_api_ipsec_sad_entry_add_del_v3_reply_t *mp)
{
}

static void
vl_api_ipsec_sad_entry_add_reply_t_handler (
  vl_api_ipsec_sad_entry_add_reply_t *mp)
{
}

static void
vl_api_ipsec_sad_entry_add_v2_reply_t_handler (
  vl_api_ipsec_sad_entry_add_reply_t *mp)
{
}

static int
api_ipsec_sad_entry_del (vat_main_t *vat)
{
  return -1;
}

static int
api_ipsec_sad_bind (vat_main_t *vat)
{
  return -1;
}

static int
api_ipsec_sad_unbind (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ipsec_sad_entry_add_del_v2_reply_t_handler (
  vl_api_ipsec_sad_entry_add_del_v2_reply_t *mp)
{
}

static void
vl_api_ipsec_spd_interface_details_t_handler (
  vl_api_ipsec_spd_interface_details_t *vat)
{
}

static int
api_ipsec_sad_entry_add_del_v3 (vat_main_t *vat)
{
  return -1;
}

static int
api_ipsec_sad_entry_update (vat_main_t *vat)
{
  return -1;
}

static int
api_ipsec_tunnel_protect_update (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ipsec_backend_details_t_handler (vl_api_ipsec_backend_details_t *mp)
{
}

static int
api_ipsec_sa_v3_dump (vat_main_t *vat)
{
  return -1;
}

static int
api_ipsec_sa_v4_dump (vat_main_t *vat)
{
  return -1;
}

static int
api_ipsec_tunnel_protect_dump (vat_main_t *vat)
{
  return -1;
}

static int
api_ipsec_tunnel_protect_del (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ipsec_tunnel_protect_details_t_handler (
  vl_api_ipsec_tunnel_protect_details_t *mp)
{
}

static int
api_ipsec_sad_entry_add (vat_main_t *vat)
{
  return -1;
}

static int
api_ipsec_sad_entry_add_v2 (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ipsec_spd_entry_add_del_reply_t_handler (
  vl_api_ipsec_spd_entry_add_del_reply_t *mp)
{
}

static void
vl_api_ipsec_spd_entry_add_del_v2_reply_t_handler (
  vl_api_ipsec_spd_entry_add_del_v2_reply_t *mp)
{
}

static int
api_ipsec_spds_dump (vat_main_t *vam)
{
  return -1;
}

static int
api_ipsec_itf_dump (vat_main_t *vam)
{
  return -1;
}

static void
vl_api_ipsec_sa_v3_details_t_handler (vl_api_ipsec_sa_v3_details_t *mp)
{
}

static void
vl_api_ipsec_sa_v4_details_t_handler (vl_api_ipsec_sa_v4_details_t *mp)
{
}

static int
api_ipsec_spd_interface_dump (vat_main_t *vat)
{
  return -1;
}

static void
vl_api_ipsec_sa_v2_details_t_handler (vl_api_ipsec_sa_v2_details_t *mp)
{
}

static int
api_ipsec_sa_v2_dump (vat_main_t *mp)
{
  return -1;
}

static int
api_ipsec_sa_dump (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_sa_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u32 sa_id = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "sa_id %d", &sa_id))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IPSEC_SA_DUMP, mp);

  mp->sa_id = ntohl (sa_id);

  S (mp);

  /* Use a control ping for synchronization */
  PING (&ipsec_test_main, mp_ping);
  S (mp_ping);

  W (ret);
  return ret;
}

static void
vl_api_ipsec_sa_details_t_handler (vl_api_ipsec_sa_details_t *mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp,
	 "sa_id %u sw_if_index %u spi %u proto %u crypto_alg %u "
	 "crypto_key %U integ_alg %u integ_key %U flags %x "
	 "tunnel_src_addr %U tunnel_dst_addr %U "
	 "salt %u seq_outbound %lu last_seq_inbound %lu "
	 "replay_window %lu stat_index %u\n",
	 ntohl (mp->entry.sad_id), ntohl (mp->sw_if_index),
	 ntohl (mp->entry.spi), ntohl (mp->entry.protocol),
	 ntohl (mp->entry.crypto_algorithm), format_hex_bytes,
	 mp->entry.crypto_key.data, mp->entry.crypto_key.length,
	 ntohl (mp->entry.integrity_algorithm), format_hex_bytes,
	 mp->entry.integrity_key.data, mp->entry.integrity_key.length,
	 ntohl (mp->entry.flags), format_vl_api_address, &mp->entry.tunnel_src,
	 format_vl_api_address, &mp->entry.tunnel_dst, ntohl (mp->salt),
	 clib_net_to_host_u64 (mp->seq_outbound),
	 clib_net_to_host_u64 (mp->last_seq_inbound),
	 clib_net_to_host_u64 (mp->replay_window), ntohl (mp->stat_index));
}

static int
api_ipsec_spd_dump (vat_main_t *vam)
{
  return -1;
}

uword
unformat_ipsec_api_crypto_alg (unformat_input_t *input, va_list *args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0)
    ;
#define _(v, f, s) else if (unformat (input, s)) *r = IPSEC_API_CRYPTO_ALG_##f;
  foreach_ipsec_crypto_alg
#undef _
    else return 0;
  return 1;
}

uword
unformat_ipsec_api_integ_alg (unformat_input_t *input, va_list *args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0)
    ;
#define _(v, f, s) else if (unformat (input, s)) *r = IPSEC_API_INTEG_ALG_##f;
  foreach_ipsec_integ_alg
#undef _
    else return 0;
  return 1;
}

static int
api_ipsec_sad_entry_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_sad_entry_add_del_t *mp;
  u32 sad_id = 0, spi = 0;
  u8 *ck = 0, *ik = 0;
  u8 is_add = 1;

  vl_api_ipsec_crypto_alg_t crypto_alg = IPSEC_API_CRYPTO_ALG_NONE;
  vl_api_ipsec_integ_alg_t integ_alg = IPSEC_API_INTEG_ALG_NONE;
  vl_api_ipsec_sad_flags_t flags = IPSEC_API_SAD_FLAG_NONE;
  vl_api_ipsec_proto_t protocol = IPSEC_API_PROTO_AH;
  vl_api_address_t tun_src, tun_dst;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "sad_id %d", &sad_id))
	;
      else if (unformat (i, "spi %d", &spi))
	;
      else if (unformat (i, "esp"))
	protocol = IPSEC_API_PROTO_ESP;
      else if (unformat (i, "tunnel_src %U", unformat_vl_api_address,
			 &tun_src))
	{
	  flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
	  if (ADDRESS_IP6 == tun_src.af)
	    flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
	}
      else if (unformat (i, "tunnel_dst %U", unformat_vl_api_address,
			 &tun_dst))
	{
	  flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
	  if (ADDRESS_IP6 == tun_src.af)
	    flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
	}
      else if (unformat (i, "crypto_alg %U", unformat_ipsec_api_crypto_alg,
			 &crypto_alg))
	;
      else if (unformat (i, "crypto_key %U", unformat_hex_string, &ck))
	;
      else if (unformat (i, "integ_alg %U", unformat_ipsec_api_integ_alg,
			 &integ_alg))
	;
      else if (unformat (i, "integ_key %U", unformat_hex_string, &ik))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  M (IPSEC_SAD_ENTRY_ADD_DEL, mp);

  mp->is_add = is_add;
  mp->entry.sad_id = ntohl (sad_id);
  mp->entry.protocol = protocol;
  mp->entry.spi = ntohl (spi);
  mp->entry.flags = flags;

  mp->entry.crypto_algorithm = crypto_alg;
  mp->entry.integrity_algorithm = integ_alg;
  mp->entry.crypto_key.length = vec_len (ck);
  mp->entry.integrity_key.length = vec_len (ik);

  if (mp->entry.crypto_key.length > sizeof (mp->entry.crypto_key.data))
    mp->entry.crypto_key.length = sizeof (mp->entry.crypto_key.data);

  if (mp->entry.integrity_key.length > sizeof (mp->entry.integrity_key.data))
    mp->entry.integrity_key.length = sizeof (mp->entry.integrity_key.data);

  if (ck)
    clib_memcpy (mp->entry.crypto_key.data, ck, mp->entry.crypto_key.length);
  if (ik)
    clib_memcpy (mp->entry.integrity_key.data, ik,
		 mp->entry.integrity_key.length);

  if (flags & IPSEC_API_SAD_FLAG_IS_TUNNEL)
    {
      clib_memcpy (&mp->entry.tunnel_src, &tun_src,
		   sizeof (mp->entry.tunnel_src));
      clib_memcpy (&mp->entry.tunnel_dst, &tun_dst,
		   sizeof (mp->entry.tunnel_dst));
    }

  S (mp);
  W (ret);
  return ret;
}

static int
api_ipsec_sad_entry_add_del_v2 (vat_main_t *vam)
{
  return -1;
}

static int
api_ipsec_interface_add_del_spd (vat_main_t *vam)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t *i = vam->input;
  vl_api_ipsec_interface_add_del_spd_t *mp;
  u32 sw_if_index;
  u8 sw_if_index_set = 0;
  u32 spd_id = (u32) ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "spd_id %d", &spd_id))
	;
      else if (unformat (i, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (spd_id == (u32) ~0)
    {
      errmsg ("spd_id must be set");
      return -99;
    }

  if (sw_if_index_set == 0)
    {
      errmsg ("missing interface name or sw_if_index");
      return -99;
    }

  M (IPSEC_INTERFACE_ADD_DEL_SPD, mp);

  mp->spd_id = ntohl (spd_id);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

static int
api_ipsec_backend_dump (vat_main_t *vam)
{
  return -1;
}

static int
api_ipsec_select_backend (vat_main_t *vam)
{
  return -1;
}

static int
api_ipsec_set_async_mode (vat_main_t *vam)
{
  return -1;
}

static int
api_ipsec_spd_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_ipsec_spd_add_del_t *mp;
  u32 spd_id = ~0;
  u8 is_add = 1;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "spd_id %d", &spd_id))
	;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }
  if (spd_id == ~0)
    {
      errmsg ("spd_id must be set");
      return -99;
    }

  M (IPSEC_SPD_ADD_DEL, mp);

  mp->spd_id = ntohl (spd_id);
  mp->is_add = is_add;

  S (mp);
  W (ret);
  return ret;
}

#include <vnet/ipsec/ipsec.api_test.c>

/*
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
