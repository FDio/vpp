/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp/api/types.h>

#include <vnet/ip/ip_types_api.h>

#define __plugin_msg_base session_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <vnet/session/session.api_enum.h>
#include <vnet/session/session.api_types.h>

#define vl_endianfun /* define message structures */
#include <vnet/session/session.api.h>
#undef vl_endianfun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} session_test_main_t;

static session_test_main_t session_test_main;

static int
api_session_rule_add_del (vat_main_t *vam)
{
  vl_api_session_rule_add_del_t *mp;
  unformat_input_t *i = vam->input;
  u32 proto = ~0, lcl_port, rmt_port, action = 0, lcl_plen, rmt_plen;
  u32 appns_index = 0, scope = 0;
  ip4_address_t lcl_ip4, rmt_ip4;
  ip6_address_t lcl_ip6, rmt_ip6;
  u8 is_ip4 = 1, conn_set = 0;
  u8 is_add = 1, *tag = 0;
  int ret;
  fib_prefix_t lcl, rmt;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "add"))
	;
      else if (unformat (i, "proto tcp"))
	proto = 0;
      else if (unformat (i, "proto udp"))
	proto = 1;
      else if (unformat (i, "appns %d", &appns_index))
	;
      else if (unformat (i, "scope %d", &scope))
	;
      else if (unformat (i, "tag %_%v%_", &tag))
	;
      else if (unformat (i, "%U/%d %d %U/%d %d", unformat_ip4_address,
			 &lcl_ip4, &lcl_plen, &lcl_port, unformat_ip4_address,
			 &rmt_ip4, &rmt_plen, &rmt_port))
	{
	  is_ip4 = 1;
	  conn_set = 1;
	}
      else if (unformat (i, "%U/%d %d %U/%d %d", unformat_ip6_address,
			 &lcl_ip6, &lcl_plen, &lcl_port, unformat_ip6_address,
			 &rmt_ip6, &rmt_plen, &rmt_port))
	{
	  is_ip4 = 0;
	  conn_set = 1;
	}
      else if (unformat (i, "action %d", &action))
	;
      else
	break;
    }
  if (proto == ~0 || !conn_set || action == ~0)
    {
      errmsg ("transport proto, connection and action must be set");
      return -99;
    }

  if (scope > 3)
    {
      errmsg ("scope should be 0-3");
      return -99;
    }

  M (SESSION_RULE_ADD_DEL, mp);

  clib_memset (&lcl, 0, sizeof (lcl));
  clib_memset (&rmt, 0, sizeof (rmt));
  if (is_ip4)
    {
      ip_set (&lcl.fp_addr, &lcl_ip4, 1);
      ip_set (&rmt.fp_addr, &rmt_ip4, 1);
      lcl.fp_len = lcl_plen;
      rmt.fp_len = rmt_plen;
    }
  else
    {
      ip_set (&lcl.fp_addr, &lcl_ip6, 0);
      ip_set (&rmt.fp_addr, &rmt_ip6, 0);
      lcl.fp_len = lcl_plen;
      rmt.fp_len = rmt_plen;
    }

  ip_prefix_encode (&lcl, &mp->lcl);
  ip_prefix_encode (&rmt, &mp->rmt);
  mp->lcl_port = clib_host_to_net_u16 ((u16) lcl_port);
  mp->rmt_port = clib_host_to_net_u16 ((u16) rmt_port);
  mp->transport_proto =
    proto ? TRANSPORT_PROTO_API_UDP : TRANSPORT_PROTO_API_TCP;
  mp->action_index = clib_host_to_net_u32 (action);
  mp->appns_index = clib_host_to_net_u32 (appns_index);
  mp->scope = scope;
  mp->is_add = is_add;
  if (tag)
    {
      clib_memcpy (mp->tag, tag, vec_len (tag));
      vec_free (tag);
    }

  S (mp);
  W (ret);
  return ret;
}

static void
vl_api_app_attach_reply_t_handler (vl_api_app_attach_reply_t *mp)
{
}

static void
vl_api_app_add_cert_key_pair_reply_t_handler (
  vl_api_app_add_cert_key_pair_reply_t *mp)
{
}

static int
api_app_attach (vat_main_t *vat)
{
  return -1;
}

static int
api_application_detach (vat_main_t *vat)
{
  return -1;
}

static int
api_app_del_cert_key_pair (vat_main_t *vat)
{
  return -1;
}

static int
api_app_add_cert_key_pair (vat_main_t *vat)
{
  return -1;
}

static int
api_session_rules_dump (vat_main_t *vam)
{
  vl_api_session_rules_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "Session Rules");
    }

  M (SESSION_RULES_DUMP, mp);
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  PING (&session_test_main, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
vl_api_session_rules_details_t_handler (vl_api_session_rules_details_t *mp)
{
  vat_main_t *vam = &vat_main;
  fib_prefix_t lcl, rmt;

  ip_prefix_decode (&mp->lcl, &lcl);
  ip_prefix_decode (&mp->rmt, &rmt);

  if (lcl.fp_proto == FIB_PROTOCOL_IP4)
    {
      print (vam->ofp,
	     "appns %u tp %u scope %d %U/%d %d %U/%d %d action: %d tag: %s",
	     clib_net_to_host_u32 (mp->appns_index), mp->transport_proto,
	     mp->scope, format_ip4_address, &lcl.fp_addr.ip4, lcl.fp_len,
	     clib_net_to_host_u16 (mp->lcl_port), format_ip4_address,
	     &rmt.fp_addr.ip4, rmt.fp_len, clib_net_to_host_u16 (mp->rmt_port),
	     clib_net_to_host_u32 (mp->action_index), mp->tag);
    }
  else
    {
      print (vam->ofp,
	     "appns %u tp %u scope %d %U/%d %d %U/%d %d action: %d tag: %s",
	     clib_net_to_host_u32 (mp->appns_index), mp->transport_proto,
	     mp->scope, format_ip6_address, &lcl.fp_addr.ip6, lcl.fp_len,
	     clib_net_to_host_u16 (mp->lcl_port), format_ip6_address,
	     &rmt.fp_addr.ip6, rmt.fp_len, clib_net_to_host_u16 (mp->rmt_port),
	     clib_net_to_host_u32 (mp->action_index), mp->tag);
    }
}

static void
vl_api_app_namespace_add_del_reply_t_handler (
  vl_api_app_namespace_add_del_reply_t *mp)
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
      if (retval == 0)
	errmsg ("app ns index %d\n", ntohl (mp->appns_index));
      vam->result_ready = 1;
    }
}

static void
vl_api_app_namespace_add_del_v2_reply_t_handler (
  vl_api_app_namespace_add_del_v2_reply_t *vat)
{
}

static void
vl_api_app_worker_add_del_reply_t_handler (
  vl_api_app_worker_add_del_reply_t *vat)
{
}

static int
api_app_namespace_add_del_v2 (vat_main_t *vat)
{
  return -1;
}

static int
api_session_enable_disable (vat_main_t *vat)
{
  return -1;
}

static int
api_app_worker_add_del (vat_main_t *vat)
{
  return -1;
}

static int
api_application_tls_key_add (vat_main_t *vat)
{
  return -1;
}

static int
api_app_namespace_add_del (vat_main_t *vam)
{
  vl_api_app_namespace_add_del_t *mp;
  unformat_input_t *i = vam->input;
  u8 *ns_id = 0, secret_set = 0, sw_if_index_set = 0;
  u32 sw_if_index, ip4_fib_id, ip6_fib_id;
  u64 secret;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "id %_%v%_", &ns_id))
	;
      else if (unformat (i, "secret %lu", &secret))
	secret_set = 1;
      else if (unformat (i, "sw_if_index %d", &sw_if_index))
	sw_if_index_set = 1;
      else if (unformat (i, "ip4_fib_id %d", &ip4_fib_id))
	;
      else if (unformat (i, "ip6_fib_id %d", &ip6_fib_id))
	;
      else
	break;
    }
  if (!ns_id || !secret_set || !sw_if_index_set)
    {
      errmsg ("namespace id, secret and sw_if_index must be set");
      return -99;
    }
  if (vec_len (ns_id) > 64)
    {
      errmsg ("namespace id too long");
      return -99;
    }
  M (APP_NAMESPACE_ADD_DEL, mp);

  vl_api_vec_to_api_string (ns_id, &mp->namespace_id);
  mp->secret = clib_host_to_net_u64 (secret);
  mp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
  mp->ip4_fib_id = clib_host_to_net_u32 (ip4_fib_id);
  mp->ip6_fib_id = clib_host_to_net_u32 (ip6_fib_id);
  vec_free (ns_id);
  S (mp);
  W (ret);
  return ret;
}

static int
api_application_tls_cert_add (vat_main_t *vat)
{
  return -1;
}

#include <vnet/session/session.api_test.c>

VAT_REGISTER_FEATURE_FUNCTION (vat_session_plugin_register);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
