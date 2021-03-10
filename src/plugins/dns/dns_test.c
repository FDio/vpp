/*
 * dns.c - skeleton vpp-api-test plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <stdbool.h>
#include <vnet/ip/ip.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <dns/dns.api_enum.h>
#include <dns/dns.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} dns_test_main_t;

dns_test_main_t dns_test_main;

#define __plugin_msg_base dns_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

static void vl_api_dns_resolve_name_reply_t_handler
  (vl_api_dns_resolve_name_reply_t * mp)
{
  vat_main_t *vam = dns_test_main.vat_main;
  i32 retval = (i32) clib_net_to_host_u32 (mp->retval);
  if (retval == 0)
    {
      if (mp->ip4_set)
	clib_warning ("resolved: %U", format_ip4_address, mp->ip4_address);
      if (mp->ip6_set)
	clib_warning ("resolved: %U", format_ip6_address, mp->ip6_address);
    }
  if (vam->async_mode)
    vam->async_errors += (retval < 0);
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

static void
vl_api_dns_resolve_name6_reply_t_handler (vl_api_dns_resolve_name6_reply_t *mp)
{
  vat_main_t *vam = dns_test_main.vat_main;
  i32 retval = (i32) clib_net_to_host_u32 (mp->retval);
  if (retval == 0)
    {
      if (mp->ip6_set)
	clib_warning ("resolved: %U", format_ip6_address, mp->ip6_address);
    }
  if (vam->async_mode)
    vam->async_errors += (retval < 0);
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

static void vl_api_dns_resolve_ip_reply_t_handler
  (vl_api_dns_resolve_ip_reply_t * mp)
{
  vat_main_t *vam = dns_test_main.vat_main;
  i32 retval = (i32) clib_net_to_host_u32 (mp->retval);
  if (retval == 0)
    clib_warning ("resolved: %s", mp->name);
  if (vam->async_mode)
    vam->async_errors += (retval < 0);
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

static int
api_dns_enable_disable (vat_main_t * vam)
{
  vl_api_dns_enable_disable_t *mp;
  unformat_input_t *i = vam->input;
  int enable = 1;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "disable"))
	enable = 0;
      else if (unformat (i, "enable"))
	enable = 1;
      else
	break;
    }

  /* Construct the API message */
  M (DNS_ENABLE_DISABLE, mp);
  mp->enable = enable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_dns_resolve_name (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_dns_resolve_name_t *mp;
  u8 *name = 0;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &name))
	;
      else
	break;
    }

  if (name == 0)
    {
      errmsg ("missing name to resolve");
      return -99;
    }

  if (vec_len (name) > 127)
    {
      errmsg ("name too long");
      return -99;
    }

  /* Construct the API message */
  M (DNS_RESOLVE_NAME, mp);
  memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

static int
api_dns_resolve_name6 (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_dns_resolve_name6_t *mp;
  u8 *name = 0;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &name))
	;
      else
	break;
    }

  if (name == 0)
    {
      errmsg ("missing name to resolve");
      return -99;
    }

  if (vec_len (name) > 127)
    {
      errmsg ("name too long");
      return -99;
    }

  /* Construct the API message */
  M (DNS_RESOLVE_NAME6, mp);
  memcpy (mp->name, name, vec_len (name));
  vec_free (name);

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

static int
api_dns_resolve_ip (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_dns_resolve_ip_t *mp;
  int is_ip6 = -1;
  ip4_address_t addr4;
  ip6_address_t addr6;
  int ret;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip6_address, &addr6))
	is_ip6 = 1;
      else if (unformat (line_input, "%U", unformat_ip4_address, &addr4))
	is_ip6 = 0;
      else
	break;
    }

  if (is_ip6 == -1)
    {
      errmsg ("missing address");
      return -99;
    }

  /* Construct the API message */
  M (DNS_RESOLVE_IP, mp);
  mp->is_ip6 = is_ip6;
  if (is_ip6)
    memcpy (mp->address, &addr6, sizeof (addr6));
  else
    memcpy (mp->address, &addr4, sizeof (addr4));

  /* send it... */
  S (mp);
  /* Wait for the reply */
  W (ret);
  return ret;
}

static int
api_dns_name_server_add_del (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_dns_name_server_add_del_t *mp;
  u8 is_add = 1;
  ip6_address_t ip6_server;
  ip4_address_t ip4_server;
  int ip6_set = 0;
  int ip4_set = 0;
  int ret = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_ip6_address, &ip6_server))
	ip6_set = 1;
      else if (unformat (i, "%U", unformat_ip4_address, &ip4_server))
	ip4_set = 1;
      else if (unformat (i, "del"))
	is_add = 0;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (ip4_set && ip6_set)
    {
      errmsg ("Only one server address allowed per message");
      return -99;
    }
  if ((ip4_set + ip6_set) == 0)
    {
      errmsg ("Server address required");
      return -99;
    }

  /* Construct the API message */
  M (DNS_NAME_SERVER_ADD_DEL, mp);

  if (ip6_set)
    {
      memcpy (mp->server_address, &ip6_server, sizeof (ip6_address_t));
      mp->is_ip6 = 1;
    }
  else
    {
      memcpy (mp->server_address, &ip4_server, sizeof (ip4_address_t));
      mp->is_ip6 = 0;
    }

  mp->is_add = is_add;

  /* send it... */
  S (mp);

  /* Wait for a reply, return good/bad news  */
  W (ret);
  return ret;
}

#include <dns/dns.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
