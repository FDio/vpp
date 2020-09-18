/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/ip/ip_format_fns.h>
#include <vnet/ethernet/ethernet_format_fns.h>
#include <lisp/lisp-cp/lisp_types.h>

/* define message IDs */
#include <lisp/lisp-cp/lisp.api_enum.h>
#include <lisp/lisp-cp/lisp.api_types.h>
#include <vpp/api/vpe.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
  u32 ping_id;
} lisp_test_main_t;

lisp_test_main_t lisp_test_main;

#define __plugin_msg_base lisp_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Macro to finish up custom dump fns */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define FINISH                                  \
    vec_add1 (s, 0);                            \
    vl_print (handle, (char *)s);               \
    vec_free (s);                               \
    return handle;

typedef struct
{
  u32 spi;
  u8 si;
} __attribute__ ((__packed__)) lisp_nsh_api_t;

#define LISP_PING(_lm, mp_ping)                                         \
  if (!(_lm)->ping_id)                                                  \
    (_lm)->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC)); \
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));          \
  mp_ping->_vl_msg_id = htons ((_lm)->ping_id);                         \
  mp_ping->client_index = vam->my_client_index;                         \
  fformat (vam->ofp, "Sending ping id=%d\n", (_lm)->ping_id);           \
  vam->result_ready = 0;                                                \

uword
unformat_nsh_address (unformat_input_t * input, va_list * args)
{
  lisp_nsh_api_t *nsh = va_arg (*args, lisp_nsh_api_t *);
  return unformat (input, "SPI:%d SI:%d", &nsh->spi, &nsh->si);
}

static u8 *
format_nsh_address_vat (u8 * s, va_list * args)
{
  nsh_t *a = va_arg (*args, nsh_t *);
  return format (s, "SPI:%d SI:%d", clib_net_to_host_u32 (a->spi), a->si);
}

static u8 *
format_lisp_flat_eid (u8 * s, va_list * args)
{
  vl_api_eid_t *eid = va_arg (*args, vl_api_eid_t *);

  switch (eid->type)
    {
    case EID_TYPE_API_PREFIX:
      if (eid->address.prefix.address.af)
	return format (s, "%U/%d", format_ip6_address,
		       eid->address.prefix.address.un.ip6,
		       eid->address.prefix.len);
      return format (s, "%U/%d", format_ip4_address,
		     eid->address.prefix.address.un.ip4,
		     eid->address.prefix.len);
    case EID_TYPE_API_MAC:
      return format (s, "%U", format_ethernet_address, eid->address.mac);
    case EID_TYPE_API_NSH:
      return format (s, "%U", format_nsh_address_vat, eid->address.nsh);
    }
  return 0;
}

static u8 *
format_lisp_eid_vat (u8 * s, va_list * args)
{
  vl_api_eid_t *deid = va_arg (*args, vl_api_eid_t *);
  vl_api_eid_t *seid = va_arg (*args, vl_api_eid_t *);
  u8 is_src_dst = (u8) va_arg (*args, int);

  if (is_src_dst)
    s = format (s, "%U|", format_lisp_flat_eid, seid);

  s = format (s, "%U", format_lisp_flat_eid, deid);

  return s;
}



/* *INDENT-OFF* */
/** Used for parsing LISP eids */
typedef struct lisp_eid_vat_t_
{
  union {
    ip46_address_t ip;
    mac_address_t mac;
    lisp_nsh_api_t nsh;
  } addr;
  /**< prefix length if IP */
  u32 len;
  /**< type of eid */
  u8 type;
} __clib_packed lisp_eid_vat_t;
/* *INDENT-ON* */

static uword
unformat_lisp_eid_vat (unformat_input_t * input, va_list * args)
{
  lisp_eid_vat_t *a = va_arg (*args, lisp_eid_vat_t *);

  clib_memset (a, 0, sizeof (a[0]));

  if (unformat (input, "%U/%d", unformat_ip46_address, a->addr.ip, &a->len))
    {
      a->type = 0;		/* ip prefix type */
    }
  else if (unformat (input, "%U", unformat_ethernet_address, &a->addr.mac))
    {
      a->type = 1;		/* mac type */
    }
  else if (unformat (input, "%U", unformat_nsh_address, a->addr.nsh))
    {
      a->type = 2;		/* NSH type */
      a->addr.nsh.spi = clib_host_to_net_u32 (a->addr.nsh.spi);
    }
  else
    {
      return 0;
    }

  if (a->type == 0)
    {
      if (ip46_address_is_ip4 (&a->addr.ip))
	return a->len > 32 ? 1 : 0;
      else
	return a->len > 128 ? 1 : 0;
    }

  return 1;
}

static void
lisp_eid_put_vat (vl_api_eid_t * eid, const lisp_eid_vat_t * vat_eid)
{
  eid->type = vat_eid->type;
  switch (eid->type)
    {
    case EID_TYPE_API_PREFIX:
      if (ip46_address_is_ip4 (&vat_eid->addr.ip))
	{
	  clib_memcpy (&eid->address.prefix.address.un.ip4,
		       &vat_eid->addr.ip.ip4, 4);
	  eid->address.prefix.address.af = ADDRESS_IP4;
	  eid->address.prefix.len = vat_eid->len;
	}
      else
	{
	  clib_memcpy (&eid->address.prefix.address.un.ip6,
		       &vat_eid->addr.ip.ip6, 16);
	  eid->address.prefix.address.af = ADDRESS_IP6;
	  eid->address.prefix.len = vat_eid->len;
	}
      return;
    case EID_TYPE_API_MAC:
      clib_memcpy (&eid->address.mac, &vat_eid->addr.mac,
		   sizeof (eid->address.mac));
      return;
    case EID_TYPE_API_NSH:
      clib_memcpy (&eid->address.nsh, &vat_eid->addr.nsh,
		   sizeof (eid->address.nsh));
      return;
    default:
      ASSERT (0);
      return;
    }
}

static int
api_lisp_add_del_locator_set (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_add_del_locator_set_t *mp;
  u8 is_add = 1;
  u8 *locator_set_name = NULL;
  u8 locator_set_name_set = 0;
  vl_api_local_locator_t locator, *locators = 0;
  u32 sw_if_index, priority, weight;
  u32 data_len = 0;

  int ret;
  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "locator-set %s", &locator_set_name))
	{
	  locator_set_name_set = 1;
	}
      else if (unformat (input, "sw_if_index %u p %u w %u",
			 &sw_if_index, &priority, &weight))
	{
	  locator.sw_if_index = htonl (sw_if_index);
	  locator.priority = priority;
	  locator.weight = weight;
	  vec_add1 (locators, locator);
	}
      else
	if (unformat
	    (input, "iface %U p %u w %u", unformat_sw_if_index, vam,
	     &sw_if_index, &priority, &weight))
	{
	  locator.sw_if_index = htonl (sw_if_index);
	  locator.priority = priority;
	  locator.weight = weight;
	  vec_add1 (locators, locator);
	}
      else
	break;
    }

  if (locator_set_name_set == 0)
    {
      errmsg ("missing locator-set name");
      vec_free (locators);
      return -99;
    }

  if (vec_len (locator_set_name) > 64)
    {
      errmsg ("locator-set name too long");
      vec_free (locator_set_name);
      vec_free (locators);
      return -99;
    }
  vec_add1 (locator_set_name, 0);

  data_len = sizeof (vl_api_local_locator_t) * vec_len (locators);

  /* Construct the API message */
  M2 (LISP_ADD_DEL_LOCATOR_SET, mp, data_len);

  mp->is_add = is_add;
  clib_memcpy (mp->locator_set_name, locator_set_name,
	       vec_len (locator_set_name));
  vec_free (locator_set_name);

  mp->locator_num = clib_host_to_net_u32 (vec_len (locators));
  if (locators)
    clib_memcpy (mp->locators, locators, data_len);
  vec_free (locators);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_add_del_locator (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_add_del_locator_t *mp;
  u32 tmp_if_index = ~0;
  u32 sw_if_index = ~0;
  u8 sw_if_index_set = 0;
  u8 sw_if_index_if_name_set = 0;
  u32 priority = ~0;
  u8 priority_set = 0;
  u32 weight = ~0;
  u8 weight_set = 0;
  u8 is_add = 1;
  u8 *locator_set_name = NULL;
  u8 locator_set_name_set = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "locator-set %s", &locator_set_name))
	{
	  locator_set_name_set = 1;
	}
      else if (unformat (input, "iface %U", unformat_sw_if_index, vam,
			 &tmp_if_index))
	{
	  sw_if_index_if_name_set = 1;
	  sw_if_index = tmp_if_index;
	}
      else if (unformat (input, "sw_if_index %d", &tmp_if_index))
	{
	  sw_if_index_set = 1;
	  sw_if_index = tmp_if_index;
	}
      else if (unformat (input, "p %d", &priority))
	{
	  priority_set = 1;
	}
      else if (unformat (input, "w %d", &weight))
	{
	  weight_set = 1;
	}
      else
	break;
    }

  if (locator_set_name_set == 0)
    {
      errmsg ("missing locator-set name");
      return -99;
    }

  if (sw_if_index_set == 0 && sw_if_index_if_name_set == 0)
    {
      errmsg ("missing sw_if_index");
      vec_free (locator_set_name);
      return -99;
    }

  if (sw_if_index_set != 0 && sw_if_index_if_name_set != 0)
    {
      errmsg ("cannot use both params interface name and sw_if_index");
      vec_free (locator_set_name);
      return -99;
    }

  if (priority_set == 0)
    {
      errmsg ("missing locator-set priority");
      vec_free (locator_set_name);
      return -99;
    }

  if (weight_set == 0)
    {
      errmsg ("missing locator-set weight");
      vec_free (locator_set_name);
      return -99;
    }

  if (vec_len (locator_set_name) > 64)
    {
      errmsg ("locator-set name too long");
      vec_free (locator_set_name);
      return -99;
    }
  vec_add1 (locator_set_name, 0);

  /* Construct the API message */
  M (LISP_ADD_DEL_LOCATOR, mp);

  mp->is_add = is_add;
  mp->sw_if_index = ntohl (sw_if_index);
  mp->priority = priority;
  mp->weight = weight;
  clib_memcpy (mp->locator_set_name, locator_set_name,
	       vec_len (locator_set_name));
  vec_free (locator_set_name);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_add_del_local_eid (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_add_del_local_eid_t *mp;
  u8 is_add = 1;
  u8 eid_set = 0;
  lisp_eid_vat_t _eid, *eid = &_eid;
  u8 *locator_set_name = 0;
  u8 locator_set_name_set = 0;
  u32 vni = 0;
  u16 key_id = 0;
  u8 *key = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "vni %d", &vni))
	{
	  ;
	}
      else if (unformat (input, "eid %U", unformat_lisp_eid_vat, eid))
	{
	  eid_set = 1;
	}
      else if (unformat (input, "locator-set %s", &locator_set_name))
	{
	  locator_set_name_set = 1;
	}
      else if (unformat (input, "key-id %U", unformat_hmac_key_id, &key_id))
	;
      else if (unformat (input, "secret-key %_%v%_", &key))
	;
      else
	break;
    }

  if (locator_set_name_set == 0)
    {
      errmsg ("missing locator-set name");
      return -99;
    }

  if (0 == eid_set)
    {
      errmsg ("EID address not set!");
      vec_free (locator_set_name);
      return -99;
    }

  if (key && (0 == key_id))
    {
      errmsg ("invalid key_id!");
      return -99;
    }

  if (vec_len (key) > 64)
    {
      errmsg ("key too long");
      vec_free (key);
      return -99;
    }

  if (vec_len (locator_set_name) > 64)
    {
      errmsg ("locator-set name too long");
      vec_free (locator_set_name);
      return -99;
    }
  vec_add1 (locator_set_name, 0);

  /* Construct the API message */
  M (LISP_ADD_DEL_LOCAL_EID, mp);

  mp->is_add = is_add;
  lisp_eid_put_vat (&mp->eid, eid);
  mp->vni = clib_host_to_net_u32 (vni);
  mp->key.id = key_id;
  clib_memcpy (mp->locator_set_name, locator_set_name,
	       vec_len (locator_set_name));
  clib_memcpy (mp->key.key, key, vec_len (key));

  vec_free (locator_set_name);
  vec_free (key);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_add_del_map_server (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_add_del_map_server_t *mp;
  u8 is_add = 1;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  ip4_address_t ipv4;
  ip6_address_t ipv6;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "%U", unformat_ip4_address, &ipv4))
	{
	  ipv4_set = 1;
	}
      else if (unformat (input, "%U", unformat_ip6_address, &ipv6))
	{
	  ipv6_set = 1;
	}
      else
	break;
    }

  if (ipv4_set && ipv6_set)
    {
      errmsg ("both eid v4 and v6 addresses set");
      return -99;
    }

  if (!ipv4_set && !ipv6_set)
    {
      errmsg ("eid addresses not set");
      return -99;
    }

  /* Construct the API message */
  M (LISP_ADD_DEL_MAP_SERVER, mp);

  mp->is_add = is_add;
  if (ipv6_set)
    {
      mp->ip_address.af = 1;
      clib_memcpy (mp->ip_address.un.ip6, &ipv6, sizeof (ipv6));
    }
  else
    {
      mp->ip_address.af = 0;
      clib_memcpy (mp->ip_address.un.ip4, &ipv4, sizeof (ipv4));
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_add_del_map_resolver (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_add_del_map_resolver_t *mp;
  u8 is_add = 1;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  ip4_address_t ipv4;
  ip6_address_t ipv6;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "%U", unformat_ip4_address, &ipv4))
	{
	  ipv4_set = 1;
	}
      else if (unformat (input, "%U", unformat_ip6_address, &ipv6))
	{
	  ipv6_set = 1;
	}
      else
	break;
    }

  if (ipv4_set && ipv6_set)
    {
      errmsg ("both eid v4 and v6 addresses set");
      return -99;
    }

  if (!ipv4_set && !ipv6_set)
    {
      errmsg ("eid addresses not set");
      return -99;
    }

  /* Construct the API message */
  M (LISP_ADD_DEL_MAP_RESOLVER, mp);

  mp->is_add = is_add;
  if (ipv6_set)
    {
      mp->ip_address.af = 1;
      clib_memcpy (mp->ip_address.un.ip6, &ipv6, sizeof (ipv6));
    }
  else
    {
      mp->ip_address.af = 0;
      clib_memcpy (mp->ip_address.un.ip6, &ipv4, sizeof (ipv4));
    }

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_enable_disable_t *mp;
  u8 is_set = 0;
  u8 is_enable = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	{
	  is_set = 1;
	  is_enable = 1;
	}
      else if (unformat (input, "disable"))
	{
	  is_set = 1;
	}
      else
	break;
    }

  if (!is_set)
    {
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (LISP_ENABLE_DISABLE, mp);

  mp->is_enable = is_enable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/**
 * Enable/disable LISP proxy ITR.
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_lisp_pitr_set_locator_set (vat_main_t * vam)
{
  u8 ls_name_set = 0;
  unformat_input_t *input = vam->input;
  vl_api_lisp_pitr_set_locator_set_t *mp;
  u8 is_add = 1;
  u8 *ls_name = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "locator-set %s", &ls_name))
	ls_name_set = 1;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!ls_name_set)
    {
      errmsg ("locator-set name not set!");
      return -99;
    }

  M (LISP_PITR_SET_LOCATOR_SET, mp);

  mp->is_add = is_add;
  clib_memcpy (mp->ls_name, ls_name, vec_len (ls_name));
  vec_free (ls_name);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_lisp_use_petr (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_use_petr_t *mp;
  u8 is_add = 0;
  ip_address_t ip;
  int ret;

  clib_memset (&ip, 0, sizeof (ip));

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	is_add = 0;
      else
	if (unformat (input, "%U", unformat_ip4_address, &ip_addr_v4 (&ip)))
	{
	  is_add = 1;
	  ip_addr_version (&ip) = AF_IP4;
	}
      else
	if (unformat (input, "%U", unformat_ip6_address, &ip_addr_v6 (&ip)))
	{
	  is_add = 1;
	  ip_addr_version (&ip) = AF_IP6;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  M (LISP_USE_PETR, mp);

  mp->is_add = is_add;
  if (is_add)
    {
      mp->ip_address.af = ip_addr_version (&ip) == AF_IP4 ? 0 : 1;
      if (mp->ip_address.af)
	clib_memcpy (mp->ip_address.un.ip6, &ip, 16);
      else
	clib_memcpy (mp->ip_address.un.ip4, &ip, 4);
    }

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static void
  vl_api_show_lisp_use_petr_reply_t_handler
  (vl_api_show_lisp_use_petr_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "%s\n", mp->is_petr_enable ? "enabled" : "disabled");
      if (mp->is_petr_enable)
	{
	  print (vam->ofp, "Proxy-ETR address; %U",
		 mp->ip_address.af ? format_ip6_address : format_ip4_address,
		 mp->ip_address.un);
	}
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static int
api_show_lisp_use_petr (vat_main_t * vam)
{
  vl_api_show_lisp_use_petr_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "Proxy-ETR status:");
    }

  M (SHOW_LISP_USE_PETR, mp);
  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
  vl_api_show_lisp_rloc_probe_state_reply_t_handler
  (vl_api_show_lisp_rloc_probe_state_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  print (vam->ofp, "%s", mp->is_enabled ? "enabled" : "disabled");
end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static int
api_show_lisp_map_register_state (vat_main_t * vam)
{
  vl_api_show_lisp_map_register_state_t *mp;
  int ret;

  M (SHOW_LISP_MAP_REGISTER_STATE, mp);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_show_lisp_rloc_probe_state (vat_main_t * vam)
{
  vl_api_show_lisp_rloc_probe_state_t *mp;
  int ret;

  M (SHOW_LISP_RLOC_PROBE_STATE, mp);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_lisp_rloc_probe_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_rloc_probe_enable_disable_t *mp;
  u8 is_set = 0;
  u8 is_enable = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	{
	  is_set = 1;
	  is_enable = 1;
	}
      else if (unformat (input, "disable"))
	is_set = 1;
      else
	break;
    }

  if (!is_set)
    {
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (LISP_RLOC_PROBE_ENABLE_DISABLE, mp);

  mp->is_enable = is_enable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_map_register_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_map_register_enable_disable_t *mp;
  u8 is_set = 0;
  u8 is_enable = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	{
	  is_set = 1;
	  is_enable = 1;
	}
      else if (unformat (input, "disable"))
	is_set = 1;
      else
	break;
    }

  if (!is_set)
    {
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (LISP_MAP_REGISTER_ENABLE_DISABLE, mp);

  mp->is_enable = is_enable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static void
  vl_api_show_lisp_map_request_mode_reply_t_handler
  (vl_api_show_lisp_map_request_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "map_request_mode: %s",
	     mp->is_src_dst ? "src-dst" : "dst-only");
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_show_lisp_map_register_state_reply_t_handler
  (vl_api_show_lisp_map_register_state_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  int retval = clib_net_to_host_u32 (mp->retval);

  print (vam->ofp, "%s", mp->is_enabled ? "enabled" : "disabled");

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
vl_api_lisp_locator_details_t_handler (vl_api_lisp_locator_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *s = 0;

  if (mp->local)
    {
      s = format (s, "%=16d%=16d%=16d",
		  ntohl (mp->sw_if_index), mp->priority, mp->weight);
    }
  else
    {
      s = format (s, "%=16U%=16d%=16d",
		  format_ip46_address,
		  mp->ip_address, mp->priority, mp->weight);
    }

  print (vam->ofp, "%v", s);
  vec_free (s);
}

static void
vl_api_lisp_locator_set_details_t_handler (vl_api_lisp_locator_set_details_t *
					  mp)
{
  vat_main_t *vam = &vat_main;
  u8 *ls_name = 0;

  ls_name = format (0, "%s", mp->ls_name);

  print (vam->ofp, "%=10d%=15v", clib_net_to_host_u32 (mp->ls_index),
	 ls_name);
  vec_free (ls_name);
}

static void vl_api_lisp_add_del_locator_set_reply_t_handler
  (vl_api_lisp_add_del_locator_set_reply_t * mp)
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


static void
vl_api_lisp_eid_table_details_t_handler (vl_api_lisp_eid_table_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *s = 0, *eid = 0;

  if (~0 == mp->locator_set_index)
    s = format (0, "action: %d", mp->action);
  else
    s = format (0, "%d", clib_net_to_host_u32 (mp->locator_set_index));

  eid = format (0, "%U", format_lisp_eid_vat,
		&mp->deid, &mp->seid, mp->is_src_dst);
  vec_add1 (eid, 0);

  print (vam->ofp, "[%d] %-35s%-20s%-30s%-20d%-20d%-10d%-20s",
	 clib_net_to_host_u32 (mp->vni),
	 eid,
	 mp->is_local ? "local" : "remote",
	 s, clib_net_to_host_u32 (mp->ttl), mp->authoritative,
	 clib_net_to_host_u16 (mp->key.id), mp->key.key);

  vec_free (s);
  vec_free (eid);
}

static void
  vl_api_lisp_eid_table_map_details_t_handler
  (vl_api_lisp_eid_table_map_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  u8 *line = format (0, "%=10d%=10d",
		     clib_net_to_host_u32 (mp->vni),
		     clib_net_to_host_u32 (mp->dp_table));
  print (vam->ofp, "%v", line);
  vec_free (line);
}

static void
  vl_api_lisp_eid_table_vni_details_t_handler
  (vl_api_lisp_eid_table_vni_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  u8 *line = format (0, "%d", clib_net_to_host_u32 (mp->vni));
  print (vam->ofp, "%v", line);
  vec_free (line);
}

static void
  vl_api_lisp_adjacencies_get_reply_t_handler
  (vl_api_lisp_adjacencies_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_lisp_adjacency_t *a;

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    {
      a = &mp->adjacencies[i];
      print (vam->ofp, "%U %40U",
	     format_lisp_flat_eid, a->leid, format_lisp_flat_eid, a->reid);
    }

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
vl_api_lisp_map_server_details_t_handler (vl_api_lisp_map_server_details_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%=20U",
	 mp->ip_address.af ? format_ip6_address : format_ip4_address,
	 mp->ip_address.un);
}

static void
vl_api_lisp_map_resolver_details_t_handler (vl_api_lisp_map_resolver_details_t
					   * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "%=20U",
	 mp->ip_address.af ? format_ip6_address : format_ip4_address,
	 mp->ip_address.un);
}

static void
vl_api_show_lisp_status_reply_t_handler (vl_api_show_lisp_status_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "feature: %s\ngpe: %s",
	     mp->is_lisp_enabled ? "enabled" : "disabled",
	     mp->is_gpe_enabled ? "enabled" : "disabled");
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_lisp_get_map_request_itr_rlocs_reply_t_handler
  (vl_api_lisp_get_map_request_itr_rlocs_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (retval >= 0)
    {
      print (vam->ofp, "%=20s", mp->locator_set_name);
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

static void
vl_api_show_lisp_pitr_reply_t_handler (vl_api_show_lisp_pitr_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);

  if (0 <= retval)
    {
      print (vam->ofp, "%-20s%-16s",
	     mp->is_enabled ? "enabled" : "disabled",
	     mp->is_enabled ? (char *) mp->locator_set_name : "");
    }

  vam->retval = retval;
  vam->result_ready = 1;
}

uword
unformat_hmac_key_id (unformat_input_t * input, va_list * args)
{
  u32 *key_id = va_arg (*args, u32 *);
  u8 *s = 0;

  if (unformat (input, "%s", &s))
    {
      if (!strcmp ((char *) s, "sha1"))
	key_id[0] = HMAC_SHA_1_96;
      else if (!strcmp ((char *) s, "sha256"))
	key_id[0] = HMAC_SHA_256_128;
      else
	{
	  clib_warning ("invalid key_id: '%s'", s);
	  key_id[0] = HMAC_NO_KEY;
	}
    }
  else
    return 0;

  vec_free (s);
  return 1;
}



static int
api_show_lisp_map_request_mode (vat_main_t * vam)
{
  vl_api_show_lisp_map_request_mode_t *mp;
  int ret;

  M (SHOW_LISP_MAP_REQUEST_MODE, mp);

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_lisp_map_request_mode (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_map_request_mode_t *mp;
  u8 mode = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "dst-only"))
	mode = 0;
      else if (unformat (input, "src-dst"))
	mode = 1;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  M (LISP_MAP_REQUEST_MODE, mp);

  mp->is_src_dst = mode == 1;

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

static int
api_show_lisp_pitr (vat_main_t * vam)
{
  vl_api_show_lisp_pitr_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "lisp status:");
    }

  M (SHOW_LISP_PITR, mp);
  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/**
 * Add/delete mapping between vni and vrf
 */
static int
api_lisp_eid_table_add_del_map (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_eid_table_add_del_map_t *mp;
  u8 is_add = 1, vni_set = 0, vrf_set = 0, bd_index_set = 0;
  u32 vni, vrf, bd_index;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "vrf %d", &vrf))
	vrf_set = 1;
      else if (unformat (input, "bd_index %d", &bd_index))
	bd_index_set = 1;
      else if (unformat (input, "vni %d", &vni))
	vni_set = 1;
      else
	break;
    }

  if (!vni_set || (!vrf_set && !bd_index_set))
    {
      errmsg ("missing arguments!");
      return -99;
    }

  if (vrf_set && bd_index_set)
    {
      errmsg ("error: both vrf and bd entered!");
      return -99;
    }

  M (LISP_EID_TABLE_ADD_DEL_MAP, mp);

  mp->is_add = is_add;
  mp->vni = htonl (vni);
  mp->dp_table = vrf_set ? htonl (vrf) : htonl (bd_index);
  mp->is_l2 = bd_index_set;

  /* send */
  S (mp);

  /* wait for reply */
  W (ret);
  return ret;
}

/**
 * Add/del remote mapping to/from LISP control plane
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_lisp_add_del_remote_mapping (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_add_del_remote_mapping_t *mp;
  u32 vni = 0;
  lisp_eid_vat_t _eid, *eid = &_eid;
  lisp_eid_vat_t _seid, *seid = &_seid;
  u8 is_add = 1, del_all = 0, eid_set = 0, seid_set = 0;
  u32 action = ~0, p, w, data_len;
  ip4_address_t rloc4;
  ip6_address_t rloc6;
  vl_api_remote_locator_t *rlocs = 0, rloc, *curr_rloc = 0;
  int ret;

  clib_memset (&rloc, 0, sizeof (rloc));

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del-all"))
	{
	  del_all = 1;
	}
      else if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "add"))
	{
	  is_add = 1;
	}
      else if (unformat (input, "eid %U", unformat_lisp_eid_vat, eid))
	{
	  eid_set = 1;
	}
      else if (unformat (input, "seid %U", unformat_lisp_eid_vat, seid))
	{
	  seid_set = 1;
	}
      else if (unformat (input, "vni %d", &vni))
	{
	  ;
	}
      else if (unformat (input, "p %d w %d", &p, &w))
	{
	  if (!curr_rloc)
	    {
	      errmsg ("No RLOC configured for setting priority/weight!");
	      return -99;
	    }
	  curr_rloc->priority = p;
	  curr_rloc->weight = w;
	}
      else if (unformat (input, "rloc %U", unformat_ip4_address, &rloc4))
	{
	  rloc.ip_address.af = 0;
	  clib_memcpy (&rloc.ip_address.un.ip6, &rloc6, sizeof (rloc6));
	  vec_add1 (rlocs, rloc);
	  curr_rloc = &rlocs[vec_len (rlocs) - 1];
	}
      else if (unformat (input, "rloc %U", unformat_ip6_address, &rloc6))
	{
	  rloc.ip_address.af = 1;
	  clib_memcpy (&rloc.ip_address.un.ip4, &rloc4, sizeof (rloc4));
	  vec_add1 (rlocs, rloc);
	  curr_rloc = &rlocs[vec_len (rlocs) - 1];
	}
      else if (unformat (input, "action %U",
			 unformat_negative_mapping_action, &action))
	{
	  ;
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (0 == eid_set)
    {
      errmsg ("missing params!");
      return -99;
    }

  if (is_add && (~0 == action) && 0 == vec_len (rlocs))
    {
      errmsg ("no action set for negative map-reply!");
      return -99;
    }

  data_len = vec_len (rlocs) * sizeof (vl_api_remote_locator_t);

  M2 (LISP_ADD_DEL_REMOTE_MAPPING, mp, data_len);
  mp->is_add = is_add;
  mp->vni = htonl (vni);
  mp->action = (u8) action;
  mp->is_src_dst = seid_set;
  mp->del_all = del_all;
  lisp_eid_put_vat (&mp->deid, eid);
  lisp_eid_put_vat (&mp->seid, seid);

  mp->rloc_num = clib_host_to_net_u32 (vec_len (rlocs));
  clib_memcpy (mp->rlocs, rlocs, data_len);
  vec_free (rlocs);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/**
 * Add/del LISP adjacency. Saves mapping in LISP control plane and updates
 * forwarding entries in data-plane accordingly.
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_lisp_add_del_adjacency (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_add_del_adjacency_t *mp;
  u32 vni = 0;
  u8 is_add = 1;
  int ret;
  lisp_eid_vat_t leid, reid;

  leid.type = reid.type = (u8) ~ 0;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "add"))
	{
	  is_add = 1;
	}
      else if (unformat (input, "reid %U/%d", unformat_ip46_address,
			 &reid.addr.ip, &reid.len))
	{
	  reid.type = 0;	/* ipv4 */
	}
      else if (unformat (input, "reid %U", unformat_ethernet_address,
			 &reid.addr.mac))
	{
	  reid.type = 1;	/* mac */
	}
      else if (unformat (input, "leid %U/%d", unformat_ip46_address,
			 &leid.addr.ip, &leid.len))
	{
	  leid.type = 0;	/* ipv4 */
	}
      else if (unformat (input, "leid %U", unformat_ethernet_address,
			 &leid.addr.mac))
	{
	  leid.type = 1;	/* mac */
	}
      else if (unformat (input, "vni %d", &vni))
	{
	  ;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if ((u8) ~ 0 == reid.type)
    {
      errmsg ("missing params!");
      return -99;
    }

  if (leid.type != reid.type)
    {
      errmsg ("remote and local EIDs are of different types!");
      return -99;
    }

  M (LISP_ADD_DEL_ADJACENCY, mp);
  mp->is_add = is_add;
  mp->vni = htonl (vni);
  lisp_eid_put_vat (&mp->leid, &leid);
  lisp_eid_put_vat (&mp->reid, &reid);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/**
 * Add/del map request itr rlocs from LISP control plane and updates
 *
 * @param vam vpp API test context
 * @return return code
 */
static int
api_lisp_add_del_map_request_itr_rlocs (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_add_del_map_request_itr_rlocs_t *mp;
  u8 *locator_set_name = 0;
  u8 locator_set_name_set = 0;
  u8 is_add = 1;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (input, "%_%v%_", &locator_set_name))
	{
	  locator_set_name_set = 1;
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (is_add && !locator_set_name_set)
    {
      errmsg ("itr-rloc is not set!");
      return -99;
    }

  if (is_add && vec_len (locator_set_name) > 64)
    {
      errmsg ("itr-rloc locator-set name too long");
      vec_free (locator_set_name);
      return -99;
    }

  M (LISP_ADD_DEL_MAP_REQUEST_ITR_RLOCS, mp);
  mp->is_add = is_add;
  if (is_add)
    {
      clib_memcpy (mp->locator_set_name, locator_set_name,
		   vec_len (locator_set_name));
    }
  else
    {
      clib_memset (mp->locator_set_name, 0, sizeof (mp->locator_set_name));
    }
  vec_free (locator_set_name);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_locator_dump (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_lisp_locator_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u8 is_index_set = 0, is_name_set = 0;
  u8 *ls_name = 0;
  u32 ls_index = ~0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "ls_name %_%v%_", &ls_name))
	{
	  is_name_set = 1;
	}
      else if (unformat (input, "ls_index %d", &ls_index))
	{
	  is_index_set = 1;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!is_index_set && !is_name_set)
    {
      errmsg ("error: expected lisp of index or name!");
      return -99;
    }

  if (is_index_set && is_name_set)
    {
      errmsg ("error: only lisp param expected!");
      return -99;
    }

  if (vec_len (ls_name) > 62)
    {
      errmsg ("error: locator set name too long!");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%=16s%=16s%=16s", "locator", "priority", "weight");
    }

  M (LISP_LOCATOR_DUMP, mp);
  mp->is_index_set = is_index_set;

  if (is_index_set)
    mp->ls_index = clib_host_to_net_u32 (ls_index);
  else
    {
      vec_add1 (ls_name, 0);
      strncpy ((char *) mp->ls_name, (char *) ls_name,
	       sizeof (mp->ls_name) - 1);
    }

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  if (!lisp_test_main.ping_id)
    lisp_test_main.ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC));
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));
  mp_ping->_vl_msg_id = htons (lisp_test_main.ping_id);
  mp_ping->client_index = vam->my_client_index;

  fformat (vam->ofp, "Sending ping id=%d\n", lisp_test_main.ping_id);

  vam->result_ready = 0;
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_locator_set_dump (vat_main_t * vam)
{
  vl_api_lisp_locator_set_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  unformat_input_t *input = vam->input;
  u8 filter = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "local"))
	{
	  filter = 1;
	}
      else if (unformat (input, "remote"))
	{
	  filter = 2;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%=10s%=15s", "ls_index", "ls_name");
    }

  M (LISP_LOCATOR_SET_DUMP, mp);

  mp->filter = filter;

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  LISP_PING (&lisp_test_main, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_eid_table_map_dump (vat_main_t * vam)
{
  u8 is_l2 = 0;
  u8 mode_set = 0;
  unformat_input_t *input = vam->input;
  vl_api_lisp_eid_table_map_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "l2"))
	{
	  is_l2 = 1;
	  mode_set = 1;
	}
      else if (unformat (input, "l3"))
	{
	  is_l2 = 0;
	  mode_set = 1;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!mode_set)
    {
      errmsg ("expected lisp of 'l2' or 'l3' parameter!");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%=10s%=10s", "VNI", is_l2 ? "BD" : "VRF");
    }

  M (LISP_EID_TABLE_MAP_DUMP, mp);
  mp->is_l2 = is_l2;

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  LISP_PING (&lisp_test_main, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_eid_table_vni_dump (vat_main_t * vam)
{
  vl_api_lisp_eid_table_vni_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "VNI");
    }

  M (LISP_EID_TABLE_VNI_DUMP, mp);

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  LISP_PING (&lisp_test_main, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_eid_table_dump (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_lisp_eid_table_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  u8 filter = 0;
  int ret;
  u32 vni, t = 0;
  lisp_eid_vat_t eid;
  u8 eid_set = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (i, "eid %U/%d", unformat_ip46_address, &eid.addr.ip, &eid.len))
	{
	  eid_set = 1;
	  eid.type = 0;
	}
      else
	if (unformat (i, "eid %U", unformat_ethernet_address, &eid.addr.mac))
	{
	  eid_set = 1;
	  eid.type = 1;
	}
      else if (unformat (i, "eid %U", unformat_nsh_address, &eid.addr.nsh))
	{
	  eid_set = 1;
	  eid.type = 2;
	}
      else if (unformat (i, "vni %d", &t))
	{
	  vni = t;
	}
      else if (unformat (i, "local"))
	{
	  filter = 1;
	}
      else if (unformat (i, "remote"))
	{
	  filter = 2;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%-35s%-20s%-30s%-20s%-20s%-10s%-20s", "EID",
	     "type", "ls_index", "ttl", "authoritative", "key_id", "key");
    }

  M (LISP_EID_TABLE_DUMP, mp);

  mp->filter = filter;
  if (eid_set)
    {
      mp->eid_set = 1;
      mp->vni = htonl (vni);
      lisp_eid_put_vat (&mp->eid, &eid);
    }

  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  LISP_PING (&lisp_test_main, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}


static int
api_lisp_adjacencies_get (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_lisp_adjacencies_get_t *mp;
  u8 vni_set = 0;
  u32 vni = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "vni %d", &vni))
	{
	  vni_set = 1;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!vni_set)
    {
      errmsg ("vni not set!");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "%s %40s", "leid", "reid");
    }

  M (LISP_ADJACENCIES_GET, mp);
  mp->vni = clib_host_to_net_u32 (vni);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_map_server_dump (vat_main_t * vam)
{
  vl_api_lisp_map_server_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "Map server");
    }

  M (LISP_MAP_SERVER_DUMP, mp);
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  LISP_PING (&lisp_test_main, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_map_resolver_dump (vat_main_t * vam)
{
  vl_api_lisp_map_resolver_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "Map resolver");
    }

  M (LISP_MAP_RESOLVER_DUMP, mp);
  /* send it... */
  S (mp);

  /* Use a control ping for synchronization */
  LISP_PING (&lisp_test_main, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_show_lisp_status (vat_main_t * vam)
{
  vl_api_show_lisp_status_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%-20s%-16s", "LISP status", "locator-set");
    }

  M (SHOW_LISP_STATUS, mp);
  /* send it... */
  S (mp);
  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_lisp_get_map_request_itr_rlocs (vat_main_t * vam)
{
  vl_api_lisp_get_map_request_itr_rlocs_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "%=20s", "itr-rlocs:");
    }

  M (LISP_GET_MAP_REQUEST_ITR_RLOCS, mp);
  /* send it... */
  S (mp);
  /* Wait for a reply... */
  W (ret);
  return ret;
}

/* _(lisp_add_del_locator_set, "locator-set <locator_name> [iface <intf> |" */
/*                             " sw_if_index <sw_if_index> p <priority> "  */
/*                             "w <weight>] [del]")                        */
/* _(lisp_add_del_locator, "locator-set <locator_name> "                    */
/*                         "iface <intf> | sw_if_index <sw_if_index> "     */
/*                         "p <priority> w <weight> [del]")                */
/* _(lisp_add_del_local_eid,"vni <vni> eid "                                */
/*                          "<ipv4|ipv6>/<prefix> | <L2 address> "         */
/*                          "locator-set <locator_name> [del]"             */
/*                          "[key-id sha1|sha256 secret-key <secret-key>]")\ */
/* _(lisp_add_del_map_resolver, "<ip4|6-addr> [del]")                       */
/* _(lisp_add_del_map_server, "<ip4|6-addr> [del]")                         */
/* _(lisp_enable_disable, "enable|disable")                                 */
/* _(lisp_map_register_enable_disable, "enable|disable")                    */
/* _(lisp_map_register_fallback_threshold, "<value>")                       */
/* _(lisp_rloc_probe_enable_disable, "enable|disable")                      */
/* _(lisp_add_del_remote_mapping, "add|del vni <vni> eid <dest-eid> "       */
/*                                "[seid <seid>] "                         */
/*                                "rloc <locator> p <prio> "               */
/*                                "w <weight> [rloc <loc> ... ] "          */
/*                                "action <action> [del-all]")             */
/* _(lisp_add_del_adjacency, "add|del vni <vni> reid <remote-eid> leid "    */
/*                           "<local-eid>")                                */
/* _(lisp_pitr_set_locator_set, "locator-set <loc-set-name> | del")         */
/* _(lisp_use_petr, "ip-address> | disable")                                */
/* _(lisp_map_request_mode, "src-dst|dst-only")                             */
/* _(lisp_add_del_map_request_itr_rlocs, "<loc-set-name> [del]")            */
/* _(lisp_eid_table_add_del_map, "[del] vni <vni> vrf <vrf>")               */
/* _(lisp_locator_set_dump, "[local | remote]")                             */
/* _(lisp_locator_dump, "ls_index <index> | ls_name <name>")                */
/* _(lisp_eid_table_dump, "[eid <ipv4|ipv6>/<prefix> | <mac>] [vni] "       */
/*                        "[local] | [remote]")                            */
/* _(lisp_add_del_ndp_entry, "[del] mac <mac> bd <bd> ip6 <ip6>")           */
/* _(lisp_ndp_bd_get, "")                                                   */
/* _(lisp_ndp_entries_get, "bd <bridge-domain>")                            */
/* _(lisp_add_del_l2_arp_entry, "[del] mac <mac> bd <bd> ip <ip4>")        */
/* _(lisp_l2_arp_bd_get, "")                                                */
/* _(lisp_l2_arp_entries_get, "bd <bridge-domain>")                         */
/* _(lisp_stats_enable_disable, "enable|disable")                           */
/* _(show_lisp_stats_enable_disable, "")                                    */
/* _(lisp_eid_table_vni_dump, "")                                           */
/* _(lisp_eid_table_map_dump, "l2|l3")                                      */
/* _(lisp_map_resolver_dump, "")                                            */
/* _(lisp_map_server_dump, "")                                              */
/* _(lisp_adjacencies_get, "vni <vni>")                                     */
/* _(lisp_nsh_set_locator_set, "[del] ls <locator-set-name>")               */
/* _(show_lisp_rloc_probe_state, "")                                        */
/* _(show_lisp_map_register_state, "")                                      */
/* _(show_lisp_status, "")                                                  */
/* _(lisp_stats_dump, "")                                                   */
/* _(lisp_stats_flush, "")                                                  */
/* _(lisp_get_map_request_itr_rlocs, "")                                    */
/* _(lisp_map_register_set_ttl, "<ttl>")                                    */
/* _(lisp_set_transport_protocol, "udp|api")                                */
/* _(lisp_get_transport_protocol, "")                                       */
/* _(lisp_enable_disable_xtr_mode, "enable|disable")                        */
/* _(lisp_show_xtr_mode, "")                                                */
/* _(lisp_enable_disable_pitr_mode, "enable|disable")                       */
/* _(lisp_show_pitr_mode, "")                                               */
/* _(lisp_enable_disable_petr_mode, "enable|disable")                       */
/* _(lisp_show_petr_mode, "")                                               */
/* _(show_lisp_nsh_mapping, "")                                             */
/* _(show_lisp_pitr, "")                                                    */
/* _(show_lisp_use_petr, "")                                                */
/* _(show_lisp_map_request_mode, "")                                        */
/* _(show_lisp_map_register_ttl, "")                                        */
/* _(show_lisp_map_register_fallback_threshold, "")                         */
/* _(lisp_add_del_locator_set, "locator-set <locator_name> [iface <intf> |"\ */
/*                             " sw_if_index <sw_if_index> p <priority> "  */
/*                             "w <weight>] [del]")                        */
/* _(lisp_add_del_locator, "locator-set <locator_name> "                   */
/*                         "iface <intf> | sw_if_index <sw_if_index> "     */
/*                         "p <priority> w <weight> [del]")                */
/* _(lisp_add_del_local_eid,"vni <vni> eid "                               */
/*                          "<ipv4|ipv6>/<prefix> | <L2 address> "         */
/*                          "locator-set <locator_name> [del]"             */
/*                          "[key-id sha1|sha256 secret-key <secret-key>]") */
/* _(lisp_add_del_map_resolver, "<ip4|6-addr> [del]")                      */
/* _(lisp_add_del_map_server, "<ip4|6-addr> [del]")                        */
/* _(lisp_enable_disable, "enable|disable")                                */
/* _(lisp_map_register_enable_disable, "enable|disable")                   */
/* _(lisp_rloc_probe_enable_disable, "enable|disable")                     */
/* _(lisp_add_del_remote_mapping, "add|del vni <vni> eid <dest-eid> "      */
/*                                "[seid <seid>] "                         */
/*                                "rloc <locator> p <prio> "               */
/*                                "w <weight> [rloc <loc> ... ] "          */
/*                                "action <action> [del-all]")             */
/* _(lisp_add_del_adjacency, "add|del vni <vni> reid <remote-eid> leid "   */
/*                           "<local-eid>")                                */
/* _(lisp_pitr_set_locator_set, "locator-set <loc-set-name> | del")        */
/* _(lisp_use_petr, "<ip-address> | disable")                              */
/* _(lisp_map_request_mode, "src-dst|dst-only")                            */
/* _(lisp_add_del_map_request_itr_rlocs, "<loc-set-name> [del]")           */
/* _(lisp_eid_table_add_del_map, "[del] vni <vni> vrf <vrf>")              */
/* _(lisp_locator_set_dump, "[local | remote]")                            */
/* _(lisp_locator_dump, "ls_index <index> | ls_name <name>")               */
/* _(lisp_eid_table_dump, "[eid <ipv4|ipv6>/<prefix> | <mac>] [vni] "      */
/*                        "[local] | [remote]")                            */
/* _(lisp_eid_table_vni_dump, "")                                          */
/* _(lisp_eid_table_map_dump, "l2|l3")                                     */
/* _(lisp_map_resolver_dump, "")                                           */
/* _(lisp_map_server_dump, "")                                             */
/* _(lisp_adjacencies_get, "vni <vni>")                                    */
/* _(gpe_fwd_entry_vnis_get, "")                                           */
/* _(gpe_native_fwd_rpaths_get, "ip4 | ip6")                               */
/* _(gpe_add_del_native_fwd_rpath, "[del] via <nh-ip-addr> [iface] "       */
/*                                 "[table <table-id>]")                   */
/* _(lisp_gpe_fwd_entries_get, "vni <vni>")                                */
/* _(lisp_gpe_fwd_entry_path_dump, "index <fwd_entry_index>")              */
/* _(gpe_set_encap_mode, "lisp|vxlan")                                     */
/* _(gpe_get_encap_mode, "")                                               */
/* _(lisp_gpe_add_del_iface, "up|down")                                    */
/* _(lisp_gpe_enable_disable, "enable|disable")                            */
/* _(lisp_gpe_add_del_fwd_entry, "reid <eid> [leid <eid>] vni <vni>"       */
/*   "vrf/bd <dp_table> loc-pair <lcl_loc> <rmt_loc> w <weight>... [del]") */
/* _(show_lisp_rloc_probe_state, "")                                       */
/* _(show_lisp_map_register_state, "")                                     */
/* _(show_lisp_status, "")                                                 */
/* _(lisp_get_map_request_itr_rlocs, "")                                   */
/* _(show_lisp_pitr, "")                                                   */
/* _(show_lisp_use_petr, "")                                               */
/* _(show_lisp_map_request_mode, "")                                       */

#include <lisp/lisp-cp/lisp.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
