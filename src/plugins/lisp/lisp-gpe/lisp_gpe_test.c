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
#include <vnet/ethernet/mac_address.h>
#include <lisp/lisp-cp/lisp_types.h>

/* define message IDs */
#include <lisp/lisp-gpe/lisp_gpe.api_enum.h>
#include <lisp/lisp-gpe/lisp_gpe.api_types.h>
#include <vlibmemory/vlib.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
  u32 ping_id;
} lisp_gpe_test_main_t;

lisp_gpe_test_main_t lisp_gpe_test_main;

#define __plugin_msg_base lisp_gpe_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#define FINISH                                                                \
  vec_add1 (s, 0);                                                            \
  vlib_cli_output (handle, (char *) s);                                       \
  vec_free (s);                                                               \
  return handle;

#define LISP_PING(_lm, mp_ping)                                         \
  if (!(_lm)->ping_id)                                                  \
    (_lm)->ping_id = vl_msg_api_get_msg_index ((u8 *) (VL_API_CONTROL_PING_CRC)); \
  mp_ping = vl_msg_api_alloc_as_if_client (sizeof (*mp_ping));          \
  mp_ping->_vl_msg_id = htons ((_lm)->ping_id);                         \
  mp_ping->client_index = vam->my_client_index;                         \
  fformat (vam->ofp, "Sending ping id=%d\n", (_lm)->ping_id);           \
  vam->result_ready = 0;                                                \

typedef struct
{
  u32 spi;
  u8 si;
} __attribute__ ((__packed__)) lisp_nsh_api_t;

static uword
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

static void vl_api_gpe_add_del_fwd_entry_reply_t_handler
  (vl_api_gpe_add_del_fwd_entry_reply_t * mp)
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
api_gpe_fwd_entry_net_to_host (vl_api_gpe_fwd_entry_t * e)
{
  e->dp_table = clib_net_to_host_u32 (e->dp_table);
  e->fwd_entry_index = clib_net_to_host_u32 (e->fwd_entry_index);
  e->vni = clib_net_to_host_u32 (e->vni);
}

static void
  gpe_fwd_entries_get_reply_t_net_to_host
  (vl_api_gpe_fwd_entries_get_reply_t * mp)
{
  u32 i;

  mp->count = clib_net_to_host_u32 (mp->count);
  for (i = 0; i < mp->count; i++)
    {
      api_gpe_fwd_entry_net_to_host (&mp->entries[i]);
    }
}

static u8 *
format_gpe_encap_mode (u8 * s, va_list * args)
{
  u32 mode = va_arg (*args, u32);

  switch (mode)
    {
    case 0:
      return format (s, "lisp");
    case 1:
      return format (s, "vxlan");
    }
  return 0;
}

static void
  vl_api_gpe_get_encap_mode_reply_t_handler
  (vl_api_gpe_get_encap_mode_reply_t * mp)
{
  vat_main_t *vam = &vat_main;

  print (vam->ofp, "gpe mode: %U", format_gpe_encap_mode, mp->encap_mode);
  vam->retval = ntohl (mp->retval);
  vam->result_ready = 1;
}

static void
  vl_api_gpe_fwd_entry_path_details_t_handler
  (vl_api_gpe_fwd_entry_path_details_t * mp)
{
  vat_main_t *vam = &vat_main;
  u8 *(*format_ip_address_fcn) (u8 *, va_list *) = 0;

  if (mp->lcl_loc.addr.af)
    format_ip_address_fcn = format_ip6_address;
  else
    format_ip_address_fcn = format_ip4_address;

  print (vam->ofp, "w:%d %30U %30U", mp->rmt_loc.weight,
	 format_ip_address_fcn, &mp->lcl_loc.addr.un,
	 format_ip_address_fcn, &mp->rmt_loc.addr.un);
}

static void
  vl_api_gpe_fwd_entries_get_reply_t_handler
  (vl_api_gpe_fwd_entries_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_gpe_fwd_entry_t *e;

  if (retval)
    goto end;

  gpe_fwd_entries_get_reply_t_net_to_host (mp);

  for (i = 0; i < mp->count; i++)
    {
      e = &mp->entries[i];
      print (vam->ofp, "%10d %10d %U %40U", e->fwd_entry_index, e->dp_table,
	     format_lisp_flat_eid, e->leid, format_lisp_flat_eid, e->reid);
    }

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_gpe_native_fwd_rpaths_get_reply_t_handler
  (vl_api_gpe_native_fwd_rpaths_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);
  vl_api_gpe_native_fwd_rpath_t *r;

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    {
      r = &mp->entries[i];
      print (vam->ofp, "fib_index: %d sw_if_index %d nh %U",
	     clib_net_to_host_u32 (r->fib_index),
	     clib_net_to_host_u32 (r->nh_sw_if_index),
	     r->nh_addr.af ? format_ip6_address : format_ip4_address,
	     r->nh_addr.un);
    }

end:
  vam->retval = retval;
  vam->result_ready = 1;
}

static void
  vl_api_gpe_fwd_entry_vnis_get_reply_t_handler
  (vl_api_gpe_fwd_entry_vnis_get_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  u32 i, n;
  int retval = clib_net_to_host_u32 (mp->retval);

  if (retval)
    goto end;

  n = clib_net_to_host_u32 (mp->count);

  for (i = 0; i < n; i++)
    print (vam->ofp, "%d", clib_net_to_host_u32 (mp->vnis[i]));

end:
  vam->retval = retval;
  vam->result_ready = 1;
}


/* *INDENT-OFF* */
/** Used for parsing LISP eids */
typedef CLIB_PACKED(struct{
  union {
          ip46_address_t ip;
          mac_address_t mac;
          lisp_nsh_api_t nsh;
  } addr;
  u32 len;       /**< prefix length if IP */
  u8 type;      /**< type of eid */
}) lisp_eid_vat_t;
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
api_gpe_add_del_fwd_entry (vat_main_t * vam)
{
  u32 dp_table = 0, vni = 0;;
  unformat_input_t *input = vam->input;
  vl_api_gpe_add_del_fwd_entry_t *mp;
  u8 is_add = 1;
  lisp_eid_vat_t _rmt_eid, *rmt_eid = &_rmt_eid;
  lisp_eid_vat_t _lcl_eid, *lcl_eid = &_lcl_eid;
  u8 rmt_eid_set = 0, lcl_eid_set = 0;
  u32 action = ~0, w;
  ip4_address_t rmt_rloc4, lcl_rloc4;
  ip6_address_t rmt_rloc6, lcl_rloc6;
  vl_api_gpe_locator_t *rmt_locs = 0, *lcl_locs = 0, rloc, *curr_rloc = 0;
  int ret;

  clib_memset (&rloc, 0, sizeof (rloc));

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "reid %U", unformat_lisp_eid_vat, rmt_eid))
	{
	  rmt_eid_set = 1;
	}
      else if (unformat (input, "leid %U", unformat_lisp_eid_vat, lcl_eid))
	{
	  lcl_eid_set = 1;
	}
      else if (unformat (input, "vrf %d", &dp_table))
	;
      else if (unformat (input, "bd %d", &dp_table))
	;
      else if (unformat (input, "vni %d", &vni))
	;
      else if (unformat (input, "w %d", &w))
	{
	  if (!curr_rloc)
	    {
	      errmsg ("No RLOC configured for setting priority/weight!");
	      return -99;
	    }
	  curr_rloc->weight = w;
	}
      else if (unformat (input, "loc-pair %U %U", unformat_ip4_address,
			 &lcl_rloc4, unformat_ip4_address, &rmt_rloc4))
	{
	  rloc.addr.af = 0;
	  clib_memcpy (&rloc.addr.un.ip4, &lcl_rloc4, sizeof (lcl_rloc4));
	  rloc.weight = 0;
	  vec_add1 (lcl_locs, rloc);

	  clib_memcpy (&rloc.addr.un.ip4, &rmt_rloc4, sizeof (rmt_rloc4));
	  vec_add1 (rmt_locs, rloc);
	  /* weight saved in rmt loc */
	  curr_rloc = &rmt_locs[vec_len (rmt_locs) - 1];
	}
      else if (unformat (input, "loc-pair %U %U", unformat_ip6_address,
			 &lcl_rloc6, unformat_ip6_address, &rmt_rloc6))
	{
	  rloc.addr.af = 1;
	  clib_memcpy (&rloc.addr.un.ip6, &lcl_rloc6, sizeof (lcl_rloc6));
	  rloc.weight = 0;
	  vec_add1 (lcl_locs, rloc);

	  clib_memcpy (&rloc.addr.un.ip6, &rmt_rloc6, sizeof (rmt_rloc6));
	  vec_add1 (rmt_locs, rloc);
	  /* weight saved in rmt loc */
	  curr_rloc = &rmt_locs[vec_len (rmt_locs) - 1];
	}
      else if (unformat (input, "action %d", &action))
	{
	  ;
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, input);
	  return -99;
	}
    }

  if (!rmt_eid_set)
    {
      errmsg ("remote eid addresses not set");
      return -99;
    }

  if (lcl_eid_set && rmt_eid->type != lcl_eid->type)
    {
      errmsg ("eid types don't match");
      return -99;
    }

  if (0 == rmt_locs && (u32) ~ 0 == action)
    {
      errmsg ("action not set for negative mapping");
      return -99;
    }

  /* Construct the API message */
  M2 (GPE_ADD_DEL_FWD_ENTRY, mp,
      sizeof (vl_api_gpe_locator_t) * vec_len (rmt_locs) * 2);

  mp->is_add = is_add;
  lisp_eid_put_vat (&mp->rmt_eid, rmt_eid);
  lisp_eid_put_vat (&mp->lcl_eid, lcl_eid);
  mp->dp_table = clib_host_to_net_u32 (dp_table);
  mp->vni = clib_host_to_net_u32 (vni);
  mp->action = action;

  if (0 != rmt_locs && 0 != lcl_locs)
    {
      mp->loc_num = clib_host_to_net_u32 (vec_len (rmt_locs) * 2);
      clib_memcpy (mp->locs, lcl_locs,
		   (sizeof (vl_api_gpe_locator_t) * vec_len (lcl_locs)));

      u32 offset = sizeof (vl_api_gpe_locator_t) * vec_len (lcl_locs);
      clib_memcpy (((u8 *) mp->locs) + offset, rmt_locs,
		   (sizeof (vl_api_gpe_locator_t) * vec_len (rmt_locs)));
    }
  vec_free (lcl_locs);
  vec_free (rmt_locs);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_enable_disable (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_gpe_enable_disable_t *mp;
  u8 is_set = 0;
  u8 is_enable = 1;
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
	  is_enable = 0;
	}
      else
	break;
    }

  if (is_set == 0)
    {
      errmsg ("Value not set");
      return -99;
    }

  /* Construct the API message */
  M (GPE_ENABLE_DISABLE, mp);

  mp->is_enable = is_enable;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

uword
unformat_gpe_encap_mode (unformat_input_t * input, va_list * args)
{
  u32 *mode = va_arg (*args, u32 *);

  if (unformat (input, "lisp"))
    *mode = 0;
  else if (unformat (input, "vxlan"))
    *mode = 1;
  else
    return 0;

  return 1;
}

static int
api_gpe_get_encap_mode (vat_main_t * vam)
{
  vl_api_gpe_get_encap_mode_t *mp;
  int ret;

  /* Construct the API message */
  M (GPE_GET_ENCAP_MODE, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_set_encap_mode (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_gpe_set_encap_mode_t *mp;
  int ret;
  u32 mode = 0;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_gpe_encap_mode, &mode))
	;
      else
	break;
    }

  /* Construct the API message */
  M (GPE_SET_ENCAP_MODE, mp);

  mp->is_vxlan = mode;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_add_del_iface (vat_main_t * vam)
{
  unformat_input_t *input = vam->input;
  vl_api_gpe_add_del_iface_t *mp;
  u8 action_set = 0, is_add = 1, is_l2 = 0, dp_table_set = 0, vni_set = 0;
  u32 dp_table = 0, vni = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "up"))
	{
	  action_set = 1;
	  is_add = 1;
	}
      else if (unformat (input, "down"))
	{
	  action_set = 1;
	  is_add = 0;
	}
      else if (unformat (input, "table_id %d", &dp_table))
	{
	  dp_table_set = 1;
	}
      else if (unformat (input, "bd_id %d", &dp_table))
	{
	  dp_table_set = 1;
	  is_l2 = 1;
	}
      else if (unformat (input, "vni %d", &vni))
	{
	  vni_set = 1;
	}
      else
	break;
    }

  if (action_set == 0)
    {
      errmsg ("Action not set");
      return -99;
    }
  if (dp_table_set == 0 || vni_set == 0)
    {
      errmsg ("vni and dp_table must be set");
      return -99;
    }

  /* Construct the API message */
  M (GPE_ADD_DEL_IFACE, mp);

  mp->is_add = is_add;
  mp->dp_table = clib_host_to_net_u32 (dp_table);
  mp->is_l2 = is_l2;
  mp->vni = clib_host_to_net_u32 (vni);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_fwd_entries_get (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gpe_fwd_entries_get_t *mp;
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
      print (vam->ofp, "%10s %10s %s %40s", "fwd_index", "dp_table",
	     "leid", "reid");
    }

  M (GPE_FWD_ENTRIES_GET, mp);
  mp->vni = clib_host_to_net_u32 (vni);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_native_fwd_rpaths_get (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gpe_native_fwd_rpaths_get_t *mp;
  int ret;
  u8 ip_family_set = 0, is_ip4 = 1;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "ip4"))
	{
	  ip_family_set = 1;
	  is_ip4 = 1;
	}
      else if (unformat (i, "ip6"))
	{
	  ip_family_set = 1;
	  is_ip4 = 0;
	}
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!ip_family_set)
    {
      errmsg ("ip family not set!");
      return -99;
    }

  M (GPE_NATIVE_FWD_RPATHS_GET, mp);
  mp->is_ip4 = is_ip4;

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_fwd_entry_vnis_get (vat_main_t * vam)
{
  vl_api_gpe_fwd_entry_vnis_get_t *mp;
  int ret;

  if (!vam->json_output)
    {
      print (vam->ofp, "VNIs");
    }

  M (GPE_FWD_ENTRY_VNIS_GET, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_add_del_native_fwd_rpath (vat_main_t * vam)
{
  unformat_input_t *i = vam->input;
  vl_api_gpe_add_del_native_fwd_rpath_t *mp;
  int ret = 0;
  u8 is_add = 1, ip_set = 0, is_ip4 = 1;
  struct in_addr ip4;
  struct in6_addr ip6;
  u32 table_id = 0, nh_sw_if_index = ~0;

  clib_memset (&ip4, 0, sizeof (ip4));
  clib_memset (&ip6, 0, sizeof (ip6));

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_add = 0;
      else if (unformat (i, "via %U %U", unformat_ip4_address, &ip4,
			 unformat_sw_if_index, vam, &nh_sw_if_index))
	{
	  ip_set = 1;
	  is_ip4 = 1;
	}
      else if (unformat (i, "via %U %U", unformat_ip6_address, &ip6,
			 unformat_sw_if_index, vam, &nh_sw_if_index))
	{
	  ip_set = 1;
	  is_ip4 = 0;
	}
      else if (unformat (i, "via %U", unformat_ip4_address, &ip4))
	{
	  ip_set = 1;
	  is_ip4 = 1;
	  nh_sw_if_index = ~0;
	}
      else if (unformat (i, "via %U", unformat_ip6_address, &ip6))
	{
	  ip_set = 1;
	  is_ip4 = 0;
	  nh_sw_if_index = ~0;
	}
      else if (unformat (i, "table %u", &table_id))
	;
      else
	{
	  errmsg ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (!ip_set)
    {
      errmsg ("nh addr not set!");
      return -99;
    }

  M (GPE_ADD_DEL_NATIVE_FWD_RPATH, mp);
  mp->is_add = is_add;
  mp->table_id = clib_host_to_net_u32 (table_id);
  mp->nh_sw_if_index = clib_host_to_net_u32 (nh_sw_if_index);
  mp->nh_addr.af = is_ip4 ? 0 : 1;
  if (is_ip4)
    clib_memcpy (mp->nh_addr.un.ip4, &ip4, sizeof (ip4));
  else
    clib_memcpy (mp->nh_addr.un.ip6, &ip6, sizeof (ip6));

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_gpe_fwd_entry_path_dump (vat_main_t * vam)
{
  vl_api_gpe_fwd_entry_path_dump_t *mp;
  vl_api_control_ping_t *mp_ping;
  unformat_input_t *i = vam->input;
  u32 fwd_entry_index = ~0;
  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "index %d", &fwd_entry_index))
	;
      else
	break;
    }

  if (~0 == fwd_entry_index)
    {
      errmsg ("no index specified!");
      return -99;
    }

  if (!vam->json_output)
    {
      print (vam->ofp, "first line");
    }

  M (GPE_FWD_ENTRY_PATH_DUMP, mp);

  /* send it... */
  S (mp);
  /* Use a control ping for synchronization */
  LISP_PING (&lisp_gpe_test_main, mp_ping);
  S (mp_ping);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#define vat_plugin_register vat_plugin_register_gpe
#include <lisp/lisp-gpe/lisp_gpe.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
