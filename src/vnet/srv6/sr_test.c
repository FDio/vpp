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

#define __plugin_msg_base sr_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <vnet/srv6/sr.api_enum.h>
#include <vnet/srv6/sr.api_types.h>

#define vl_endianfun /* define message structures */
#include <vnet/srv6/sr.api.h>
#undef vl_endianfun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} sr_test_main_t;

static sr_test_main_t sr_test_main;

static int
api_sr_steering_add_del (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_set_encap_hop_limit (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_set_encap_source (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_policy_del (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_policy_mod (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_policy_add (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_policy_mod_v2 (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_policy_add_v2 (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_localsids_dump (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_policies_dump (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_policies_v2_dump (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_policies_with_sl_index_dump (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_steering_pol_dump (vat_main_t *vam)
{
  return -1;
}

static void
vl_api_sr_policies_details_t_handler (vl_api_sr_policies_details_t *mp)
{
}

static void
vl_api_sr_policies_v2_details_t_handler (vl_api_sr_policies_v2_details_t *mp)
{
}

static void
vl_api_sr_localsids_details_t_handler (vl_api_sr_localsids_details_t *mp)
{
}

static void
vl_api_sr_policies_with_sl_index_details_t_handler (
  vl_api_sr_policies_with_sl_index_details_t *mp)
{
}

static void
vl_api_sr_steering_pol_details_t_handler (vl_api_sr_steering_pol_details_t *mp)
{
}

static int
api_sr_localsid_add_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sr_localsid_add_del_t *mp;

  u8 is_del;
  ip6_address_t localsid;
  u8 end_psp = 0;
  u8 behavior = ~0;
  u32 sw_if_index;
  u32 fib_table = ~(u32) 0;
  ip46_address_t nh_addr;
  clib_memset (&nh_addr, 0, sizeof (ip46_address_t));

  bool nexthop_set = 0;

  int ret;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "del"))
	is_del = 1;
      else if (unformat (i, "address %U", unformat_ip6_address, &localsid))
	;
      else if (unformat (i, "next-hop %U", unformat_ip46_address, &nh_addr))
	nexthop_set = 1;
      else if (unformat (i, "behavior %u", &behavior))
	;
      else if (unformat (i, "sw_if_index %u", &sw_if_index))
	;
      else if (unformat (i, "fib-table %u", &fib_table))
	;
      else if (unformat (i, "end.psp %u", &behavior))
	;
      else
	break;
    }

  M (SR_LOCALSID_ADD_DEL, mp);

  clib_memcpy (mp->localsid, &localsid, sizeof (mp->localsid));

  if (nexthop_set)
    {
      clib_memcpy (&mp->nh_addr.un, &nh_addr, sizeof (mp->nh_addr.un));
    }
  mp->behavior = behavior;
  mp->sw_if_index = ntohl (sw_if_index);
  mp->fib_table = ntohl (fib_table);
  mp->end_psp = end_psp;
  mp->is_del = is_del;

  S (mp);
  W (ret);
  return ret;
}

#include <vnet/srv6/sr.api_test.c>

VAT_REGISTER_FEATURE_FUNCTION (vat_sr_plugin_register);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
