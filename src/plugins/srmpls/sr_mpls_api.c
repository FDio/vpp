/*
 * ------------------------------------------------------------------
 * sr_api.c - ipv6 segment routing api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates. Licensed under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include "sr_mpls.h"
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip_types_api.h>

#include <vnet/format_fns.h>
#include <plugins/srmpls/sr_mpls.api_enum.h>
#include <plugins/srmpls/sr_mpls.api_types.h>

#define vl_api_version(n, v) static u32 api_version = v;
#include <plugins/srmpls/sr_mpls.api.h>
#undef vl_api_version

#define vl_endianfun
#include <plugins/srmpls/sr_mpls.api.h>
#undef vl_endianfun

#define vl_calcsizefun
#include <plugins/srmpls/sr_mpls.api.h>
#undef vl_calcsizefun

#define vl_printfun
#include <plugins/srmpls/sr_mpls.api.h>
#undef vl_printfun

#define vl_msg_name_crc_list
#include <plugins/srmpls/sr_mpls.api.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                             \
_(SR_MPLS_POLICY_DEL, sr_mpls_policy_del)                         \
_(SR_MPLS_STEERING_ADD_DEL, sr_mpls_steering_add_del)             \
_(SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR, sr_mpls_policy_assign_endpoint_color)

static u16 msg_id_base;

static void
vl_api_sr_mpls_policy_add_t_handler (vl_api_sr_mpls_policy_add_t * mp)
{
  vl_api_sr_mpls_policy_add_reply_t *rmp;

  mpls_label_t *segments = 0, *seg;
  mpls_label_t this_address = 0;

  int i;
  for (i = 0; i < mp->n_segments; i++)
    {
      vec_add2 (segments, seg, 1);
      this_address = ntohl (mp->segments[i]);
      clib_memcpy (seg, &this_address, sizeof (this_address));
    }

  int rv = 0;
  rv = sr_mpls_policy_add (ntohl (mp->bsid),
			   segments, mp->is_spray, ntohl (mp->weight));
  vec_free (segments);

  REPLY_MACRO (VL_API_SR_MPLS_POLICY_ADD_REPLY);
}

static void
vl_api_sr_mpls_policy_mod_t_handler (vl_api_sr_mpls_policy_mod_t * mp)
{
  vl_api_sr_mpls_policy_mod_reply_t *rmp;

  mpls_label_t *segments = 0, *seg;
  mpls_label_t this_address = 0;

  int i;
  for (i = 0; i < mp->n_segments; i++)
    {
      vec_add2 (segments, seg, 1);
      this_address = ntohl (mp->segments[i]);
      clib_memcpy (seg, &this_address, sizeof (this_address));
    }

  int rv = 0;
  rv = sr_mpls_policy_mod (ntohl (mp->bsid),
			   ntohl (mp->operation), segments,
			   ntohl (mp->sl_index), ntohl (mp->weight));
  vec_free (segments);

  REPLY_MACRO (VL_API_SR_MPLS_POLICY_MOD_REPLY);
}

static void
vl_api_sr_mpls_policy_del_t_handler (vl_api_sr_mpls_policy_del_t * mp)
{
  vl_api_sr_mpls_policy_del_reply_t *rmp;
  int rv = 0;
  rv = sr_mpls_policy_del (ntohl (mp->bsid));

  REPLY_MACRO (VL_API_SR_MPLS_POLICY_DEL_REPLY);
}

static void vl_api_sr_mpls_steering_add_del_t_handler
  (vl_api_sr_mpls_steering_add_del_t * mp)
{
  vl_api_sr_mpls_steering_add_del_reply_t *rmp;
  fib_prefix_t prefix;
  ip46_address_t next_hop;
  clib_memset (&prefix, 0, sizeof (ip46_address_t));

  ip_prefix_decode (&mp->prefix, &prefix);
  ip_address_decode (&mp->next_hop, &next_hop);

  int rv = 0;
  if (mp->is_del)
    rv = sr_mpls_steering_policy_del (&prefix.fp_addr,
				      prefix.fp_len,
				      ip46_address_is_ip4 (&prefix.fp_addr) ?
				      SR_STEER_IPV4 : SR_STEER_IPV6,
				      ntohl (mp->table_id),
				      ntohl (mp->color));
  else
    rv = sr_mpls_steering_policy_add (ntohl (mp->bsid),
				      ntohl (mp->table_id),
				      &prefix.fp_addr,
				      prefix.fp_len,
				      ip46_address_is_ip4 (&prefix.fp_addr) ?
				      SR_STEER_IPV4 : SR_STEER_IPV6,
				      &next_hop,
				      ip46_address_is_ip4 (&next_hop) ?
				      SR_STEER_IPV4 : SR_STEER_IPV6,
				      ntohl (mp->color), mp->co_bits,
				      ntohl (mp->vpn_label));

  REPLY_MACRO (VL_API_SR_MPLS_STEERING_ADD_DEL_REPLY);
}

static void vl_api_sr_mpls_policy_assign_endpoint_color_t_handler
  (vl_api_sr_mpls_policy_assign_endpoint_color_t * mp)
{
  vl_api_sr_mpls_policy_assign_endpoint_color_reply_t *rmp;
  int rv = 0;

  ip46_address_t endpoint;
  clib_memset (&endpoint, 0, sizeof (ip46_address_t));
  ip_address_decode (&mp->endpoint, &endpoint);

  rv = sr_mpls_policy_assign_endpoint_color (ntohl (mp->bsid),
					     &endpoint,
					     ip46_address_is_ip4 (&endpoint) ?
					     SR_STEER_IPV4 : SR_STEER_IPV6,
					     ntohl (mp->color));

  REPLY_MACRO (VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_REPLY);
}

static void
setup_message_id_table (api_main_t * am)
{
#define _(id, n, crc)                                                         \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + REPLY_MSG_ID_BASE);
  foreach_vl_msg_name_crc_sr_mpls;
#undef _
}

static clib_error_t *
sr_mpls_api_hookup (vlib_main_t * vm)
{
  api_main_t *am = vlibapi_get_main ();

  u8 *name = format (0, "sr_mpls_%08x%c", api_version, 0);
  REPLY_MSG_ID_BASE =
    vl_msg_api_get_msg_ids ((char *) name, VL_MSG_SR_MPLS_LAST);
  vec_free (name);

#define _(N, n)                                                               \
  vl_msg_api_config (&(vl_msg_api_msg_config_t){                              \
    .id = REPLY_MSG_ID_BASE + VL_API_##N,                                     \
    .name = #n,                                                               \
    .handler = vl_api_##n##_t_handler,                                        \
    .endian = vl_api_##n##_t_endian,                                          \
    .format_fn = vl_api_##n##_t_format,                                       \
    .size = sizeof (vl_api_##n##_t),                                          \
    .traced = 1,                                                              \
    .tojson = vl_api_##n##_t_tojson,                                          \
    .fromjson = vl_api_##n##_t_fromjson,                                      \
    .calc_size = vl_api_##n##_t_calc_size,                                    \
  });
  foreach_vpe_api_msg;
#undef _

  /*
   * Manually register the sr policy add msg, so we trace enough bytes
   * to capture a typical segment list
   */
  vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = REPLY_MSG_ID_BASE + VL_API_SR_MPLS_POLICY_ADD,
    .name = "sr_mpls_policy_add",
    .handler = vl_api_sr_mpls_policy_add_t_handler,
    .endian = vl_api_sr_mpls_policy_add_t_endian,
    .format_fn = vl_api_sr_mpls_policy_add_t_format,
    .size = 256,
    .traced = 1,
    .tojson = vl_api_sr_mpls_policy_add_t_tojson,
    .fromjson = vl_api_sr_mpls_policy_add_t_fromjson,
    .calc_size = vl_api_sr_mpls_policy_add_t_calc_size,
  });
  /*
   * Manually register the sr policy mod msg, so we trace enough bytes
   * to capture a typical segment list
   */
  vl_msg_api_config (&(vl_msg_api_msg_config_t){
    .id = REPLY_MSG_ID_BASE + VL_API_SR_MPLS_POLICY_MOD,
    .name = "sr_mpls_policy_mod",
    .handler = vl_api_sr_mpls_policy_mod_t_handler,
    .endian = vl_api_sr_mpls_policy_mod_t_endian,
    .format_fn = vl_api_sr_mpls_policy_mod_t_format,
    .size = 256,
    .traced = 1,
    .tojson = vl_api_sr_mpls_policy_mod_t_tojson,
    .fromjson = vl_api_sr_mpls_policy_mod_t_fromjson,
    .calc_size = vl_api_sr_mpls_policy_mod_t_calc_size,
  });

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (sr_mpls_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables: eval: (c-set-style "gnu") End:
 */
