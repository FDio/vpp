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
#include <vnet/srmpls/sr_mpls.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>

#include <vnet/vnet_msg_enum.h>

#define vl_typedefs		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_typedefs

#define vl_endianfun		/* define message structures */
#include <vnet/vnet_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <vnet/vnet_all_api_h.h>
#undef vl_printfun

#include <vlibapi/api_helper_macros.h>

#define foreach_vpe_api_msg                             \
_(SR_MPLS_POLICY_DEL, sr_mpls_policy_del)                         \
_(SR_MPLS_STEERING_ADD_DEL, sr_mpls_steering_add_del)             \
_(SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR, sr_mpls_policy_assign_endpoint_color)


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
			   segments, mp->type, ntohl (mp->weight));
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
			   mp->operation, segments, ntohl (mp->sl_index),
			   ntohl (mp->weight));
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
  ip46_address_t prefix;
  memset (&prefix, 0, sizeof (ip46_address_t));
  if (mp->traffic_type == SR_STEER_IPV4)
    memcpy (&prefix.ip4, mp->prefix_addr, sizeof (prefix.ip4));
  else
    memcpy (&prefix, mp->prefix_addr, sizeof (prefix.ip6));

  int rv = 0;
  if (mp->is_del)
    rv = sr_mpls_steering_policy_del (&prefix,
				      ntohl (mp->mask_width),
				      mp->traffic_type,
				      ntohl (mp->table_id),
				      ntohl (mp->color));
  else
    rv = sr_mpls_steering_policy_add (ntohl (mp->bsid),
				      ntohl (mp->table_id),
				      &prefix,
				      ntohl (mp->mask_width),
				      mp->traffic_type,
				      (ip46_address_t *) & mp->next_hop,
				      mp->nh_type,
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
  memset (&endpoint, 0, sizeof (ip46_address_t));
  if (mp->endpoint_type == SR_STEER_IPV4)
    memcpy (&endpoint.ip4, mp->endpoint, sizeof (endpoint.ip4));
  else
    memcpy (&endpoint, mp->endpoint, sizeof (endpoint.ip6));

  rv = sr_mpls_policy_assign_endpoint_color (ntohl (mp->bsid),
					     &endpoint, mp->endpoint_type,
					     ntohl (mp->color));

  REPLY_MACRO (VL_API_SR_MPLS_POLICY_ASSIGN_ENDPOINT_COLOR_REPLY);
}

/*
 * sr_mpls_api_hookup Add vpe's API message handlers to the table. vlib has
 * alread mapped shared memory and added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_sr_mpls;
#undef _
}

static clib_error_t *
sr_mpls_api_hookup (vlib_main_t * vm)
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
   * Manually register the sr policy add msg, so we trace enough bytes
   * to capture a typical segment list
   */
  vl_msg_api_set_handlers (VL_API_SR_MPLS_POLICY_ADD,
			   "sr_mpls_policy_add",
			   vl_api_sr_mpls_policy_add_t_handler,
			   vl_noop_handler,
			   vl_api_sr_mpls_policy_add_t_endian,
			   vl_api_sr_mpls_policy_add_t_print, 256, 1);

  /*
   * Manually register the sr policy mod msg, so we trace enough bytes
   * to capture a typical segment list
   */
  vl_msg_api_set_handlers (VL_API_SR_MPLS_POLICY_MOD,
			   "sr_mpls_policy_mod",
			   vl_api_sr_mpls_policy_mod_t_handler,
			   vl_noop_handler,
			   vl_api_sr_mpls_policy_mod_t_endian,
			   vl_api_sr_mpls_policy_mod_t_print, 256, 1);

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
