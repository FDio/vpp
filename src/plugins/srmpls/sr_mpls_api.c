/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/* sr_api.c - ipv6 segment routing api */

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

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

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
  rv = sr_mpls_policy_mod (ntohl (mp->bsid), mp->operation, segments, ntohl (mp->sl_index),
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

#include <plugins/srmpls/sr_mpls.api.c>

static clib_error_t *
sr_mpls_api_hookup (vlib_main_t *vm)
{
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (sr_mpls_api_hookup);
