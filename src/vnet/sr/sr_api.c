/*
 *------------------------------------------------------------------
 * sr_api.c - ipv6 segment routing api
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
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
_(SR_MULTICAST_MAP_ADD_DEL, sr_multicast_map_add_del)

static void vl_api_sr_tunnel_add_del_t_handler
  (vl_api_sr_tunnel_add_del_t * mp)
{
#if IP6SR == 0
  clib_warning ("unimplemented");
#else
  ip6_sr_add_del_tunnel_args_t _a, *a = &_a;
  int rv = 0;
  vl_api_sr_tunnel_add_del_reply_t *rmp;
  ip6_address_t *segments = 0, *seg;
  ip6_address_t *tags = 0, *tag;
  ip6_address_t *this_address;
  int i;

  if (mp->n_segments == 0)
    {
      rv = -11;
      goto out;
    }

  memset (a, 0, sizeof (*a));
  a->src_address = (ip6_address_t *) & mp->src_address;
  a->dst_address = (ip6_address_t *) & mp->dst_address;
  a->dst_mask_width = mp->dst_mask_width;
  a->flags_net_byte_order = mp->flags_net_byte_order;
  a->is_del = (mp->is_add == 0);
  a->rx_table_id = ntohl (mp->outer_vrf_id);
  a->tx_table_id = ntohl (mp->inner_vrf_id);

  a->name = format (0, "%s", mp->name);
  if (!(vec_len (a->name)))
    a->name = 0;

  a->policy_name = format (0, "%s", mp->policy_name);
  if (!(vec_len (a->policy_name)))
    a->policy_name = 0;

  /* Yank segments and tags out of the API message */
  this_address = (ip6_address_t *) mp->segs_and_tags;
  for (i = 0; i < mp->n_segments; i++)
    {
      vec_add2 (segments, seg, 1);
      clib_memcpy (seg->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }
  for (i = 0; i < mp->n_tags; i++)
    {
      vec_add2 (tags, tag, 1);
      clib_memcpy (tag->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }

  a->segments = segments;
  a->tags = tags;

  rv = ip6_sr_add_del_tunnel (a);

out:

  REPLY_MACRO (VL_API_SR_TUNNEL_ADD_DEL_REPLY);
#endif
}

static void vl_api_sr_policy_add_del_t_handler
  (vl_api_sr_policy_add_del_t * mp)
{
#if IP6SR == 0
  clib_warning ("unimplemented");
#else
  ip6_sr_add_del_policy_args_t _a, *a = &_a;
  int rv = 0;
  vl_api_sr_policy_add_del_reply_t *rmp;
  int i;

  memset (a, 0, sizeof (*a));
  a->is_del = (mp->is_add == 0);

  a->name = format (0, "%s", mp->name);
  if (!(vec_len (a->name)))
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE2;
      goto out;
    }

  if (!(mp->tunnel_names[0]))
    {
      rv = VNET_API_ERROR_NO_SUCH_NODE2;
      goto out;
    }

  // start deserializing tunnel_names
  int num_tunnels = mp->tunnel_names[0];	//number of tunnels
  u8 *deser_tun_names = mp->tunnel_names;
  deser_tun_names += 1;		//moving along

  u8 *tun_name = 0;
  int tun_name_len = 0;

  for (i = 0; i < num_tunnels; i++)
    {
      tun_name_len = *deser_tun_names;
      deser_tun_names += 1;
      vec_resize (tun_name, tun_name_len);
      memcpy (tun_name, deser_tun_names, tun_name_len);
      vec_add1 (a->tunnel_names, tun_name);
      deser_tun_names += tun_name_len;
      tun_name = 0;
    }

  rv = ip6_sr_add_del_policy (a);

out:

  REPLY_MACRO (VL_API_SR_POLICY_ADD_DEL_REPLY);
#endif
}

static void vl_api_sr_multicast_map_add_del_t_handler
  (vl_api_sr_multicast_map_add_del_t * mp)
{
#if IP6SR == 0
  clib_warning ("unimplemented");
#else
  ip6_sr_add_del_multicastmap_args_t _a, *a = &_a;
  int rv = 0;
  vl_api_sr_multicast_map_add_del_reply_t *rmp;

  memset (a, 0, sizeof (*a));
  a->is_del = (mp->is_add == 0);

  a->multicast_address = (ip6_address_t *) & mp->multicast_address;
  a->policy_name = format (0, "%s", mp->policy_name);

  if (a->multicast_address == 0)
    {
      rv = -1;
      goto out;
    }

  if (!(a->policy_name))
    {
      rv = -2;
      goto out;
    }

  rv = ip6_sr_add_del_multicastmap (a);

out:

  REPLY_MACRO (VL_API_SR_MULTICAST_MAP_ADD_DEL_REPLY);
#endif
}

/*
 * sr_api_hookup
 * Add vpe's API message handlers to the table.
 * vlib has alread mapped shared memory and
 * added the client registration handlers.
 * See .../vlib-api/vlibmemory/memclnt_vlib.c:memclnt_process()
 */
#define vl_msg_name_crc_list
#include <vnet/vnet_all_api_h.h>
#undef vl_msg_name_crc_list

static void
setup_message_id_table (api_main_t * am)
{
#define _(id,n,crc) vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id);
  foreach_vl_msg_name_crc_sr;
#undef _
}

static clib_error_t *
sr_api_hookup (vlib_main_t * vm)
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
   * Manually register the sr tunnel add del msg, so we trace
   * enough bytes to capture a typical segment list
   */
  vl_msg_api_set_handlers (VL_API_SR_TUNNEL_ADD_DEL,
			   "sr_tunnel_add_del",
			   vl_api_sr_tunnel_add_del_t_handler,
			   vl_noop_handler,
			   vl_api_sr_tunnel_add_del_t_endian,
			   vl_api_sr_tunnel_add_del_t_print, 256, 1);


  /*
   * Manually register the sr policy add del msg, so we trace
   * enough bytes to capture a typical tunnel name list
   */
  vl_msg_api_set_handlers (VL_API_SR_POLICY_ADD_DEL,
			   "sr_policy_add_del",
			   vl_api_sr_policy_add_del_t_handler,
			   vl_noop_handler,
			   vl_api_sr_policy_add_del_t_endian,
			   vl_api_sr_policy_add_del_t_print, 256, 1);

  /*
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (sr_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
