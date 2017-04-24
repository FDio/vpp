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
#include <vnet/srv6/sr.h>
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
_(SR_LOCALSID_ADD_DEL, sr_localsid_add_del)             \
_(SR_POLICY_DEL, sr_policy_del)                         \
_(SR_STEERING_ADD_DEL, sr_steering_add_del)
//_(SR_LOCALSIDS, sr_localsids_dump)
//_(SR_LOCALSID_BEHAVIORS, sr_localsid_behaviors_dump)

static void vl_api_sr_localsid_add_del_t_handler
  (vl_api_sr_localsid_add_del_t * mp)
{
  vl_api_sr_localsid_add_del_reply_t *rmp;
  int rv = 0;
/*
 * int sr_cli_localsid (char is_del, ip6_address_t *localsid_addr,
 *  char end_psp, u8 behavior, u32 sw_if_index, u32 vlan_index, u32 fib_table,
 *  ip46_address_t *nh_addr, void *ls_plugin_mem)
 */
  rv = sr_cli_localsid (mp->is_del,
			(ip6_address_t *) & mp->localsid_addr,
			mp->end_psp,
			mp->behavior,
			ntohl (mp->sw_if_index),
			ntohl (mp->vlan_index),
			ntohl (mp->fib_table),
			(ip46_address_t *) & mp->nh_addr, NULL);

  REPLY_MACRO (VL_API_SR_LOCALSID_ADD_DEL_REPLY);
}

static void
vl_api_sr_policy_add_t_handler (vl_api_sr_policy_add_t * mp)
{
  vl_api_sr_policy_add_reply_t *rmp;
  ip6_address_t *segments = 0, *seg;
  ip6_address_t *this_address = (ip6_address_t *) mp->segments;

  int i;
  for (i = 0; i < mp->n_segments; i++)
    {
      vec_add2 (segments, seg, 1);
      clib_memcpy (seg->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }

/*
 * sr_policy_add (ip6_address_t *bsid, ip6_address_t *segments,
 *                u32 weight, u8 behavior, u32 fib_table, u8 is_encap)
 */
  int rv = 0;
  rv = sr_policy_add ((ip6_address_t *) & mp->bsid_addr,
		      segments,
		      ntohl (mp->weight),
		      mp->type, ntohl (mp->fib_table), mp->is_encap);

  REPLY_MACRO (VL_API_SR_POLICY_ADD_REPLY);
}

static void
vl_api_sr_policy_mod_t_handler (vl_api_sr_policy_mod_t * mp)
{
  vl_api_sr_policy_mod_reply_t *rmp;

  ip6_address_t *segments = 0, *seg;
  ip6_address_t *this_address = (ip6_address_t *) mp->segments;

  int i;
  for (i = 0; i < mp->n_segments; i++)
    {
      vec_add2 (segments, seg, 1);
      clib_memcpy (seg->as_u8, this_address->as_u8, sizeof (*this_address));
      this_address++;
    }

  int rv = 0;
/*
 * int
 * sr_policy_mod(ip6_address_t *bsid, u32 index, u32 fib_table,
 *               u8 operation, ip6_address_t *segments, u32 sl_index,
 *               u32 weight, u8 is_encap)
 */
  rv = sr_policy_mod ((ip6_address_t *) & mp->bsid_addr,
		      ntohl (mp->sr_policy_index),
		      ntohl (mp->fib_table),
		      mp->operation,
		      segments, ntohl (mp->sl_index), ntohl (mp->weight));

  REPLY_MACRO (VL_API_SR_POLICY_MOD_REPLY);
}

static void
vl_api_sr_policy_del_t_handler (vl_api_sr_policy_del_t * mp)
{
  vl_api_sr_policy_del_reply_t *rmp;
  int rv = 0;
/*
 * int
 * sr_policy_del (ip6_address_t *bsid, u32 index)
 */
  rv = sr_policy_del ((ip6_address_t *) & mp->bsid_addr,
		      ntohl (mp->sr_policy_index));

  REPLY_MACRO (VL_API_SR_POLICY_DEL_REPLY);
}

static void vl_api_sr_steering_add_del_t_handler
  (vl_api_sr_steering_add_del_t * mp)
{
  vl_api_sr_steering_add_del_reply_t *rmp;
  int rv = 0;
/*
 * int
 * sr_steering_policy(int is_del, ip6_address_t *bsid, u32 sr_policy_index,
 *  u32 table_id, ip46_address_t *prefix, u32 mask_width, u32 sw_if_index,
 *  u8 traffic_type)
 */
  rv = sr_steering_policy (mp->is_del,
			   (ip6_address_t *) & mp->bsid_addr,
			   ntohl (mp->sr_policy_index),
			   ntohl (mp->table_id),
			   (ip46_address_t *) & mp->prefix_addr,
			   ntohl (mp->mask_width),
			   ntohl (mp->sw_if_index), mp->traffic_type);

  REPLY_MACRO (VL_API_SR_STEERING_ADD_DEL_REPLY);
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
   * Manually register the sr policy add msg, so we trace
   * enough bytes to capture a typical segment list
   */
  vl_msg_api_set_handlers (VL_API_SR_POLICY_ADD,
			   "sr_policy_add",
			   vl_api_sr_policy_add_t_handler,
			   vl_noop_handler,
			   vl_api_sr_policy_add_t_endian,
			   vl_api_sr_policy_add_t_print, 256, 1);

  /*
   * Manually register the sr policy mod msg, so we trace
   * enough bytes to capture a typical segment list
   */
  vl_msg_api_set_handlers (VL_API_SR_POLICY_MOD,
			   "sr_policy_mod",
			   vl_api_sr_policy_mod_t_handler,
			   vl_noop_handler,
			   vl_api_sr_policy_mod_t_endian,
			   vl_api_sr_policy_mod_t_print, 256, 1);

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
