/*
 *------------------------------------------------------------------
 * l2_api.c - layer 2 forwarding api
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
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_fib.h>

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

#define foreach_vpe_api_msg                                 \
_(L2_XCONNECT_DUMP, l2_xconnect_dump)                       \
_(L2_FIB_CLEAR_TABLE, l2_fib_clear_table)                   \
_(L2_FIB_TABLE_DUMP, l2_fib_table_dump)                     \
_(L2_FIB_TABLE_ENTRY, l2_fib_table_entry)                   \
_(L2_FIB_ADD_DEL, l2_fib_add_del)                           \
_(L2_FLAGS, l2_flags)                                       \
_(BRIDGE_DOMAIN_ADD_DEL, bridge_domain_add_del)             \
_(BRIDGE_DOMAIN_DUMP, bridge_domain_dump)                   \
_(BRIDGE_DOMAIN_DETAILS, bridge_domain_details)             \
_(BRIDGE_DOMAIN_SW_IF_DETAILS, bridge_domain_sw_if_details) \
_(BRIDGE_FLAGS, bridge_flags)

static void
send_l2_xconnect_details (unix_shared_memory_queue_t * q, u32 context,
			  u32 rx_sw_if_index, u32 tx_sw_if_index)
{
  vl_api_l2_xconnect_details_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_L2_XCONNECT_DETAILS);
  mp->context = context;
  mp->rx_sw_if_index = htonl (rx_sw_if_index);
  mp->tx_sw_if_index = htonl (tx_sw_if_index);

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_l2_xconnect_dump_t_handler (vl_api_l2_xconnect_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  l2input_main_t *l2im = &l2input_main;
  vnet_sw_interface_t *swif;
  l2_input_config_t *config;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* *INDENT-OFF* */
  pool_foreach (swif, im->sw_interfaces,
  ({
    config = vec_elt_at_index (l2im->configs, swif->sw_if_index);
    if (config->xconnect)
      send_l2_xconnect_details (q, mp->context, swif->sw_if_index,
                                config->output_sw_if_index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_l2_fib_clear_table_t_handler (vl_api_l2_fib_clear_table_t * mp)
{
  int rv = 0;
  vl_api_l2_fib_clear_table_reply_t *rmp;

  /* DAW-FIXME: This API should only clear non-static l2fib entries, but
   *            that is not currently implemented.  When that TODO is fixed
   *            this call should be changed to pass 1 instead of 0.
   */
  l2fib_clear_table (0);

  REPLY_MACRO (VL_API_L2_FIB_CLEAR_TABLE_REPLY);
}

static void
send_l2fib_table_entry (vpe_api_main_t * am,
			unix_shared_memory_queue_t * q,
			l2fib_entry_key_t * l2fe_key,
			l2fib_entry_result_t * l2fe_res, u32 context)
{
  vl_api_l2_fib_table_entry_t *mp;

  mp = vl_msg_api_alloc (sizeof (*mp));
  memset (mp, 0, sizeof (*mp));
  mp->_vl_msg_id = ntohs (VL_API_L2_FIB_TABLE_ENTRY);

  mp->bd_id =
    ntohl (l2input_main.bd_configs[l2fe_key->fields.bd_index].bd_id);

  mp->mac = l2fib_make_key (l2fe_key->fields.mac, 0);
  mp->sw_if_index = ntohl (l2fe_res->fields.sw_if_index);
  mp->static_mac = l2fe_res->fields.static_mac;
  mp->filter_mac = l2fe_res->fields.filter;
  mp->bvi_mac = l2fe_res->fields.bvi;
  mp->context = context;

  vl_msg_api_send_shmem (q, (u8 *) & mp);
}

static void
vl_api_l2_fib_table_entry_t_handler (vl_api_l2_fib_table_entry_t * mp)
{
  clib_warning ("BUG");
}

static void
vl_api_l2_fib_table_dump_t_handler (vl_api_l2_fib_table_dump_t * mp)
{
  vpe_api_main_t *am = &vpe_api_main;
  bd_main_t *bdm = &bd_main;
  l2fib_entry_key_t *l2fe_key = NULL;
  l2fib_entry_result_t *l2fe_res = NULL;
  u32 ni, bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  unix_shared_memory_queue_t *q;
  uword *p;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    return;

  /* see l2fib_table_dump: ~0 means "any" */
  if (bd_id == ~0)
    bd_index = ~0;
  else
    {
      p = hash_get (bdm->bd_index_by_bd_id, bd_id);
      if (p == 0)
	return;

      bd_index = p[0];
    }

  l2fib_table_dump (bd_index, &l2fe_key, &l2fe_res);

  vec_foreach_index (ni, l2fe_key)
  {
    send_l2fib_table_entry (am, q, vec_elt_at_index (l2fe_key, ni),
			    vec_elt_at_index (l2fe_res, ni), mp->context);
  }
  vec_free (l2fe_key);
  vec_free (l2fe_res);
}

static void
vl_api_l2_fib_add_del_t_handler (vl_api_l2_fib_add_del_t * mp)
{
  bd_main_t *bdm = &bd_main;
  l2input_main_t *l2im = &l2input_main;
  vl_api_l2_fib_add_del_reply_t *rmp;
  int rv = 0;
  u64 mac = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  u32 static_mac;
  u32 filter_mac;
  u32 bvi_mac;
  uword *p;

  mac = mp->mac;

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto bad_sw_if_index;
    }
  bd_index = p[0];

  if (mp->is_add)
    {
      filter_mac = mp->filter_mac ? 1 : 0;
      if (filter_mac == 0)
	{
	  VALIDATE_SW_IF_INDEX (mp);
	  if (vec_len (l2im->configs) <= sw_if_index)
	    {
	      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	      goto bad_sw_if_index;
	    }
	  else
	    {
	      l2_input_config_t *config;
	      config = vec_elt_at_index (l2im->configs, sw_if_index);
	      if (config->bridge == 0)
		{
		  rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
		  goto bad_sw_if_index;
		}
	    }
	}
      static_mac = mp->static_mac ? 1 : 0;
      bvi_mac = mp->bvi_mac ? 1 : 0;
      l2fib_add_entry (mac, bd_index, sw_if_index, static_mac, filter_mac,
		       bvi_mac);
    }
  else
    {
      l2fib_del_entry (mac, bd_index);
    }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_L2_FIB_ADD_DEL_REPLY);
}

static void
vl_api_l2_flags_t_handler (vl_api_l2_flags_t * mp)
{
  vl_api_l2_flags_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  u32 flags = ntohl (mp->feature_bitmap);
  u32 rbm = 0;

  VALIDATE_SW_IF_INDEX (mp);

#define _(a,b) \
    if (flags & L2INPUT_FEAT_ ## a) \
        rbm = l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_ ## a, mp->is_set);
  foreach_l2input_feat;
#undef _

  BAD_SW_IF_INDEX_LABEL;

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_L2_FLAGS_REPLY,
  ({
    rmp->resulting_feature_bitmap = ntohl(rbm);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_bridge_flags_t_handler (vl_api_bridge_flags_t * mp)
{
  vlib_main_t *vm = vlib_get_main ();
  bd_main_t *bdm = &bd_main;
  vl_api_bridge_flags_reply_t *rmp;
  int rv = 0;
  u32 bd_id = ntohl (mp->bd_id);
  u32 bd_index;
  u32 flags = ntohl (mp->feature_bitmap);
  uword *p;

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p == 0)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto out;
    }

  bd_index = p[0];

  bd_set_flags (vm, bd_index, flags, mp->is_set);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_BRIDGE_FLAGS_REPLY,
  ({
    rmp->resulting_feature_bitmap = ntohl(flags);
  }));
  /* *INDENT-ON* */
}

/*
 * l2_api_hookup
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
  foreach_vl_msg_name_crc_l2;
#undef _
}

static clib_error_t *
l2_api_hookup (vlib_main_t * vm)
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
   * Set up the (msg_name, crc, message-id) table
   */
  setup_message_id_table (am);

  return 0;
}

VLIB_API_INIT_FUNCTION (l2_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
