/*
 *------------------------------------------------------------------
 * map_api.c - vnet map api
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

#include "map.h"
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>
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

#define foreach_vpe_api_msg			\
_(MAP_ADD_DOMAIN, map_add_domain)		\
_(MAP_DEL_DOMAIN, map_del_domain)		\
_(MAP_ADD_DEL_RULE, map_add_del_rule)		\
_(MAP_DOMAIN_DUMP, map_domain_dump)		\
_(MAP_RULE_DUMP, map_rule_dump)			\
_(MAP_SUMMARY_STATS, map_summary_stats)

static void
vl_api_map_add_domain_t_handler (vl_api_map_add_domain_t * mp)
{
  vl_api_map_add_domain_reply_t *rmp;
  int rv = 0;
  u32 index;
  u8 flags = mp->is_translation ? MAP_DOMAIN_TRANSLATION : 0;
  rv =
    map_create_domain ((ip4_address_t *) & mp->ip4_prefix, mp->ip4_prefix_len,
		       (ip6_address_t *) & mp->ip6_prefix, mp->ip6_prefix_len,
		       (ip6_address_t *) & mp->ip6_src,
		       mp->ip6_src_prefix_len, mp->ea_bits_len,
		       mp->psid_offset, mp->psid_length, &index,
		       ntohs (mp->mtu), flags);

  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_MAP_ADD_DOMAIN_REPLY,
  ({
    rmp->index = ntohl(index);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_map_del_domain_t_handler (vl_api_map_del_domain_t * mp)
{
  vl_api_map_del_domain_reply_t *rmp;
  int rv = 0;

  rv = map_delete_domain (ntohl (mp->index));

  REPLY_MACRO (VL_API_MAP_DEL_DOMAIN_REPLY);
}

static void
vl_api_map_add_del_rule_t_handler (vl_api_map_add_del_rule_t * mp)
{
  vl_api_map_del_domain_reply_t *rmp;
  int rv = 0;

  rv =
    map_add_del_psid (ntohl (mp->index), ntohs (mp->psid),
		      (ip6_address_t *) mp->ip6_dst, mp->is_add);

  REPLY_MACRO (VL_API_MAP_ADD_DEL_RULE_REPLY);
}

static void
vl_api_map_domain_dump_t_handler (vl_api_map_domain_dump_t * mp)
{
  vl_api_map_domain_details_t *rmp;
  map_main_t *mm = &map_main;
  map_domain_t *d;
  unix_shared_memory_queue_t *q;

  if (pool_elts (mm->domains) == 0)
    return;

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  /* *INDENT-OFF* */
  pool_foreach(d, mm->domains,
  ({
    /* Make sure every field is initiated (or don't skip the memset()) */
    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = ntohs(VL_API_MAP_DOMAIN_DETAILS);
    rmp->domain_index = htonl(d - mm->domains);
    rmp->ea_bits_len = d->ea_bits_len;
    rmp->psid_offset = d->psid_offset;
    rmp->psid_length = d->psid_length;
    clib_memcpy(rmp->ip4_prefix, &d->ip4_prefix, sizeof(rmp->ip4_prefix));
    rmp->ip4_prefix_len = d->ip4_prefix_len;
    clib_memcpy(rmp->ip6_prefix, &d->ip6_prefix, sizeof(rmp->ip6_prefix));
    rmp->ip6_prefix_len = d->ip6_prefix_len;
    clib_memcpy(rmp->ip6_src, &d->ip6_src, sizeof(rmp->ip6_src));
    rmp->ip6_src_len = d->ip6_src_len;
    rmp->mtu = htons(d->mtu);
    rmp->is_translation = (d->flags & MAP_DOMAIN_TRANSLATION);
    rmp->context = mp->context;

    vl_msg_api_send_shmem (q, (u8 *)&rmp);
  }));
  /* *INDENT-ON* */
}

static void
vl_api_map_rule_dump_t_handler (vl_api_map_rule_dump_t * mp)
{
  unix_shared_memory_queue_t *q;
  u16 i;
  ip6_address_t dst;
  vl_api_map_rule_details_t *rmp;
  map_main_t *mm = &map_main;
  u32 domain_index = ntohl (mp->domain_index);
  map_domain_t *d;

  if (pool_elts (mm->domains) == 0)
    return;

  d = pool_elt_at_index (mm->domains, domain_index);
  if (!d || !d->rules)
    {
      return;
    }

  q = vl_api_client_index_to_input_queue (mp->client_index);
  if (q == 0)
    {
      return;
    }

  for (i = 0; i < (0x1 << d->psid_length); i++)
    {
      dst = d->rules[i];
      if (dst.as_u64[0] == 0 && dst.as_u64[1] == 0)
	{
	  continue;
	}
      rmp = vl_msg_api_alloc (sizeof (*rmp));
      memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id = ntohs (VL_API_MAP_RULE_DETAILS);
      rmp->psid = htons (i);
      clib_memcpy (rmp->ip6_dst, &dst, sizeof (rmp->ip6_dst));
      rmp->context = mp->context;
      vl_msg_api_send_shmem (q, (u8 *) & rmp);
    }
}

static void
vl_api_map_summary_stats_t_handler (vl_api_map_summary_stats_t * mp)
{
  vl_api_map_summary_stats_reply_t *rmp;
  vlib_combined_counter_main_t *cm;
  vlib_counter_t v;
  int i, which;
  u64 total_pkts[VLIB_N_RX_TX];
  u64 total_bytes[VLIB_N_RX_TX];
  map_main_t *mm = &map_main;
  unix_shared_memory_queue_t *q =
    vl_api_client_index_to_input_queue (mp->client_index);

  if (!q)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_MAP_SUMMARY_STATS_REPLY);
  rmp->context = mp->context;
  rmp->retval = 0;

  if (pool_elts (mm->domains) == 0)
    {
      rmp->retval = -1;
      goto out;
    }

  memset (total_pkts, 0, sizeof (total_pkts));
  memset (total_bytes, 0, sizeof (total_bytes));

  map_domain_counter_lock (mm);
  vec_foreach (cm, mm->domain_counters)
  {
    which = cm - mm->domain_counters;

    for (i = 0; i < vlib_combined_counter_n_counters (cm); i++)
      {
	vlib_get_combined_counter (cm, i, &v);
	total_pkts[which] += v.packets;
	total_bytes[which] += v.bytes;
      }
  }

  map_domain_counter_unlock (mm);

  /* Note: in network byte order! */
  rmp->total_pkts[MAP_DOMAIN_COUNTER_RX] =
    clib_host_to_net_u64 (total_pkts[MAP_DOMAIN_COUNTER_RX]);
  rmp->total_bytes[MAP_DOMAIN_COUNTER_RX] =
    clib_host_to_net_u64 (total_bytes[MAP_DOMAIN_COUNTER_RX]);
  rmp->total_pkts[MAP_DOMAIN_COUNTER_TX] =
    clib_host_to_net_u64 (total_pkts[MAP_DOMAIN_COUNTER_TX]);
  rmp->total_bytes[MAP_DOMAIN_COUNTER_TX] =
    clib_host_to_net_u64 (total_bytes[MAP_DOMAIN_COUNTER_TX]);
  rmp->total_bindings = clib_host_to_net_u64 (pool_elts (mm->domains));
  rmp->total_ip4_fragments = 0;	// Not yet implemented. Should be a simple counter.
  rmp->total_security_check[MAP_DOMAIN_COUNTER_TX] =
    clib_host_to_net_u64 (map_error_counter_get
			  (ip4_map_node.index, MAP_ERROR_ENCAP_SEC_CHECK));
  rmp->total_security_check[MAP_DOMAIN_COUNTER_RX] =
    clib_host_to_net_u64 (map_error_counter_get
			  (ip4_map_node.index, MAP_ERROR_DECAP_SEC_CHECK));

out:
  vl_msg_api_send_shmem (q, (u8 *) & rmp);
}

/*
 * vpe_api_hookup
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
  foreach_vl_msg_name_crc_map;
#undef _
}

static clib_error_t *
map_api_hookup (vlib_main_t * vm)
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

VLIB_API_INIT_FUNCTION (map_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
