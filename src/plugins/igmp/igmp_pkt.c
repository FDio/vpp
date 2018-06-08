/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <igmp/igmp_pkt.h>

static void
vlib_buffer_append (vlib_buffer_t * b, uword l)
{
  b->current_data += l;
  b->current_length += l;
}

static vlib_buffer_t *
igmp_pkt_get_buffer (void)
{
  vlib_buffer_free_list_t *fl;
  vlib_main_t *vm;
  vlib_buffer_t *b;
  u32 bi;

  vm = vlib_get_main ();

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return (NULL);

  b = vlib_get_buffer (vm, bi);
  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
  vlib_buffer_init_for_free_list (b, fl);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->flags |= VLIB_BUFFER_IS_TRACED;

  return (b);
}

static void *
igmp_pkt_build_ip_header (vlib_buffer_t * b,
			  u32 sw_if_index,
			  igmp_msg_type_t msg_type,
			  const igmp_group_t * group)
{
  ip4_header_t *ip4;

  ip4 = vlib_buffer_get_current (b);
  memset (ip4, 0, sizeof (ip4_header_t));
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 1;
  ip4->protocol = IP_PROTOCOL_IGMP;
  ip4->tos = 0xc0;

  ip4_src_address_for_packet (&ip4_main.lookup_main,
			      sw_if_index, &ip4->src_address);

  vlib_buffer_append (b, sizeof (*ip4));

  switch (msg_type)
    {
    case IGMP_MSG_REPORT:
      ip4->dst_address.as_u32 = IGMP_MEMBERSHIP_REPORT_ADDRESS;
      break;
    case IGMP_MSG_QUERY:
      if (group != NULL)
	clib_memcpy (&ip4->dst_address, &group->key->ip4,
		     sizeof (ip4_address_t));
      else
	ip4->dst_address.as_u32 = IGMP_GENERAL_QUERY_ADDRESS;
      break;
    }

  return (vlib_buffer_get_current (b));
}

vlib_buffer_t *
igmp_pkt_build_report_v3 (u32 sw_if_index, const igmp_group_t * group)
{
  igmp_membership_report_v3_t *report;
  vlib_buffer_t *b;

  b = igmp_pkt_get_buffer ();
  igmp_pkt_build_ip_header (b, sw_if_index, IGMP_MSG_REPORT, group);

  report = vlib_buffer_get_current (b);
  report->header.type = IGMP_TYPE_membership_report_v3;
  report->header.code = 0;
  report->header.checksum = 0;
  report->unused = 0;

  vlib_buffer_append (b, sizeof (igmp_membership_report_v3_t));

  return (b);
}

static void
igmp_pkt_tx (vlib_buffer_t * b, u32 sw_if_index)
{
  const igmp_config_t *config;

  config = igmp_config_lookup (sw_if_index);

  vnet_buffer (b)->ip.adj_index[VLIB_TX] = config->adj_index;

  vlib_put_buffer_to_node (vlib_get_main (), ip4_rewrite_mcast_node.index, b);

  IGMP_DBG ("  ..tx: %U", format_vnet_sw_if_index_name,
            vnet_get_main (), sw_if_index);
}

void
igmp_pkt_send_report_v3 (vlib_buffer_t * b,
			 u32 sw_if_index, u32 n_bytes, u32 n_groups)
{
  igmp_membership_report_v3_t *igmp;
  ip4_header_t *ip4;

  b->current_data = 0;

  ip4 = vlib_buffer_get_current (b);
  igmp = (igmp_membership_report_v3_t *) (ip4 + 1);

  igmp->n_groups = clib_host_to_net_u16 (n_groups);

  igmp->header.checksum =
    ~ip_csum_fold (ip_incremental_checksum (0, igmp, n_bytes));

  ip4->length = clib_host_to_net_u16 (b->current_length);
  ip4->checksum = ip4_header_checksum (ip4);

  igmp_pkt_tx (b, sw_if_index);
}

static igmp_membership_group_v3_type_t
igmp_filter_mode_to_report_type (igmp_filter_mode_t mode)
{
  switch (mode)
    {
    case IGMP_FILTER_MODE_INCLUDE:
      return (IGMP_MEMBERSHIP_GROUP_mode_is_include);
    case IGMP_FILTER_MODE_EXCLUDE:
      return (IGMP_MEMBERSHIP_GROUP_mode_is_exclude);
    }

  return (IGMP_MEMBERSHIP_GROUP_mode_is_include);
}

u32
igmp_pkt_report_v3_add_report (vlib_buffer_t * b,
                               const ip46_address_t *grp,
                               const ip46_address_t *srcs,
                               igmp_membership_group_v3_type_t type)
{
  igmp_membership_group_v3_t *igmp_group;
  const ip46_address_t *s;
  u32 len, i;

  igmp_group = vlib_buffer_get_current (b);

  memset (igmp_group, 0, sizeof (igmp_membership_group_v3_t));
  igmp_group->type = type;
  igmp_group->n_src_addresses = vec_len(srcs);
  igmp_group->n_src_addresses =
    clib_host_to_net_u16 (igmp_group->n_src_addresses);
  igmp_group->group_address.as_u32 = grp->ip4.as_u32;
  i = 0;
  /* *INDENT-OFF* */
  vec_foreach(s, srcs)
    {
      igmp_group->src_addresses[i++].as_u32 = s->ip4.as_u32;
    };
  /* *INDENT-ON* */
  len = ((sizeof (ip4_address_t) * i) + sizeof (igmp_membership_group_v3_t));

  IGMP_DBG ("  ..add-group: %U", format_ip46_address, grp, IP46_TYPE_IP4);
  vlib_buffer_append (b, len);

  return (len);
}

static u32
igmp_pkt_report_v3_add_group (vlib_buffer_t * b,
			      const igmp_group_t * group,
			      igmp_membership_group_v3_type_t type)
{
  igmp_membership_group_v3_t *igmp_group;
  igmp_src_t *src;
  u32 len, i;

  igmp_group = vlib_buffer_get_current (b);

  memset (igmp_group, 0, sizeof (igmp_membership_group_v3_t));
  igmp_group->type = type;
  igmp_group->n_src_addresses =
    hash_elts (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE]);
  igmp_group->n_src_addresses =
    clib_host_to_net_u16 (igmp_group->n_src_addresses);
  igmp_group->group_address.as_u32 = group->key->ip4.as_u32;
  i = 0;
  /* *INDENT-OFF* */
  FOR_EACH_SRC (src, group, IGMP_FILTER_MODE_INCLUDE,
    ({
      igmp_group->src_addresses[i++].as_u32 = src->key->ip4.as_u32;
    }));
  /* *INDENT-ON* */
  len = ((sizeof (ip4_address_t) * i) + sizeof (igmp_membership_group_v3_t));

  IGMP_DBG ("  ..add-group: %U", format_igmp_key, group->key);
  vlib_buffer_append (b, len);

  return (len);
}

static u32
igmp_pkt_report_v3_get_size (igmp_group_t * group)
{
  ASSERT (IGMP_FILTER_MODE_INCLUDE == group->router_filter_mode);

  return ((hash_elts (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE]) *
	   sizeof (ip4_address_t)) + sizeof (igmp_membership_group_v3_t));
}

/**
 * Send igmp membership general report.
 */
void
igmp_send_general_report_v3 (u32 obj, void *data)
{
  igmp_config_t *config;
  igmp_group_t *group;
  igmp_main_t *im;
  vlib_buffer_t *b;
  u32 n_avail, n_max, n_g, n_groups, n_bytes;

  im = &igmp_main;
  config = pool_elt_at_index (im->configs, obj);

  ASSERT (config->timers[IGMP_CONFIG_TIMER_GENERAL_QUERY] !=
	  IGMP_TIMER_ID_INVALID);

  igmp_timer_retire (&config->timers[IGMP_CONFIG_TIMER_GENERAL_QUERY]);

  /*
   * Get the first buffer into which the report is written. Should
   * the size of this buffer grow to exceed the interface's MTU
   * then fetch another.
   */
  n_groups = n_bytes = 0;
  n_avail = n_max = vnet_sw_interface_get_mtu (vnet_get_main (),
					       config->sw_if_index,
					       VNET_MTU_IP4);
  b = igmp_pkt_build_report_v3 (config->sw_if_index, NULL);

  /* *INDENT-OFF* */
  FOR_EACH_GROUP (group, config,
    ({
      n_g = igmp_pkt_report_v3_get_size (group);

      if (n_g > n_max)
        // panic
        continue;
      if (n_g > n_avail)
        {
          /*
           * no more romm in this packet to send this group. ship
           * what we have, then send another.
           * N.B. this algo needs improving...
           *  1 - the reports should be time spaced
           *  2 - we assume all the sources can fit into one buffer
           */
          igmp_pkt_send_report_v3 (b,
                                   config->sw_if_index,
                                   n_bytes,
                                   n_groups);
          b = igmp_pkt_build_report_v3(config->sw_if_index, NULL);
          n_groups = n_bytes = 0; n_avail = n_max;
        }

      igmp_pkt_report_v3_add_group (b, group,
                                    igmp_filter_mode_to_report_type
                                    (group->router_filter_mode));
      n_avail -= n_g; n_bytes += n_g;
      n_groups++;
    }));
  /* *INDENT-ON* */

  igmp_pkt_send_report_v3 (b, config->sw_if_index, n_bytes, n_groups);
}

void
igmp_send_state_change_group_report_v3 (u32 sw_if_index,
					const igmp_group_t * group)
{
  vlib_buffer_t *b;
  u32 n_bytes;

  IGMP_DBG ("state-change-group: %U", format_igmp_key, group->key);

  b = igmp_pkt_build_report_v3 (sw_if_index, group);
  n_bytes = igmp_pkt_report_v3_add_group (b, group,
					  IGMP_MEMBERSHIP_GROUP_allow_new_sources);
  igmp_pkt_send_report_v3 (b, sw_if_index, n_bytes, 1);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
