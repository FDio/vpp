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
igmp_pkt_get_buffer (igmp_pkt_build_report_t *br)
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

  /* clear out stale data */
  vnet_buffer(b)->sw_if_index[VLIB_RX] = ~0;

  /*
   * save progress in the builder
   */
  vec_add1(br->buffers, bi);
  br->n_avail = vnet_sw_interface_get_mtu (vnet_get_main (),
                                           br->sw_if_index,
                                           VNET_MTU_IP4);

  return (b);
}

static vlib_buffer_t *
igmp_pkt_build_ip_header (igmp_pkt_build_report_t *br,
			  igmp_msg_type_t msg_type,
			  const igmp_group_t * group)
{
  ip4_header_t *ip4;
  vlib_buffer_t *b;

  b = igmp_pkt_get_buffer(br);

  if (NULL == b)
    return (NULL);

  ip4 = vlib_buffer_get_current (b);
  memset (ip4, 0, sizeof (ip4_header_t));
  ip4->ip_version_and_header_length = 0x45;
  ip4->ttl = 1;
  ip4->protocol = IP_PROTOCOL_IGMP;
  ip4->tos = 0xc0;

  ip4_src_address_for_packet (&ip4_main.lookup_main,
			      br->sw_if_index,
                              &ip4->src_address);

  vlib_buffer_append (b, sizeof (*ip4));
  br->n_avail -= sizeof (*ip4);

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

  return (b);
}

static vlib_buffer_t *
igmp_pkt_build_report_v3 (igmp_pkt_build_report_t *br,
                          const igmp_group_t * group)
{
  igmp_membership_report_v3_t *report;
  vlib_buffer_t *b;

  b = igmp_pkt_build_ip_header(br, IGMP_MSG_REPORT, group);

  if (NULL == b)
    return (NULL);

  report = vlib_buffer_get_current (b);
  report->header.type = IGMP_TYPE_membership_report_v3;
  report->header.code = 0;
  report->header.checksum = 0;
  report->unused = 0;

  vlib_buffer_append (b, sizeof (igmp_membership_report_v3_t));
  br->n_avail -= sizeof (igmp_membership_report_v3_t);
  br->n_bytes += sizeof (igmp_membership_report_v3_t);

  return (b);
}

static void
igmp_pkt_tx (igmp_pkt_build_report_t *br)
{
  const igmp_config_t *config;
  vlib_buffer_t *b;
  vlib_main_t *vm;
  vlib_frame_t *f;
  u32 *to_next;
  u32 ii;

  vm = vlib_get_main ();
  config = igmp_config_lookup (br->sw_if_index);
  f = vlib_get_frame_to_node (vm, ip4_rewrite_mcast_node.index);
  to_next = vlib_frame_vector_args (f);

  vec_foreach_index(ii, br->buffers)
    {
      b = vlib_get_buffer (vm, br->buffers[ii]);
      vnet_buffer (b)->ip.adj_index[VLIB_TX] = config->adj_index;
      to_next[ii] = br->buffers[ii];
      f->n_vectors++;
    }

  vlib_put_frame_to_node (vm, ip4_rewrite_mcast_node.index, f);

  IGMP_DBG ("  ..tx: %U", format_vnet_sw_if_index_name,
            vnet_get_main(),
            br->sw_if_index);

  vec_free(br->buffers);
}

static vlib_buffer_t *
igmp_pkt_build_report_get_active (igmp_pkt_build_report_t *br)
{
  if (NULL == br->buffers)
    return (NULL);

  return (vlib_get_buffer (vlib_get_main(),
                           br->buffers[vec_len(br->buffers) - 1]));
}
static void
igmp_pkt_build_report_bake (igmp_pkt_build_report_t *br)
{
  igmp_membership_report_v3_t *igmp;
  ip4_header_t *ip4;
  vlib_buffer_t *b;

  b = igmp_pkt_build_report_get_active(br);

  b->current_data = 0;

  ip4 = vlib_buffer_get_current (b);
  igmp = (igmp_membership_report_v3_t *) (ip4 + 1);

  igmp->n_groups = clib_host_to_net_u16 (br->n_groups);

  igmp->header.checksum =
    ~ip_csum_fold (ip_incremental_checksum (0, igmp, br->n_bytes));

  ip4->length = clib_host_to_net_u16 (b->current_length);
  ip4->checksum = ip4_header_checksum (ip4);

  br->n_bytes = br->n_avail = br->n_groups = 0;
}

void
igmp_pkt_send_report_v3 (igmp_pkt_build_report_t *br)
{
  if (NULL == br->buffers)
    return;

  igmp_pkt_build_report_bake (br);
  igmp_pkt_tx (br);
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

static u32
igmp_pkt_report_v3_get_size (const igmp_group_t * group)
{
  ASSERT (IGMP_FILTER_MODE_INCLUDE == group->router_filter_mode);

  return ((hash_elts (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE]) *
           sizeof (ip4_address_t)) + sizeof (igmp_membership_group_v3_t));
}

static igmp_membership_group_v3_t *
igmp_pkt_report_v3_append_group (igmp_pkt_build_report_t *br,
                                 const ip46_address_t *grp,
                                 igmp_membership_group_v3_type_t type)
{
  igmp_membership_group_v3_t *igmp_group;
  vlib_buffer_t *b;

  b = igmp_pkt_build_report_get_active(br);

  if (br->n_avail < sizeof(igmp_membership_group_v3_t))
    {
      igmp_pkt_build_report_bake (br);
      b = igmp_pkt_build_report_v3 (br, NULL);
      if (NULL == b)
        return (NULL);
    }
  br->n_avail -= sizeof(igmp_membership_group_v3_t);
  br->n_bytes += sizeof(igmp_membership_group_v3_t);
  br->n_groups++;
  br->n_srcs = 0;

  igmp_group = vlib_buffer_get_current (b);
  vlib_buffer_append (b, sizeof(igmp_membership_group_v3_t));

  igmp_group->type = type;
  igmp_group->n_aux_u32s = 0;
  igmp_group->n_src_addresses = 0;
  igmp_group->group_address.as_u32 = grp->ip4.as_u32;

  return (igmp_group);
}

static igmp_membership_group_v3_t *
igmp_pkt_report_v3_append_src (igmp_pkt_build_report_t *br,
                               igmp_membership_group_v3_t *igmp_group,
                               const ip46_address_t *grp,
                               igmp_membership_group_v3_type_t type,
                               const ip46_address_t *src)
{
  vlib_buffer_t *b;

  b = igmp_pkt_build_report_get_active(br);

  if (br->n_avail < sizeof(ip4_address_t))
    {
      igmp_group->n_src_addresses = clib_host_to_net_u16 (br->n_srcs);
      igmp_pkt_build_report_bake (br);
      b = igmp_pkt_build_report_v3 (br, NULL);
      if (NULL == b)
        return (NULL);
      igmp_group = igmp_pkt_report_v3_append_group(br, grp, type);
    }

  igmp_group->src_addresses[br->n_srcs].as_u32 = src->ip4.as_u32;
  br->n_srcs++;
  br->n_avail -= sizeof(ip4_address_t);
  br->n_bytes += sizeof(ip4_address_t);
  vlib_buffer_append (b, sizeof(ip4_address_t));

  return (igmp_group);
}

void
igmp_pkt_report_v3_add_report (igmp_pkt_build_report_t *br,
                               const ip46_address_t *grp,
                               const ip46_address_t *srcs,
                               igmp_membership_group_v3_type_t type)
{
  igmp_membership_group_v3_t *igmp_group;
  const ip46_address_t *s;
  vlib_buffer_t *b;

  b = igmp_pkt_build_report_get_active(br);

  if (NULL == b)
    {
      b = igmp_pkt_build_report_v3 (br, NULL);
      if (NULL == b)
        /* failed to allocate buffer */
        return;
    }

  igmp_group = igmp_pkt_report_v3_append_group(br, grp, type);

  if (NULL == igmp_group)
    return;

  /* *INDENT-OFF* */
  vec_foreach(s, srcs)
    {
      igmp_group = igmp_pkt_report_v3_append_src(br, igmp_group,
                                                 grp, type, s);
      if (NULL == igmp_group)
        return;
    };
  /* *INDENT-ON* */

  igmp_group->n_src_addresses = clib_host_to_net_u16 (br->n_srcs);

  IGMP_DBG ("  ..add-group: %U", format_ip46_address, grp, IP46_TYPE_IP4);
}

void
igmp_pkt_report_v3_add_group (igmp_pkt_build_report_t *br,
                              const igmp_group_t * group,
			      igmp_membership_group_v3_type_t type)
{
  igmp_membership_group_v3_t *igmp_group;
  vlib_buffer_t *b;
  igmp_src_t *src;

  b = igmp_pkt_build_report_get_active(br);

  if (NULL == b)
    {
      b = igmp_pkt_build_report_v3 (br, NULL);
      if (NULL == b)
        /* failed to allocate buffer */
        return;
    }

  /*
   * if the group won't fit in a partially full buffer, start again
   */
  if ((0 != br->n_groups) &&
      (igmp_pkt_report_v3_get_size (group) > br->n_avail))
    {
      igmp_pkt_build_report_bake (br);
      b = igmp_pkt_build_report_v3 (br, NULL);
      if (NULL == b)
        /* failed to allocate buffer */
        return;
    }

  igmp_group = igmp_pkt_report_v3_append_group(br, group->key, type);
  
  /* *INDENT-OFF* */
  FOR_EACH_SRC (src, group, IGMP_FILTER_MODE_INCLUDE,
    ({
      igmp_group = igmp_pkt_report_v3_append_src(br, igmp_group,
                                                 group->key, type,
                                                 src->key);
      if (NULL == igmp_group)
        return;
    }));
  /* *INDENT-ON* */
  igmp_group->n_src_addresses = clib_host_to_net_u16 (br->n_srcs);

  IGMP_DBG ("  ..add-group: %U srcs:%d",
            format_igmp_key, group->key,
            hash_elts (group->igmp_src_by_key[IGMP_FILTER_MODE_INCLUDE]));
}

/**
 * Send igmp membership general report.
 
 * 4.2.16
 "   If the set of Group Records required in a Report does not fit within
 *   the size limit of a single Report message (as determined by the MTU
 *   of the network on which it will be sent), the Group Records are sent
 *   in as many Report messages as needed to report the entire set.

 *   If a single Group Record contains so many source addresses that it
 *   does not fit within the size limit of a single Report message, if its
 *   Type is not MODE_IS_EXCLUDE or CHANGE_TO_EXCLUDE_MODE, it is split
 *   into multiple Group Records, each containing a different subset of
 *   the source addresses and each sent in a separate Report message.  If
 *   its Type is MODE_IS_EXCLUDE or CHANGE_TO_EXCLUDE_MODE, a single Group
 *   Record is sent, containing as many source addresses as can fit, and
 *  the remaining source addresses are not reported; though the choice of
 *   which sources to report is arbitrary, it is preferable to report the
 *  same set of sources in each subsequent report, rather than reporting
 *  different sources each time."
  */
void
igmp_pkt_send_general_report_v3 (const igmp_config_t *config)
{
  igmp_group_t *group;

  igmp_pkt_build_report_t br = {
    .sw_if_index = config->sw_if_index,
  };


  /* *INDENT-OFF* */
  FOR_EACH_GROUP (group, config,
    ({
      igmp_pkt_report_v3_add_group
        (&br, group,
         igmp_filter_mode_to_report_type(group->router_filter_mode));
    }));
  /* *INDENT-ON* */

  igmp_pkt_send_report_v3 (&br);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
