/*
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
 */
#include <vnet/ip/ip.h>

typedef struct {
  u32 ranges_per_adjacency;
  u32 special_adjacency_format_function_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} source_range_check_main_t;

source_range_check_main_t source_range_check_main;

vlib_node_registration_t ip4_source_port_and_range_check;

typedef struct {
  union {
    u16x8 as_u16x8;
    u16 as_u16[8];
  };
} u16x8vec_t;

typedef struct {
  u16x8vec_t low;
  u16x8vec_t hi;
} port_range_t;

#define foreach_ip4_source_and_port_range_check_error		\
_(CHECK_FAIL, "ip4 source and port range check bad packets")	\
_(CHECK_OK, "ip4 source and port range check good packets")

typedef enum {
#define _(sym,str) IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_##sym,
  foreach_ip4_source_and_port_range_check_error
#undef _
  IP4_SOURCE_AND_PORT_RANGE_CHECK_N_ERROR,
} ip4_source_and_port_range_check_error_t;

static char * ip4_source_and_port_range_check_error_strings[] = {
#define _(sym,string) string,
  foreach_ip4_source_and_port_range_check_error
#undef _
};

typedef struct {
  u32 pass;
  u32 bypass;
  u32 is_tcp;
  ip4_address_t src_addr;
  u16 dst_port;
} ip4_source_and_port_range_check_trace_t;

static u8 * format_ip4_source_and_port_range_check_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  ip4_source_and_port_range_check_trace_t * t =
    va_arg (*va, ip4_source_and_port_range_check_trace_t *);

  if (t->bypass)
    s = format (s, "PASS (bypass case)");
  else
    s = format (s, "src ip %U %s dst port %d: %s",
        format_ip4_address, &t->src_addr, t->is_tcp ? "TCP" : "UDP",
        (u32) t->dst_port,
        (t->pass == 1) ? "PASS" : "FAIL");
  return s;
}

typedef enum {
  IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP,
  IP4_SOURCE_AND_PORT_RANGE_CHECK_N_NEXT,
} ip4_source_and_port_range_check_next_t;

typedef union {
  u32 fib_index;
} ip4_source_and_port_range_check_config_t;

static inline u32 check_adj_port_range_x1 (ip_adjacency_t * adj,
                                           u16 dst_port,
                                           u32 next)
{
  port_range_t *range;
  u16x8vec_t key;
  u16x8vec_t diff1;
  u16x8vec_t diff2;
  u16x8vec_t sum, sum_equal_diff2;
  u16 sum_nonzero, sum_equal, winner_mask;
  int i;
  u8 * rwh;

  if (adj->lookup_next_index != IP_LOOKUP_NEXT_ICMP_ERROR || dst_port == 0)
    return IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP;

  rwh = (u8 *)(&adj->rewrite_header);
  range = (port_range_t *)rwh;

  /* Make the obvious screw-case work. A variant also works w/ no MMX */
  if (PREDICT_FALSE(dst_port == 65535))
    {
      int j;

      for (i = 0; i < VLIB_BUFFER_PRE_DATA_SIZE / sizeof(port_range_t); i++)
        {
          for (j = 0; j < 8; j++)
            if (range->low.as_u16x8[j] == 65535)
              return next;
          range++;
        }
      return IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP;
    }

  key.as_u16x8 = u16x8_splat (dst_port);

  for (i = 0; i < VLIB_BUFFER_PRE_DATA_SIZE / sizeof(port_range_t); i++)
    {
      diff1.as_u16x8 = u16x8_sub_saturate (range->low.as_u16x8, key.as_u16x8);
      diff2.as_u16x8 = u16x8_sub_saturate (range->hi.as_u16x8, key.as_u16x8);
      sum.as_u16x8 = u16x8_add (diff1.as_u16x8, diff2.as_u16x8);
      sum_equal_diff2.as_u16x8 = u16x8_is_equal (sum.as_u16x8, diff2.as_u16x8);
      sum_nonzero = ~u16x8_zero_byte_mask (sum.as_u16x8);
      sum_equal = ~u16x8_zero_byte_mask (sum_equal_diff2.as_u16x8);
      winner_mask = sum_nonzero & sum_equal;
      if (winner_mask)
        return next;
      range++;
    }
  return IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP;
}

always_inline uword
ip4_source_and_port_range_check_inline
(vlib_main_t * vm, vlib_node_runtime_t * node,
 vlib_frame_t * frame)
{
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_config_main_t * cm = &lm->rx_config_mains[VNET_UNICAST];
  u32 n_left_from, * from, * to_next;
  u32 next_index;
  vlib_node_runtime_t * error_node = node;
  u32 good_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
               to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
    {
          vlib_buffer_t * b0, * b1;
      ip4_header_t * ip0, * ip1;
      ip4_fib_mtrie_t * mtrie0, * mtrie1;
      ip4_fib_mtrie_leaf_t leaf0, leaf1;
      ip4_source_and_port_range_check_config_t * c0, * c1;
      ip_adjacency_t * adj0, * adj1;
      u32 bi0, next0, adj_index0, pass0, save_next0;
      u32 bi1, next1, adj_index1, pass1, save_next1;
          udp_header_t * udp0, * udp1;

      /* Prefetch next iteration. */
      {
        vlib_buffer_t * p2, * p3;

        p2 = vlib_get_buffer (vm, from[2]);
        p3 = vlib_get_buffer (vm, from[3]);

        vlib_prefetch_buffer_header (p2, LOAD);
        vlib_prefetch_buffer_header (p3, LOAD);

        CLIB_PREFETCH (p2->data, sizeof (ip0[0]), LOAD);
        CLIB_PREFETCH (p3->data, sizeof (ip1[0]), LOAD);
      }

      bi0 = to_next[0] = from[0];
      bi1 = to_next[1] = from[1];
      from += 2;
      to_next += 2;
      n_left_from -= 2;
      n_left_to_next -= 2;

      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);

      ip0 = vlib_buffer_get_current (b0);
      ip1 = vlib_buffer_get_current (b1);

      c0 = vnet_get_config_data (&cm->config_main,
                     &b0->current_config_index,
                     &next0,
                     sizeof (c0[0]));
      c1 = vnet_get_config_data (&cm->config_main,
                     &b1->current_config_index,
                     &next1,
                     sizeof (c1[0]));

          /* we can't use the default VRF here... */
          ASSERT (c0->fib_index && c1->fib_index);

      mtrie0 = &vec_elt_at_index (im->fibs, c0->fib_index)->mtrie;
      mtrie1 = &vec_elt_at_index (im->fibs, c1->fib_index)->mtrie;

      leaf0 = leaf1 = IP4_FIB_MTRIE_LEAF_ROOT;

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0,
                                             &ip0->src_address, 0);
      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1,
                                             &ip1->src_address, 0);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0,
                                             &ip0->src_address, 1);
      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1,
                                             &ip1->src_address, 1);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0,
                                             &ip0->src_address, 2);
      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1,
                                             &ip1->src_address, 2);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0,
                                             &ip0->src_address, 3);
      leaf1 = ip4_fib_mtrie_lookup_step (mtrie1, leaf1,
                                             &ip1->src_address, 3);

      adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);
      adj_index1 = ip4_fib_mtrie_leaf_get_adj_index (leaf1);

      ASSERT (adj_index0 == ip4_fib_lookup_with_table (im, c0->fib_index,
                               &ip0->src_address,
                                                           0 /* use dflt rt */));

      ASSERT (adj_index1 == ip4_fib_lookup_with_table (im, c1->fib_index,
                               &ip1->src_address,
                               0));
      adj0 = ip_get_adjacency (lm, adj_index0);
      adj1 = ip_get_adjacency (lm, adj_index1);

          pass0 = 0;
          pass0 |= ip4_address_is_multicast (&ip0->src_address);
          pass0 |= ip0->src_address.as_u32 == clib_host_to_net_u32(0xFFFFFFFF);
          pass0 |= (ip0->protocol != IP_PROTOCOL_UDP) &&
        (ip0->protocol != IP_PROTOCOL_TCP);

          pass1 = 0;
          pass1 |= ip4_address_is_multicast (&ip1->src_address);
          pass1 |= ip1->src_address.as_u32 == clib_host_to_net_u32(0xFFFFFFFF);
          pass1 |= (ip1->protocol != IP_PROTOCOL_UDP) &&
        (ip1->protocol != IP_PROTOCOL_TCP);

      save_next0 = next0;
      udp0 = ip4_next_header (ip0);
      save_next1 = next1;
      udp1 = ip4_next_header (ip1);

          if (PREDICT_TRUE(pass0 == 0))
            {
          good_packets ++;
              next0 = check_adj_port_range_x1
                (adj0, clib_net_to_host_u16(udp0->dst_port), next0);
          good_packets -= (save_next0 != next0);
              b0->error = error_node->errors
                [IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_CHECK_FAIL];
            }

          if (PREDICT_TRUE(pass1 == 0))
            {
          good_packets ++;
              next1 = check_adj_port_range_x1
                (adj1, clib_net_to_host_u16(udp1->dst_port), next1);
          good_packets -= (save_next1 != next1);
              b1->error = error_node->errors
                [IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_CHECK_FAIL];
            }

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            ip4_source_and_port_range_check_trace_t * t =
          vlib_add_trace (vm, node, b0, sizeof (*t));
            t->pass = next0 == save_next0;
        t->bypass = pass0;
        t->src_addr.as_u32 = ip0->src_address.as_u32;
        t->dst_port = (pass0 == 0) ?
          clib_net_to_host_u16(udp0->dst_port) : 0;
        t->is_tcp = ip0->protocol == IP_PROTOCOL_TCP;
            }

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b1->flags & VLIB_BUFFER_IS_TRACED))) {
            ip4_source_and_port_range_check_trace_t * t =
          vlib_add_trace (vm, node, b1, sizeof (*t));
            t->pass = next1 == save_next1;
        t->bypass = pass1;
        t->src_addr.as_u32 = ip1->src_address.as_u32;
        t->dst_port = (pass1 == 0) ?
          clib_net_to_host_u16(udp1->dst_port) : 0;
        t->is_tcp = ip1->protocol == IP_PROTOCOL_TCP;
            }

      vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                       to_next, n_left_to_next,
                       bi0, bi1, next0, next1);
    }

      while (n_left_from > 0 && n_left_to_next > 0)
    {
      vlib_buffer_t * b0;
      ip4_header_t * ip0;
      ip4_fib_mtrie_t * mtrie0;
      ip4_fib_mtrie_leaf_t leaf0;
      ip4_source_and_port_range_check_config_t * c0;
      ip_adjacency_t * adj0;
      u32 bi0, next0, adj_index0, pass0, save_next0;
          udp_header_t * udp0;

      bi0 = from[0];
      to_next[0] = bi0;
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      ip0 = vlib_buffer_get_current (b0);

      c0 = vnet_get_config_data
            (&cm->config_main, &b0->current_config_index,
             &next0,
             sizeof (c0[0]));

          /* we can't use the default VRF here... */
          ASSERT(c0->fib_index);

      mtrie0 = &vec_elt_at_index (im->fibs, c0->fib_index)->mtrie;

      leaf0 = IP4_FIB_MTRIE_LEAF_ROOT;

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0,
                                             &ip0->src_address, 0);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0,
                                             &ip0->src_address, 1);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0,
                                             &ip0->src_address, 2);

      leaf0 = ip4_fib_mtrie_lookup_step (mtrie0, leaf0,
                                             &ip0->src_address, 3);

      adj_index0 = ip4_fib_mtrie_leaf_get_adj_index (leaf0);

      ASSERT (adj_index0 == ip4_fib_lookup_with_table
                  (im, c0->fib_index,
                   &ip0->src_address,
                   0 /* use default route */));
          adj0 = ip_get_adjacency (lm, adj_index0);

      /*
       * $$$ which (src,dst) categories should we always pass?
       */
          pass0 = 0;
          pass0 |= ip4_address_is_multicast (&ip0->src_address);
          pass0 |= ip0->src_address.as_u32 == clib_host_to_net_u32(0xFFFFFFFF);
          pass0 |= (ip0->protocol != IP_PROTOCOL_UDP) &&
        (ip0->protocol != IP_PROTOCOL_TCP);

      save_next0 = next0;
      udp0 = ip4_next_header (ip0);

          if (PREDICT_TRUE(pass0 == 0))
            {
          good_packets ++;
              next0 = check_adj_port_range_x1
                (adj0, clib_net_to_host_u16(udp0->dst_port), next0);
          good_packets -= (save_next0 != next0);
              b0->error = error_node->errors
                [IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_CHECK_FAIL];
            }

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            ip4_source_and_port_range_check_trace_t * t =
          vlib_add_trace (vm, node, b0, sizeof (*t));
            t->pass = next0 == save_next0;
        t->bypass = pass0;
        t->src_addr.as_u32 = ip0->src_address.as_u32;
        t->dst_port = (pass0 == 0) ?
          clib_net_to_host_u16(udp0->dst_port) : 0;
        t->is_tcp = ip0->protocol == IP_PROTOCOL_TCP;
            }

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                       to_next, n_left_to_next,
                       bi0, next0);
    }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ip4_source_port_and_range_check.index,
                   IP4_SOURCE_AND_PORT_RANGE_CHECK_ERROR_CHECK_OK,
                   good_packets);
  return frame->n_vectors;
}

static uword
ip4_source_and_port_range_check (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  return ip4_source_and_port_range_check_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (ip4_source_port_and_range_check) = {
  .function = ip4_source_and_port_range_check,
  .name = "ip4-source-and-port-range-check",
  .vector_size = sizeof (u32),

  .n_errors = ARRAY_LEN(ip4_source_and_port_range_check_error_strings),
  .error_strings = ip4_source_and_port_range_check_error_strings,

  .n_next_nodes = IP4_SOURCE_AND_PORT_RANGE_CHECK_N_NEXT,
  .next_nodes = {
    [IP4_SOURCE_AND_PORT_RANGE_CHECK_NEXT_DROP] = "error-drop",
  },

  .format_buffer = format_ip4_header,
  .format_trace = format_ip4_source_and_port_range_check_trace,
};

int set_ip_source_and_port_range_check (vlib_main_t * vm,
                                        u32 fib_index,
                                        u32 sw_if_index,
                                        u32 is_add)
{
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_config_main_t * rx_cm = &lm->rx_config_mains[VNET_UNICAST];
  u32 ci;
  ip4_source_and_port_range_check_config_t config;
  u32 feature_index;
  int rv = 0;
  u8 is_del = !is_add;

  config.fib_index = fib_index;
  feature_index = im->ip4_unicast_rx_feature_source_and_port_range_check;

  vec_validate (rx_cm->config_index_by_sw_if_index, sw_if_index);

  ci = rx_cm->config_index_by_sw_if_index[sw_if_index];
  ci = (is_del
    ? vnet_config_del_feature
    : vnet_config_add_feature)
    (vm, &rx_cm->config_main,
     ci,
     feature_index,
     &config,
     sizeof (config));
  rx_cm->config_index_by_sw_if_index[sw_if_index] = ci;

  return rv;
}

static clib_error_t *
set_ip_source_and_port_range_check_fn (vlib_main_t * vm,
             unformat_input_t * input,
             vlib_cli_command_t * cmd)
{
  vnet_main_t * vnm = vnet_get_main();
  ip4_main_t * im = &ip4_main;
  clib_error_t * error = 0;
  u32 is_add = 1;
  u32 sw_if_index = ~0;
  u32 vrf_id = ~0;
  u32 fib_index;
  uword * p;
  int rv = 0;

  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface, vnm,
            &sw_if_index))
	;
      else if (unformat (input, "vrf %d", &vrf_id))
	;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Interface required but not specified");

  if (vrf_id == ~0)
    return clib_error_return (0, "VRF ID required but not specified");

  if (vrf_id == 0)
    return clib_error_return (0, "VRF ID should not be default. Should be distinct VRF for this purpose. ");

  p = hash_get (im->fib_index_by_table_id, vrf_id);

  if (p == 0)
    return clib_error_return (0, "Invalid VRF ID %d", vrf_id);

  fib_index = p[0];
  rv = set_ip_source_and_port_range_check (vm, fib_index, sw_if_index, is_add);

  switch(rv)
    {
    case 0:
      break;

    default:
      return clib_error_return
        (0, "set source and port-range on interface returned an unexpected value: %d", rv);
    }
  return error;
}

VLIB_CLI_COMMAND (set_interface_ip_source_and_port_range_check_command,
                  static) = {
  .path = "set interface ip source-and-port-range-check",
  .function = set_ip_source_and_port_range_check_fn,
  .short_help = "set int ip source-and-port-range-check <intfc> vrf <n> [del]",
};

static u8 * format_source_and_port_rc_adjacency (u8 * s, va_list * args)
{
  CLIB_UNUSED (vnet_main_t * vnm) = va_arg (*args, vnet_main_t *);
  ip_lookup_main_t * lm = va_arg (*args, ip_lookup_main_t *);
  u32 adj_index = va_arg (*args, u32);
  ip_adjacency_t * adj = ip_get_adjacency (lm, adj_index);
  source_range_check_main_t * srm = &source_range_check_main;
  u8 * rwh = (u8 *) (&adj->rewrite_header);
  port_range_t * range;
  int i, j;
  int printed = 0;

  range = (port_range_t *) rwh;

  s = format (s, "allow ");

  for (i = 0; i < srm->ranges_per_adjacency; i++)
    {
      for (j = 0; j < 8; j++)
        {
          if (range->low.as_u16[j])
            {
              if (printed)
                s = format (s, ", ");
              if (range->hi.as_u16[j] > (range->low.as_u16[j] + 1))
                s = format (s, "%d-%d", (u32) range->low.as_u16[j],
                            (u32) range->hi.as_u16[j] - 1);
              else
                s = format (s, "%d", range->low.as_u16[j]);
              printed = 1;
            }
        }
      range++;
    }
  return s;
}

clib_error_t * ip4_source_and_port_range_check_init (vlib_main_t * vm)
{
  source_range_check_main_t * srm = &source_range_check_main;
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;

  srm->vlib_main = vm;
  srm->vnet_main = vnet_get_main();

  srm->ranges_per_adjacency = VLIB_BUFFER_PRE_DATA_SIZE / (2*sizeof(u16x8));
  srm->special_adjacency_format_function_index =
      vnet_register_special_adjacency_format_function
      (lm, format_source_and_port_rc_adjacency);
  ASSERT (srm->special_adjacency_format_function_index);

  return 0;
}

VLIB_INIT_FUNCTION (ip4_source_and_port_range_check_init);


int ip4_source_and_port_range_check_add_del
(ip4_address_t * address, u32 length, u32 vrf_id, u16 * low_ports,
 u16 * hi_ports, int is_add)
{
  source_range_check_main_t * srm = &source_range_check_main;
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  uword * p;
  u32 fib_index;
  u32 adj_index;
  ip_adjacency_t * adj;
  int i, j, k;
  port_range_t * range;
  u8 *rwh;

  p = hash_get (im->fib_index_by_table_id, vrf_id);
  if (!p)
    {
      ip4_fib_t * f;
      f = find_ip4_fib_by_table_index_or_id (im, vrf_id, 0 /* flags */);
      fib_index = f->index;
    }
  else
    fib_index = p[0];

  adj_index = ip4_fib_lookup_with_table
    (im, fib_index, address, 0 /* disable_default_route */);

  if (is_add == 0)
    {
      adj = ip_get_adjacency (lm, adj_index);
      if (adj->lookup_next_index != IP_LOOKUP_NEXT_ICMP_ERROR)
        return VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE;

      rwh = (u8 *)(&adj->rewrite_header);

      for (i = 0; i < vec_len (low_ports); i++)
        {
          range = (port_range_t *) rwh;
          for (j = 0; j < srm->ranges_per_adjacency; j++)
            {
              for (k = 0; k < 8; k++)
                {
                  if (low_ports[i] == range->low.as_u16[k] &&
                      hi_ports[i] == range->hi.as_u16[k])
                    {
                      range->low.as_u16[k] = range->hi.as_u16[k] = 0;
                      goto doublebreak;
                    }
                }
              range++;
            }
        doublebreak: ;
        }

      range = (port_range_t *) rwh;
      /* Have we deleted all ranges yet? */
      for (i = 0; i < srm->ranges_per_adjacency; i++)
        {
          for (j = 0; j < 8; j++)
            {
              if (range->low.as_u16[i] != 0)
                goto still_occupied;
            }
          range++;
        }
      /* Yes, lose the adjacency... */
      {
    ip4_add_del_route_args_t a;

        memset (&a, 0, sizeof(a));
        a.flags = IP4_ROUTE_FLAG_FIB_INDEX | IP4_ROUTE_FLAG_DEL;
        a.table_index_or_table_id = fib_index;
        a.dst_address = address[0];
        a.dst_address_length = length;
        a.adj_index = adj_index;
        ip4_add_del_route (im, &a);
      }

    still_occupied:
      ;
    }
  else
    {
      adj = ip_get_adjacency (lm, adj_index);
      /* $$$$ fixme: add ports if address + mask match */
      if (adj->lookup_next_index == IP_LOOKUP_NEXT_ICMP_ERROR)
        return VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE;

      {
        ip_adjacency_t template_adj;
        ip4_add_del_route_args_t a;

        memset (&template_adj, 0, sizeof (template_adj));

        template_adj.lookup_next_index = IP_LOOKUP_NEXT_ICMP_ERROR;
        template_adj.if_address_index = ~0;
        template_adj.special_adjacency_format_function_index =
          srm->special_adjacency_format_function_index;

        rwh = (u8 *) (&template_adj.rewrite_header);

        range = (port_range_t *) rwh;

        if (vec_len (low_ports) > 8 * srm->ranges_per_adjacency)
          return VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY;

        j = k = 0;

        for (i = 0; i < vec_len (low_ports); i++)
          {
            for (; j < srm->ranges_per_adjacency; j++)
              {
                for (; k < 8; k++)
                  {
                    if (range->low.as_u16[k] == 0)
                      {
                        range->low.as_u16[k] = low_ports[i];
                        range->hi.as_u16[k] = hi_ports[i];
                        k++;
                        if (k == 7)
                          {
                            k = 0;
                            j++;
                          }
                        goto doublebreak2;
                      }
                  }
                k = 0;
                range++;
              }
            j = 0;
            /* Too many ports specified... */
            return VNET_API_ERROR_EXCEEDED_NUMBER_OF_PORTS_CAPACITY;

          doublebreak2: ;
          }

        memset (&a, 0, sizeof(a));
        a.flags = IP4_ROUTE_FLAG_FIB_INDEX;
        a.table_index_or_table_id = fib_index;
        a.dst_address = address[0];
        a.dst_address_length = length;
        a.add_adj = &template_adj;
        a.n_add_adj = 1;

        ip4_add_del_route (im, &a);
      }
    }

  return 0;
}

static clib_error_t *
ip_source_and_port_range_check_command_fn (vlib_main_t * vm,
                                           unformat_input_t * input,
                                           vlib_cli_command_t * cmd)
{
  u16 * low_ports = 0;
  u16 * high_ports = 0;
  u16 this_low;
  u16 this_hi;
  ip4_address_t addr;
  u32 length;
  u32 tmp, tmp2;
  u8 prefix_set = 0;
  u32 vrf_id = ~0;
  int is_add = 1;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U/%d", unformat_ip4_address, &addr, &length))
        prefix_set = 1;
      else if (unformat (input, "vrf %d", &vrf_id))
        ;
      else if (unformat (input, "del"))
        is_add = 0;
      else if (unformat (input, "port %d", &tmp))
        {
          if (tmp == 0 || tmp > 65535)
            return clib_error_return (0, "port %d out of range", tmp);
          this_low = tmp;
          this_hi = this_low + 1;
          vec_add1 (low_ports, this_low);
          vec_add1 (high_ports, this_hi);
        }
      else if (unformat (input, "range %d - %d", &tmp, &tmp2))
        {
          if (tmp > tmp2)
            return clib_error_return (0, "ports %d and %d out of order",
                                      tmp, tmp2);
          if (tmp == 0 || tmp > 65535)
            return clib_error_return (0, "low port %d out of range", tmp);
          if (tmp2 == 0 || tmp2 > 65535)
            return clib_error_return (0, "hi port %d out of range", tmp2);
          this_low = tmp;
          this_hi = tmp2+1;
          vec_add1 (low_ports, this_low);
          vec_add1 (high_ports, this_hi);
        }
      else
        break;
    }

  if (prefix_set == 0)
    return clib_error_return (0, "<address>/<mask> not specified");

  if (vrf_id == ~0)
    return clib_error_return (0, "VRF ID required, not specified");

  if (vrf_id == 0)
    return clib_error_return (0, "VRF ID should not be default. Should be distinct VRF for this purpose. ");

  if (vec_len(low_ports) == 0)
    return clib_error_return (0, "At least one port or port range required");

  rv = ip4_source_and_port_range_check_add_del
    (&addr, length, vrf_id, low_ports, high_ports, is_add);

  switch(rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE:
      return clib_error_return
        (0, "Incorrect adjacency for add/del operation in ip4 source and port-range check.");

    case VNET_API_ERROR_EXCEEDED_NUMBER_OF_PORTS_CAPACITY:
      return clib_error_return
        (0, "Too many ports in add/del operation in ip4 source and port-range check.");

    case VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY:
      return clib_error_return
        (0, "Too many ranges requested for add operation in ip4 source and port-range check.");

    default:
      return clib_error_return
        (0, "ip4_source_and_port_range_check_add returned an unexpected value: %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (ip_source_and_port_range_check_command, static) = {
  .path = "set ip source-and-port-range-check",
  .function = ip_source_and_port_range_check_command_fn,
  .short_help =
  "set ip source-and-port-range-check <ip-addr>/<mask> range <nn>-<nn> vrf <id>",
};


static clib_error_t *
show_source_and_port_range_check_fn (vlib_main_t * vm,
                                     unformat_input_t * input,
                                     vlib_cli_command_t * cmd)
{
  source_range_check_main_t * srm = & source_range_check_main;
  ip4_main_t * im = &ip4_main;
  ip_lookup_main_t * lm = &im->lookup_main;
  port_range_t * range;
  u32 fib_index;
  ip4_address_t addr;
  u8 addr_set = 0;
  u32 vrf_id = ~0;
  int rv, i, j;
  u32 adj_index;
  ip_adjacency_t *adj;
  u32 port = 0;
  u8 * rwh;
  uword * p;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_ip4_address, &addr))
        addr_set = 1;
      else if (unformat (input, "vrf %d", &vrf_id))
        ;
      else if (unformat (input, "port %d", &port))
        ;
      else
        break;
    }

  if (addr_set == 0)
    return clib_error_return (0, "<address> not specified");

  if (vrf_id == ~0)
    return clib_error_return (0, "VRF ID required, not specified");

  p = hash_get (im->fib_index_by_table_id, vrf_id);
  if (p == 0)
    return clib_error_return (0, "VRF %d not found", vrf_id);
  fib_index = p[0];

  adj_index = ip4_fib_lookup_with_table
    (im, fib_index, &addr, 0 /* disable_default_route */);

  adj = ip_get_adjacency (lm, adj_index);

  if (adj->lookup_next_index != IP_LOOKUP_NEXT_ICMP_ERROR)
    {
      vlib_cli_output (vm, "%U: src address drop", format_ip4_address, &addr);
      return 0;
    }

  if (port)
    {
      rv = check_adj_port_range_x1 (adj, (u16) port, 1234);
      if (rv == 1234)
        vlib_cli_output (vm, "%U port %d PASS", format_ip4_address,
                         &addr, port);
      else
        vlib_cli_output (vm, "%U port %d FAIL", format_ip4_address,
                         &addr, port);
      return 0;
    }
  else
    {
      u8 * s;
      rwh = (u8 *) (&adj->rewrite_header);

      s = format (0, "%U: ", format_ip4_address, &addr);

      range = (port_range_t *) rwh;

      for (i = 0; i < srm->ranges_per_adjacency; i++)
        {
          for (j = 0; j < 8; j++)
            {
              if (range->low.as_u16[j])
                s = format (s, "%d - %d ", (u32) range->low.as_u16[j],
                            (u32) range->hi.as_u16[j]);
            }
          range++;
        }
      vlib_cli_output (vm, "%s", s);
      vec_free(s);
    }

  return 0;
}

VLIB_CLI_COMMAND (show_source_and_port_range_check, static) = {
  .path = "show ip source-and-port-range-check",
  .function = show_source_and_port_range_check_fn,
  .short_help =
  "show ip source-and-port-range-check vrf <nn> <ip-addr> <port>",
};
