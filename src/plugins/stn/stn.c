/*
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
 */

#include <stn/stn.h>

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/ip/format.h>
#include <vnet/ethernet/packet.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>

stn_main_t stn_main;
static vlib_node_registration_t stn_ip4_punt;
static vlib_node_registration_t stn_ip6_punt;

static u8 stn_hw_addr_local[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static u8 stn_hw_addr_dst[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};

static ethernet_header_t stn_ip4_ethernet_header = {};
static ethernet_header_t stn_ip6_ethernet_header = {};

typedef struct {
  clib_bihash_kv_16_8_t kv;
} stn_ip46_punt_trace_t;

static u8 *
format_stn_rule (u8 * s, va_list * args)
{
  stn_rule_t *r = va_arg (*args, stn_rule_t *);
  stn_main_t *stn = &stn_main;
  u32 indent = format_get_indent (s);
  u32 node_index = ip46_address_is_ip4(&r->address)?stn_ip4_punt.index:stn_ip6_punt.index;
  vlib_node_t *next_node = vlib_get_next_node(vlib_get_main(), node_index, r->next_node_index);
  s = format (s, "rule_index: %d\n", r - stn->rules);
  s = format (s, "%Uaddress: %U\n", format_white_space, indent,
	      format_ip46_address, &r->address, IP46_TYPE_ANY);
  s = format (s, "%Uiface: %U (%d)\n", format_white_space, indent,
  	      format_vnet_sw_if_index_name, vnet_get_main(), r->sw_if_index,
	      r->sw_if_index);
  s = format (s, "%Unext_node: %s (%d)", format_white_space, indent,
	      next_node->name, next_node->index);
  return s;
}

static_always_inline u8 *
format_stn_ip46_punt_trace (u8 * s, va_list * args, u8 is_ipv4)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  stn_ip46_punt_trace_t *t = va_arg (*args, stn_ip46_punt_trace_t *);
  u32 indent = format_get_indent (s);

  format (s, "dst_address: %U\n", format_ip46_address,
	  (ip46_address_t *)&t->kv.key, IP46_TYPE_ANY);

  if (t->kv.value == ~(0L))
    {
      s = format (s, "%Urule: none", format_white_space, indent);
    }
  else
    {
      s = format (s, "%Urule:\n%U%U", format_white_space, indent,
		     format_white_space, indent + 2,
		     format_stn_rule, &stn_main.rules[t->kv.value]);
    }
  return s;
}

static void
stn_punt_fn (vlib_main_t * vm,
	           vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  stn_main_t *stn = &stn_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u32 next0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);

/*
 * We are not guaranteed any particular layer here.
 * So we need to reparse from the beginning of the packet.
 * which may not start from zero with some DPDK drivers.

	  ip4_header_t *ip = vlib_buffer_get_current(p0);
	  if ((ip->ip_version_and_header_length & 0xf0) == 0x40)
*
*/
         int ethernet_header_offset = 0; /* to be filled by DPDK */
         ethernet_header_t *eth = (ethernet_header_t *)(p0->data + ethernet_header_offset);
         /* ensure the block current data starts at L3 boundary now for the subsequent nodes */
         vlib_buffer_advance(p0, ethernet_header_offset + sizeof(ethernet_header_t) - p0->current_data);
          if (clib_net_to_host_u16(eth->type) == ETHERNET_TYPE_IP4)
	    next0 = stn->punt_to_stn_ip4_next_index;
	  else
	    next0 = stn->punt_to_stn_ip6_next_index;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
}

typedef enum
{
  STN_IP_PUNT_DROP,
  STN_IP_PUNT_N_NEXT,
} stn_ip_punt_next_t;

static_always_inline uword
stn_ip46_punt_fn (vlib_main_t * vm,
	           vlib_node_runtime_t * node, vlib_frame_t * frame,
		   u8 is_ipv4)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  stn_main_t *stn = &stn_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      /* Single loop */
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  clib_bihash_kv_16_8_t kv;
	  u32 next0 = STN_IP_PUNT_DROP;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  p0 = vlib_get_buffer (vm, pi0);

	  if (is_ipv4)
	    {
	      ip4_header_t *hdr = (ip4_header_t *) vlib_buffer_get_current(p0);
	      ip46_address_set_ip4((ip46_address_t *)kv.key, &hdr->dst_address);
	    }
	  else
	    {
	      ip6_header_t *hdr = (ip6_header_t *) vlib_buffer_get_current(p0);
	      kv.key[0] = hdr->dst_address.as_u64[0];
	      kv.key[1] = hdr->dst_address.as_u64[1];
	    }

	  kv.value = ~(0L);
	  clib_bihash_search_inline_16_8 (&stn->rule_by_address_table, &kv);
	  if (kv.value != ~(0L))
	    {
	      ethernet_header_t *eth;
	      stn_rule_t *r = &stn->rules[kv.value];
	      vnet_buffer(p0)->sw_if_index[VLIB_TX] = r->sw_if_index;
	      next0 = r->next_node_index;
	      vlib_buffer_advance(p0, -sizeof(*eth));
	      eth = (ethernet_header_t *) vlib_buffer_get_current(p0);
	      if (is_ipv4)
		clib_memcpy(eth, &stn_ip4_ethernet_header, sizeof(*eth));
	      else
		clib_memcpy(eth, &stn_ip6_ethernet_header, sizeof(*eth));
	    }

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      stn_ip46_punt_trace_t *tr =
		  vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->kv = kv;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, pi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


#define foreach_stn_ip_punt_error \
 _(NONE, "no error")

typedef enum {
#define _(sym,str) STN_IP_punt_ERROR_##sym,
  foreach_stn_ip_punt_error
#undef _
  STN_IP_PUNT_N_ERROR,
} ila_error_t;

static char *stn_ip_punt_error_strings[] = {
#define _(sym,string) string,
    foreach_stn_ip_punt_error
#undef _
};

u8 *
format_stn_ip6_punt_trace (u8 * s, va_list * args)
{
  return format_stn_ip46_punt_trace (s, args, 0);
}

static uword
stn_ip6_punt_fn (vlib_main_t * vm,
	           vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return stn_ip46_punt_fn(vm, node, frame, 0);
}

/** *INDENT-OFF* */
VLIB_REGISTER_NODE (stn_ip6_punt, static) =
{
  .function = stn_ip6_punt_fn,
  .name = "stn-ip6-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_stn_ip6_punt_trace,
  .n_errors = STN_IP_PUNT_N_ERROR,
  .error_strings = stn_ip_punt_error_strings,
  .n_next_nodes = STN_IP_PUNT_N_NEXT,
  .next_nodes =
  {
      [STN_IP_PUNT_DROP] = "error-drop"
  },
};
/** *INDENT-ON* */

u8 *
format_stn_ip4_punt_trace (u8 * s, va_list * args)
{
  return format_stn_ip46_punt_trace (s, args, 1);
}

static uword
stn_ip4_punt_fn (vlib_main_t * vm,
	           vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return stn_ip46_punt_fn(vm, node, frame, 1);
}

/** *INDENT-OFF* */
VLIB_REGISTER_NODE (stn_ip4_punt, static) =
{
  .function = stn_ip4_punt_fn,
  .name = "stn-ip4-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_stn_ip4_punt_trace,
  .n_errors = STN_IP_PUNT_N_ERROR,
  .error_strings = stn_ip_punt_error_strings,
  .n_next_nodes = STN_IP_PUNT_N_NEXT,
  .next_nodes =
  {
      [STN_IP_PUNT_DROP] = "error-drop",
  },
};
/** *INDENT-ON* */

clib_error_t *
stn_init (vlib_main_t * vm)
{
  stn_main_t *stn = &stn_main;
  stn->rules = 0;
  clib_bihash_init_16_8(&stn->rule_by_address_table, "stn addresses",
			1024, 1<<20);

  clib_memcpy(stn_ip4_ethernet_header.dst_address, stn_hw_addr_dst, 6);
  clib_memcpy(stn_ip4_ethernet_header.src_address, stn_hw_addr_local, 6);
  stn_ip4_ethernet_header.type = clib_host_to_net_u16(ETHERNET_TYPE_IP4);

  clib_memcpy(stn_ip6_ethernet_header.dst_address, stn_hw_addr_dst, 6);
  clib_memcpy(stn_ip6_ethernet_header.src_address, stn_hw_addr_local, 6);
  stn_ip6_ethernet_header.type = clib_host_to_net_u16(ETHERNET_TYPE_IP6);

  u32 punt_node_index = vlib_get_node_by_name(vm, (u8 *)"error-punt")->index;
  stn->punt_to_stn_ip4_next_index =
      vlib_node_add_next(vm, punt_node_index, stn_ip4_punt.index);
  stn->punt_to_stn_ip6_next_index =
        vlib_node_add_next(vm, punt_node_index, stn_ip6_punt.index);

  return stn_api_init (vm, stn);

  return NULL;
}

VLIB_INIT_FUNCTION (stn_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "VPP Steals the NIC for Container integration",
};
/* *INDENT-ON* */

int stn_rule_add_del (stn_rule_add_del_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main();
  vlib_main_t *vm = vlib_get_main();
  stn_main_t *stn = &stn_main;

  stn_rule_t *r = NULL;
  clib_bihash_kv_16_8_t kv;
  kv.key[0] = args->address.as_u64[0];
  kv.key[1] = args->address.as_u64[1];

  if (clib_bihash_search_inline_16_8 (&stn->rule_by_address_table, &kv) == 0)
    {
      r = &stn->rules[kv.value];
    }
  else if (!args->del)
    {
      pool_get(stn->rules, r);
      kv.value = r - stn->rules;
      clib_bihash_add_del_16_8(&stn->rule_by_address_table, &kv, 1);
      r->address = args->address;

      stn->n_rules++;
      if (stn->n_rules == 1)
	{
	  foreach_vlib_main({
	    this_vlib_main->os_punt_frame = stn_punt_fn;
	  });
	  udp_punt_unknown(vm, 0, 1);
	  udp_punt_unknown(vm, 1, 1);
	  tcp_punt_unknown(vm, 0, 1);
	  tcp_punt_unknown(vm, 1, 1);
	}
    }

  if (!args->del)
    {
      /* Getting output node and adding it as next */
      u32 output_node_index =
          vnet_tx_node_index_for_sw_interface(vnm, args->sw_if_index);
      u32 node_index = ip46_address_is_ip4(&args->address)?
          stn_ip4_punt.index : stn_ip6_punt.index;

      r->sw_if_index = args->sw_if_index;
      r->next_node_index =
	  vlib_node_add_next(vm, node_index, output_node_index);

      /* enabling forwarding on the output node (might not be done since
       * it is unnumbered) */
      vnet_feature_enable_disable("ip4-unicast", "ip4-lookup", args->sw_if_index,
				  1, 0, 0);
      vnet_feature_enable_disable("ip6-unicast", "ip6-lookup", args->sw_if_index,
				  1, 0, 0);
      vnet_feature_enable_disable("ip4-unicast", "ip4-drop", args->sw_if_index,
				  0, 0, 0);
      vnet_feature_enable_disable("ip6-unicast", "ip6-drop", args->sw_if_index,
				  0, 0, 0);
    }
  else if (r)
    {
      clib_bihash_add_del_16_8(&stn->rule_by_address_table, &kv, 0);
      pool_put(stn->rules, r);

      stn->n_rules--;
      if (stn->n_rules == 0)
	{
	  foreach_vlib_main({
	    this_vlib_main->os_punt_frame = NULL;
	  });
	}
    }
  else
    {
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  return 0;
}

static clib_error_t *
show_stn_rules_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  stn_main_t *stn = &stn_main;
  u8 *s = 0;
  stn_rule_t *rule;
  pool_foreach(rule, stn->rules, {
      s = format (s, "- %U\n", format_stn_rule, rule);
  });

  vlib_cli_output(vm, "%v", s);

  vec_free(s);
  return NULL;
}

VLIB_CLI_COMMAND (show_stn_rules_command, static) =
{
  .path = "show stn rules",
  .short_help = "",
  .function = show_stn_rules_fn,
};

static clib_error_t *
stn_rule_fn (vlib_main_t * vm,
		      unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  stn_rule_add_del_args_t args = {};
  u8 got_addr = 0;
  u8 got_iface = 0;
  int ret;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "address %U", unformat_ip46_address,
		    &args.address, IP46_TYPE_ANY))
	got_addr = 1;
      else if (unformat
	       (line_input, "interface %U", unformat_vnet_sw_interface,
		vnet_get_main(), &args.sw_if_index))
	got_iface = 1;
      else if (unformat (line_input, "del"))
	args.del = 1;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (!got_addr)
    {
      error = clib_error_return (0, "Missing address");
      goto done;
    }

  if (!got_iface)
    {
      error = clib_error_return (0, "Missing interface");
      goto done;
    }

  if ((ret = stn_rule_add_del (&args)))
    {
      error = clib_error_return (0, "stn_rule_add_del returned error %d", ret);
      goto done;
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (stn_rule_command, static) =
{
  .path = "stn rule",
  .short_help = "address <addr> interface <iface> [del]",
  .function = stn_rule_fn,
};
