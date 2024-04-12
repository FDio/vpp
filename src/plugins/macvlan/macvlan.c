/* Copyright (c) 2024 Cisco and/or its affiliates.
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
 * limitations under the License. */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include "macvlan.h"

typedef struct
{
  union
  {
    struct
    {
      mac_address_t mac__;
      u16 pad;
    };
    u64 dmac;
  };
  u32 sw_if_index;
} macvlan_entry_t;

/* macvlan-input node: steer packets rx on the parent interface to the
 * corresponding child interface based on dest mac */

#define foreach_macvlan_input_next                                            \
  _ (DROP, "error-drop")                                                      \
  _ (ETHERNET_INPUT, "ethernet-input")

typedef enum
{
#define _(s, n) MACVLAN_INPUT_NEXT_##s,
  foreach_macvlan_input_next
#undef _
    MACVLAN_INPUT_N_NEXT,
} macvlan_input_next_t;

typedef struct
{
  u64 dmac;
  u32 sw_if_index;
} macvlan_input_trace_t;

static u8 *
format_macvlan_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  const macvlan_input_trace_t *tr =
    va_arg (*args, const macvlan_input_trace_t *);
  return format (s, "dmac %U -> %U", format_mac_address_t, &tr->dmac,
		 format_vnet_sw_if_index_name, vnm, tr->sw_if_index);
}

static_always_inline uword
macvlan_input (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
	       const int is_traced)
{
  const u64 bcast = clib_host_to_net_u64 (0xffffffffffff0000);
  u32 *from = vlib_frame_vector_args (frame), *bi = from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  const u32 n_tot = frame->n_vectors;
  u32 n_left = n_tot;

  vlib_get_buffers (vm, from, b, n_tot);

  while (n_left > 0)
    {
      const ethernet_header_t *eth = vlib_buffer_get_current (b[0]);
      const u64 dmac = clib_mem_unaligned (eth->dst_address, u64) &
		       clib_host_to_net_u64 (0xffffffffffff0000);
      const macvlan_entry_t *entry;
      u32 next__;

      entry = vnet_feature_next_with_data (&next__, b[0], sizeof (*entry));

      if (entry->dmac == dmac)
	{
	  /* macvlan hit, steer to the relevant interface */
	  vnet_buffer (b[0])->sw_if_index[VLIB_RX] = entry->sw_if_index;
	  next[0] = MACVLAN_INPUT_NEXT_ETHERNET_INPUT;
	  goto trace;
	}
      else if (PREDICT_FALSE (dmac == bcast))
	{
	  /* broadcast, flood */
	  u32 clones[2];
	  vlib_buffer_clone (vm, bi[0], clones, 2, 64);
	  ASSERT (clones[0] == bi[0]);
	  vnet_buffer (b[0])->sw_if_index[VLIB_RX] = entry->sw_if_index;
	  vlib_buffer_enqueue_to_single_next (
	    vm, node, &bi[0], MACVLAN_INPUT_NEXT_ETHERNET_INPUT, 1);
	  bi[0] = clones[1];
	}

      /* macvlan miss or flood, deliver to current interface */
      next[0] = next__;

    trace:
      if (is_traced && b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  macvlan_input_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->dmac = dmac;
	  tr->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	}

      next++;
      bi++;
      b++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_tot);
  return n_tot;
}

VLIB_NODE_FN (macvlan_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return macvlan_input (vm, node, from, 1 /* is_traced */);
  return macvlan_input (vm, node, from, 0 /* is_traced */);
}

VLIB_REGISTER_NODE (macvlan_input_node) = {
  .name = "macvlan-input",
  .vector_size = sizeof (u32),
  .n_next_nodes = MACVLAN_INPUT_N_NEXT,
  .next_nodes =
    {
#define _(s, n) [MACVLAN_INPUT_NEXT_##s] = n,
      foreach_macvlan_input_next
#undef _
    },
  .format_trace = format_macvlan_input_trace,
};

VNET_FEATURE_INIT (macvlan_input_feat, static) = {
  .arc_name = "device-input",
  .node_name = "macvlan-input",
};

/* macvlan-output node: steer packets leaving the child interface to tx on the
 * parent interface */

#define foreach_macvlan_output_next _ (DROP, "error-drop")

typedef enum
{
#define _(s, n) MACVLAN_OUTPUT_NEXT_##s,
  foreach_macvlan_output_next
#undef _
    MACVLAN_OUTPUT_N_NEXT,
} macvlan_output_next_t;

typedef struct
{
  u32 sw_if_index;
} macvlan_output_trace_t;

static u8 *
format_macvlan_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  const macvlan_output_trace_t *tr =
    va_arg (*args, const macvlan_output_trace_t *);
  vnet_main_t *vnm = vnet_get_main ();
  return format (s, "-> %U", format_vnet_sw_if_index_name, vnm,
		 tr->sw_if_index);
}

static_always_inline uword
macvlan_output (vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_frame_t *frame, const int is_traced)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *from = vlib_frame_vector_args (frame);
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  const u32 n_tot = frame->n_vectors;
  u32 n_left = n_tot;

  vlib_get_buffers (vm, from, b, n_tot);

  while (n_left > 0)
    {
      const u32 *parent_sw_if_index;
      u32 next__;
      parent_sw_if_index = vnet_feature_next_with_data (
	&next__, b[0], sizeof (*parent_sw_if_index));
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = *parent_sw_if_index;
      next[0] = next__;

      if (is_traced && b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  macvlan_output_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	}

      next++;
      b++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, n_tot);
  return n_tot;
}

VLIB_NODE_FN (macvlan_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return macvlan_output (vm, node, from, 1 /* is_traced */);
  return macvlan_output (vm, node, from, 0 /* is_traced */);
}

VLIB_REGISTER_NODE (macvlan_output_node) = {
  .name = "macvlan-output",
  .vector_size = sizeof (u32),
  .n_next_nodes = MACVLAN_OUTPUT_N_NEXT,
  .next_nodes =
    {
#define _(s, n) [MACVLAN_OUTPUT_NEXT_##s] = n,
      foreach_macvlan_output_next
#undef _
    },
  .format_trace = format_macvlan_output_trace,
};

VNET_FEATURE_INIT (macvlan_output_feat, static) = {
  .arc_name = "interface-output",
  .node_name = "macvlan-output",
};

/* API & cli */

int
macvlan_add_del (u32 parent_sw_if_index, u32 child_sw_if_index, bool is_add)
{
  int rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
  vnet_main_t *vnm = vnet_get_main ();
  const mac_address_t *mac;
  macvlan_entry_t entry;

  if (!(vnet_sw_interface_is_api_valid (vnm, parent_sw_if_index) &&
	vnet_sw_interface_is_api_valid (vnm, child_sw_if_index)))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  mac = (void *) vnet_sw_interface_get_hw_address (vnm, child_sw_if_index);
  if (!mac)
    goto err0;

  mac_address_copy (&entry.mac__, mac);
  entry.pad = 0;
  entry.sw_if_index = child_sw_if_index;
  rv = vnet_feature_enable_disable ("device-input", "macvlan-input",
				    parent_sw_if_index, is_add, &entry,
				    sizeof (entry));
  if (rv)
    goto err0;

  rv = vnet_feature_enable_disable (
    "interface-output", "macvlan-output", child_sw_if_index, is_add,
    &parent_sw_if_index, sizeof (parent_sw_if_index));
  if (rv)
    goto err1;

  return 0;

err1:
  vnet_feature_enable_disable ("device-input", "macvlan-input",
			       parent_sw_if_index, !is_add, 0, 0);
err0:
  return rv;
}

static clib_error_t *
macvlan_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  u32 parent_sw_if_index, child_sw_if_index;
  clib_error_t *err;
  bool is_add;
  int rv;

  err = macvlan_parse_add_del (input, &parent_sw_if_index, &child_sw_if_index,
			       &is_add);
  if (err)
    return err;

  rv = macvlan_add_del (parent_sw_if_index, child_sw_if_index, is_add);
  switch (rv)
    {
    case 0:
      break; /* success */
    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      err = clib_error_return (0, "wrong interface");
      break;
    case VNET_API_ERROR_LIMIT_EXCEEDED:
      err = clib_error_return (0, "too many entries");
      break;
    default:
      err = clib_error_return (0, "error %d", rv);
      break;
    }

  return err;
}

VLIB_CLI_COMMAND (macvlan_cmd, static) = {
  .path = "macvlan",
  .function = macvlan_cli,
  .short_help = "macvlan [add|del] parent <itfc> child <itfc>",
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "MACVLAN plugin",
};
