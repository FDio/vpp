// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vlib/vlib.h>
#include <vnet/util/throttle.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_sas.h>
#include <vnet/buffer.h>
#include <vcdp/vcdp.api_enum.h>
#include <vcdp/vcdp_funcs.h>

/* This is shamelessly copied from vnet/ip/icmp4.c to avoid having to add custom next node hooks there. */
/* This node is used to generate ICMP error messages */
/** ICMP throttling */
static throttle_t icmp_throttle;

typedef enum {
  VCDP_ICMP_ERROR_NEXT_DROP,
  VCDP_ICMP_ERROR_NEXT_LOOKUP,
  VCDP_ICMP_ERROR_N_NEXT,
} vcdp_icmp_error_next_t;

typedef struct {
  u8 packet_data[64];
} vcdp_icmp_error_trace_t;

static u8 *
format_vcdp_icmp_error_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  vcdp_icmp_error_trace_t *t = va_arg (*va, vcdp_icmp_error_trace_t *);

  s = format (s, "%U",
	      format_ip4_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

VLIB_NODE_FN(vcdp_icmp_error_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *from;
  u32 n_left = frame->n_vectors;
  u32 thread_index = vm->thread_index;
  u16 nexts[VLIB_FRAME_SIZE] = {0}, *next = nexts;

  from = vlib_frame_vector_args(frame);
  vlib_get_buffers(vm, from, bufs, n_left);
  b = bufs;

  u64 seed = throttle_seed (&icmp_throttle, thread_index, vlib_time_now (vm));

  while (n_left > 0) {
    // next[0] = VCDP_BYPASS_NEXT_LOOKUP;

    /* May have an L2 header */
    vlib_buffer_advance(b[0], vnet_buffer(b[0])->ip.save_rewrite_length);
    vnet_buffer(b[0])->ip.save_rewrite_length = 0;
    ip4_header_t *ip = vlib_buffer_get_current(b[0]);
    clib_warning("PAYLOAD PACKET: %U %d", format_ip4_header, ip, 40, vnet_buffer(b[0])->ip.save_rewrite_length);
    u32 src = ip->src_address.as_u32;

    /*
     *  Rate limit based on the src,dst addresses in the original packet
     */
    u64 r0 = (u64) ip->dst_address.as_u32 << 32 | ip->src_address.as_u32;
    if (throttle_check(&icmp_throttle, thread_index, r0, seed)) {
      b[0]->error = node->errors[VCDP_ICMP_ERROR_THROTTLED];
      next[0] = VCDP_ICMP_ERROR_NEXT_DROP;
      goto done;
    }

    u32 sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];

    /* Add IP header and ICMPv4 header including a 4 byte data field */
    vlib_buffer_advance(b[0], -sizeof(ip4_header_t) - sizeof(icmp46_header_t) - 4);

    b[0]->current_length = b[0]->current_length > 576 ? 576 : b[0]->current_length;

    // Free any chained buffers, keeping the first one
    if (b[0]->flags & VLIB_BUFFER_NEXT_PRESENT) {
      vlib_buffer_free_one(vm, b[0]->next_buffer);
      b[0]->total_length_not_including_first_buffer = 0;
      b[0]->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
    }

    ip4_header_t *out_ip = vlib_buffer_get_current(b[0]);
    icmp46_header_t *icmp = (icmp46_header_t *) &out_ip[1];

    /* Fill ip header fields */
    out_ip->ip_version_and_header_length = 0x45;
    out_ip->tos = 0;
    out_ip->length = clib_host_to_net_u16(b[0]->current_length);
    out_ip->fragment_id = 0;
    out_ip->flags_and_fragment_offset = 0;
    out_ip->ttl = 64;
    out_ip->protocol = IP_PROTOCOL_ICMP;
    out_ip->dst_address.as_u32 = src;
    /* Prefer a source address from "offending interface" */
    if (!ip4_sas_by_sw_if_index(sw_if_index, &out_ip->dst_address,
                                &out_ip->src_address)) { /* interface has no IP4 address - should not happen */
      next[0] = VCDP_ICMP_ERROR_NEXT_DROP;
      b[0]->error = node->errors[VCDP_ICMP_ERROR_SAS_FAILED];
      goto done;
    }

    out_ip->checksum = ip4_header_checksum(out_ip);

    /* Fill icmp header fields */
    icmp->type = vnet_buffer(b[0])->ip.icmp.type;
    icmp->code = vnet_buffer(b[0])->ip.icmp.code;
    *((u32 *) (icmp + 1)) = clib_host_to_net_u32(vnet_buffer(b[0])->ip.icmp.data);
    icmp->checksum = 0;
    ip_csum_t sum = ip_incremental_checksum(0, icmp, b[0]->current_length - sizeof(ip4_header_t));
    icmp->checksum = ~ip_csum_fold(sum);

    next[0] = VCDP_ICMP_ERROR_NEXT_LOOKUP;

done:
    b[0]->error = 0;
    next += 1;
    n_left -= 1;
    b += 1;
  }
  vlib_buffer_enqueue_to_next(vm, node, from, nexts, frame->n_vectors);

  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE))) {
    int i;
    b = bufs;
    for (i = 0; i < frame->n_vectors; i++) {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED) {
        vcdp_icmp_error_trace_t *t = vlib_add_trace(vm, node, b[0], sizeof(*t));
        clib_memcpy(t->packet_data, vlib_buffer_get_current(b[0]), sizeof(t->packet_data));
        b++;
      } else
        break;
    }
  }

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(vcdp_icmp_error_node) = {
  .name = "vcdp-icmp-error",
  .vector_size = sizeof(u32),
  .n_errors = VCDP_ICMP_N_ERROR,
  .error_counters = vcdp_icmp_error_counters,
  .n_next_nodes = VCDP_ICMP_ERROR_N_NEXT,
  .next_nodes =
    {
      [VCDP_ICMP_ERROR_NEXT_DROP] = "vcdp-drop",
      [VCDP_ICMP_ERROR_NEXT_LOOKUP] = "vcdp-icmp-error-forwarding",
    },
  .format_trace = format_vcdp_icmp_error_trace,
};

static clib_error_t *
vcdp_icmp_init(vlib_main_t *vm)
{
  vlib_thread_main_t *tm = &vlib_thread_main;
  u32 n_vlib_mains = tm->n_vlib_mains;
  throttle_init(&icmp_throttle, n_vlib_mains, THROTTLE_BITS, 1e-5);

  return 0;
}

VLIB_INIT_FUNCTION(vcdp_icmp_init);
