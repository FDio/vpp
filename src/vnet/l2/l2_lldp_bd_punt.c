/*
 * l2_lldp_bd_punt.c : layer 2 LLDP BD punting
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vlib/cli.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_lldp_bd_punt.h>

#include <vppinfra/error.h>
#include <vppinfra/hash.h>

typedef struct
{
  u8 src[6];
  u8 dst[6];
  u32 ingress_sw_if_index;
  u32 egress_sw_if_index;
  u16 bd_index;
} l2_lldp_bd_punt_trace_t;

/* packet trace format function */
static u8 *
format_l2_lldp_bd_punt_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_lldp_bd_punt_trace_t *t = va_arg (*args, l2_lldp_bd_punt_trace_t *);

  s = format (
    s, "l2-lldp-bd-punt: sw_if_index in %d out %d dst %U src %U bd_index %d",
    t->ingress_sw_if_index, t->egress_sw_if_index, format_ethernet_address,
    t->dst, format_ethernet_address, t->src, t->bd_index);
  return s;
}
#ifndef CLIB_MARCH_VARIANT
l2_lldp_bd_punt_main_t l2_lldp_bd_punt_main;
#endif /* CLIB_MARCH_VARIANT */

#define foreach_l2_lldp_bd_punt_error                                         \
  _ (L2_LLDP_PUNTED, "L2 LLDP punted packets")                                \
  _ (REPL_FAIL, "L2 LLDP clone failure")

typedef enum
{
#define _(sym, str) L2_LLDP_BD_PUNT_ERROR_##sym,
  foreach_l2_lldp_bd_punt_error
#undef _
    L2_LLDP_BD_PUNT_N_ERROR,
} l2_lldp_bd_punt_error_t;

static char *l2_lldp_bd_punt_error_strings[] = {
#define _(sym, string) string,
  foreach_l2_lldp_bd_punt_error
#undef _
};

typedef enum
{
  L2_LLDP_BD_PUNT_NEXT_L2_OUTPUT,
  L2_LLDP_BD_PUNT_NEXT_DROP,
  L2_LLDP_BD_PUNT_N_NEXT,
} l2_lldp_bd_punt_next_t;

u8
pkt_need_lldp_punt (vlib_buffer_t *b)
{
  u16 ethertype;
  u8 *current;
  current = vlib_buffer_get_current (b);
  ethertype =
    clib_mem_unaligned (current + vnet_buffer (b)->l2.l2_len - 2, u16);

  return (ethertype == clib_host_to_net_u16 (ETHERNET_TYPE_802_1_LLDP) &&
	  (b->flags & VNET_BUFFER_F_LOCALLY_ORIGINATED) == 0);
}

/*
 * Perform lldp replication on one packet
 */
VLIB_NODE_FN (l2_lldp_bd_punt_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from;
  l2_lldp_bd_punt_main_t *lm = &l2_lldp_bd_punt_main;
  u16 next_indices[256], *next_index = next_indices;
  vlib_buffer_t *bufs[256], **b = bufs;
  vlib_buffer_t *copied_bufs[256], **cb = copied_bufs;
  u32 copied_buffer_indices[256], *cbi = copied_buffer_indices;

  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, frame->n_vectors);
  n_left_from = frame->n_vectors;

  while (n_left_from > 8)
    {
      ethernet_header_t *eh;
      u32 swif0 = vec_elt (lm->bd_punt_if, vnet_buffer (b[0])->l2.bd_index);
      u32 swif1 = vec_elt (lm->bd_punt_if, vnet_buffer (b[1])->l2.bd_index);
      u32 swif2 = vec_elt (lm->bd_punt_if, vnet_buffer (b[2])->l2.bd_index);
      u32 swif3 = vec_elt (lm->bd_punt_if, vnet_buffer (b[3])->l2.bd_index);

      mac_address_t *src_mac0 = vec_elt_at_index (lm->bd_punt_src_mac, swif0);
      mac_address_t *src_mac1 = vec_elt_at_index (lm->bd_punt_src_mac, swif1);
      mac_address_t *src_mac2 = vec_elt_at_index (lm->bd_punt_src_mac, swif2);
      mac_address_t *src_mac3 = vec_elt_at_index (lm->bd_punt_src_mac, swif3);
      vlib_prefetch_buffer_header (b[4], STORE);
      vlib_prefetch_buffer_header (b[5], STORE);
      vlib_prefetch_buffer_header (b[6], STORE);
      vlib_prefetch_buffer_header (b[7], STORE);

      if (pkt_need_lldp_punt (b[0]))
	{
	  cb[0] = vlib_buffer_copy (vm, b[0]);
	  if (PREDICT_FALSE (!cb[0]))
	    vlib_node_increment_counter (vm, node->node_index,
					 L2_LLDP_BD_PUNT_ERROR_REPL_FAIL, 1);
	  else
	    {
	      eh = vlib_buffer_get_current (cb[0]);
	      clib_memcpy_fast (eh->src_address, src_mac0, 6);
	      vnet_buffer (cb[0])->sw_if_index[VLIB_TX] = swif0;
	      vnet_buffer (cb[0])->l2.feature_bitmap = L2OUTPUT_FEAT_OUTPUT;
	      cb[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	      cbi[0] = vlib_get_buffer_index (vm, cb[0]);
	      cb++;
	      cbi++;
	    }
	}
      if (pkt_need_lldp_punt (b[1]))
	{
	  cb[0] = vlib_buffer_copy (vm, b[1]);
	  if (PREDICT_FALSE (!cb[0]))
	    vlib_node_increment_counter (vm, node->node_index,
					 L2_LLDP_BD_PUNT_ERROR_REPL_FAIL, 1);
	  else
	    {
	      eh = vlib_buffer_get_current (cb[0]);
	      clib_memcpy_fast (eh->src_address, src_mac1, 6);
	      vnet_buffer (cb[0])->sw_if_index[VLIB_TX] = swif1;
	      vnet_buffer (cb[0])->l2.feature_bitmap = L2OUTPUT_FEAT_OUTPUT;
	      cb[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	      cbi[0] = vlib_get_buffer_index (vm, cb[0]);
	      cb++;
	      cbi++;
	    }
	}
      if (pkt_need_lldp_punt (b[2]))
	{
	  cb[0] = vlib_buffer_copy (vm, b[2]);
	  if (PREDICT_FALSE (!cb[0]))
	    vlib_node_increment_counter (vm, node->node_index,
					 L2_LLDP_BD_PUNT_ERROR_REPL_FAIL, 1);
	  else
	    {
	      eh = vlib_buffer_get_current (cb[0]);
	      clib_memcpy_fast (eh->src_address, src_mac2, 6);
	      vnet_buffer (cb[0])->sw_if_index[VLIB_TX] = swif2;
	      vnet_buffer (cb[0])->l2.feature_bitmap = L2OUTPUT_FEAT_OUTPUT;
	      cb[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	      cbi[0] = vlib_get_buffer_index (vm, cb[0]);
	      cb++;
	      cbi++;
	    }
	}
      if (pkt_need_lldp_punt (b[3]))
	{
	  cb[0] = vlib_buffer_copy (vm, b[3]);
	  if (PREDICT_FALSE (!cb[0]))
	    vlib_node_increment_counter (vm, node->node_index,
					 L2_LLDP_BD_PUNT_ERROR_REPL_FAIL, 1);
	  else
	    {
	      eh = vlib_buffer_get_current (cb[0]);
	      clib_memcpy_fast (eh->src_address, src_mac3, 6);
	      vnet_buffer (cb[0])->sw_if_index[VLIB_TX] = swif3;
	      vnet_buffer (cb[0])->l2.feature_bitmap = L2OUTPUT_FEAT_OUTPUT;
	      cb[0]->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	      cbi[0] = vlib_get_buffer_index (vm, cb[0]);
	      cb++;
	      cbi++;
	    }
	}

      next_index[0] = vnet_l2_feature_next (b[0], lm->feat_next_node_index,
					    L2INPUT_FEAT_LLDP_BD_PUNT);
      next_index[1] = vnet_l2_feature_next (b[1], lm->feat_next_node_index,
					    L2INPUT_FEAT_LLDP_BD_PUNT);
      next_index[2] = vnet_l2_feature_next (b[2], lm->feat_next_node_index,
					    L2INPUT_FEAT_LLDP_BD_PUNT);
      next_index[3] = vnet_l2_feature_next (b[3], lm->feat_next_node_index,
					    L2INPUT_FEAT_LLDP_BD_PUNT);

      next_index += 4;
      b += 4;
      from += 4;
      n_left_from -= 4;
    }

  while (n_left_from > 0)
    {
      ethernet_header_t *eh;
      u32 swif0 = vec_elt (lm->bd_punt_if, vnet_buffer (b[0])->l2.bd_index);
      mac_address_t *src_mac0 = vec_elt_at_index (lm->bd_punt_src_mac, swif0);
      if (pkt_need_lldp_punt (b[0]))
	{
	  cb[0] = vlib_buffer_copy (vm, b[0]);
	  if (PREDICT_FALSE (!cb[0]))
	    vlib_node_increment_counter (vm, node->node_index,
					 L2_LLDP_BD_PUNT_ERROR_REPL_FAIL, 1);
	  else
	    {
	      eh = vlib_buffer_get_current (cb[0]);
	      clib_memcpy_fast (eh->src_address, src_mac0, 6);
	      vnet_buffer (cb[0])->sw_if_index[VLIB_TX] = swif0;
	      vnet_buffer (cb[0])->l2.feature_bitmap = L2OUTPUT_FEAT_OUTPUT;
	      cbi[0] = vlib_get_buffer_index (vm, cb[0]);
	      cb += 1;
	      cbi += 1;
	    }
	}
      next_index[0] = vnet_l2_feature_next (b[0], lm->feat_next_node_index,
					    L2INPUT_FEAT_LLDP_BD_PUNT);
      next_index += 1;
      b += 1;
      from += 1;
      n_left_from -= 1;
    }

  /* Deal with traced packets */
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      b = bufs;
      while (b < bufs + frame->n_vectors)
	{
	  if (PREDICT_FALSE ((*b)->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      l2_lldp_bd_punt_trace_t *t =
		vlib_add_trace (vm, node, *b, sizeof (*t));
	      ethernet_header_t *eth = vlib_buffer_get_current (*b);
	      t->ingress_sw_if_index = vnet_buffer (*b)->sw_if_index[VLIB_RX];
	      t->egress_sw_if_index = vnet_buffer (*b)->sw_if_index[VLIB_TX];
	      t->bd_index = vnet_buffer (*b)->l2.bd_index;
	      clib_memcpy_fast (t->src, eth->src_address, 6);
	      clib_memcpy_fast (t->dst, eth->dst_address, 6);
	    }
	  b++;
	}
      /* Also force trace copied packets */
      cb = copied_bufs;
      while (cb < copied_bufs + (cbi - copied_buffer_indices))
	{
	  if ((cb[0]->flags & VLIB_BUFFER_IS_TRACED) &&
	      vlib_trace_buffer (vm, node, L2_LLDP_BD_PUNT_NEXT_L2_OUTPUT,
				 cb[0], 0 /* follow_chain */))
	    {
	      l2_lldp_bd_punt_trace_t *t =
		vlib_add_trace (vm, node, *cb, sizeof (*t));
	      ethernet_header_t *eth = vlib_buffer_get_current (*cb);
	      t->ingress_sw_if_index = vnet_buffer (*cb)->sw_if_index[VLIB_RX];
	      t->egress_sw_if_index = vnet_buffer (*cb)->sw_if_index[VLIB_TX];
	      t->bd_index = vnet_buffer (*cb)->l2.bd_index;
	      clib_memcpy_fast (t->src, eth->src_address, 6);
	      clib_memcpy_fast (t->dst, eth->dst_address, 6);
	    }
	  cb++;
	}
    }
  /* enqueue copied packets */
  if (cbi > copied_buffer_indices)
    {
      u32 n_copied = cbi - copied_buffer_indices;
      vlib_node_increment_counter (
	vm, node->node_index, L2_LLDP_BD_PUNT_ERROR_L2_LLDP_PUNTED, n_copied);
      vlib_buffer_enqueue_to_single_next (vm, node, copied_buffer_indices,
					  L2_LLDP_BD_PUNT_NEXT_L2_OUTPUT,
					  n_copied);
    }
  /* enqueue original packets */
  from = vlib_frame_vector_args (frame);
  vlib_buffer_enqueue_to_next (vm, node, from, next_indices, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (l2_lldp_bd_punt_node) = {
  .name = "l2-lldp-bd-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_lldp_bd_punt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l2_lldp_bd_punt_error_strings),
  .error_strings = l2_lldp_bd_punt_error_strings,

  .n_next_nodes = L2_LLDP_BD_PUNT_N_NEXT,

  .next_nodes = {
        [L2_LLDP_BD_PUNT_NEXT_L2_OUTPUT] = "l2-output",
        [L2_LLDP_BD_PUNT_NEXT_DROP] = "error-drop",
  },
};

#ifndef CLIB_MARCH_VARIANT

static void
lldp_bd_punt_change_mac (struct ethernet_main_t_ *im, u32 sw_if_index,
			 uword opaque)
{
  l2_lldp_bd_punt_main_t *mp = &l2_lldp_bd_punt_main;
  const u8 *mac =
    vnet_sw_interface_get_hw_address (vnet_get_main (), sw_if_index);
  clib_memcpy_fast (mp->bd_punt_src_mac[sw_if_index].bytes, mac, 6);
}

clib_error_t *
l2_lldp_bd_punt_init (vlib_main_t *vm)
{
  l2_lldp_bd_punt_main_t *mp = &l2_lldp_bd_punt_main;

  ethernet_address_change_ctx_t ctx = {
    .function = lldp_bd_punt_change_mac,
    .function_opaque = 0,
  };
  vec_add1 (ethernet_main.address_change_callbacks, ctx);

  /* Initialize the feature next-node indexes */
  feat_bitmap_init_next_nodes (vm, l2_lldp_bd_punt_node.index, L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       mp->feat_next_node_index);

  return NULL;
}

VLIB_INIT_FUNCTION (l2_lldp_bd_punt_init);

static clib_error_t *
l2_lldp_bd_punt_enable_disable (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  u32 bd_id;
  u32 enable;
  uword *p;
  u32 sw_if_index = ~0;
  bd_main_t *bdm = &bd_main;
  vnet_main_t *vnm = vnet_get_main ();

  if (!unformat (input, "%d", &bd_id))
    {
      error = clib_error_return (0, "missing bridge-domain-id");
      goto done;
    }

  enable = 1;

  p = hash_get (bdm->bd_index_by_bd_id, bd_id);
  if (p == 0)
    return clib_error_return (0, "No such bridge domain %d", bd_id);

  if (unformat (input, "tx %U", unformat_vnet_sw_interface, vnm, &sw_if_index))
    ;

  if (unformat (input, "disable"))
    enable = 0;

  if (enable && sw_if_index == ~0)
    {
      error = clib_error_return (0, "missing tx <interface>");
      goto done;
    }

  if (sw_if_index != ~0)
    {
      const u8 *mac;

      vec_validate (l2_lldp_bd_punt_main.bd_punt_src_mac, sw_if_index);
      mac = vnet_sw_interface_get_hw_address (vnm, sw_if_index);
      clib_memcpy_fast (
	l2_lldp_bd_punt_main.bd_punt_src_mac[sw_if_index].bytes, mac, 6);
    }

  if (enable)
    {
      vec_validate (l2_lldp_bd_punt_main.bd_punt_if, p[0]);
      l2_lldp_bd_punt_main.bd_punt_if[p[0]] = sw_if_index;
      bd_set_flags (vm, p[0], L2_LLDP_BD_PUNT, 1);
    }
  else
    {
      bd_set_flags (vm, p[0], L2_LLDP_BD_PUNT, 0);
    }

done:
  return error;
}

VLIB_CLI_COMMAND (bd_lldp_punt_cli, static) = {
  .path = "set bridge-domain lldp-punt",
  .short_help = "set bridge-domain lldp-punt <bridge-domain-id> [tx "
		"<interface>] [disable]",
  .function = l2_lldp_bd_punt_enable_disable,
};

#endif /* CLIB_MARCH_VARIANT */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
