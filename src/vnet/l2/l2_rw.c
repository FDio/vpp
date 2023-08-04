/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/l2/feat_bitmap.h>
#include <vnet/l2/l2_rw.h>
#include <vnet/classify/vnet_classify.h>

/**
 * @file
 * @brief Layer 2 Rewrite.
 *
 * Layer 2-Rewrite node uses classify tables to match packets. Then, using
 * the provisioned mask and value, modifies the packet header.
 */


#ifndef CLIB_MARCH_VARIANT
l2_rw_main_t l2_rw_main;
#endif /* CLIB_MARCH_VARIANT */

typedef struct
{
  u32 sw_if_index;
  u32 classify_table_index;
  u32 rewrite_entry_index;
} l2_rw_trace_t;

static u8 *
format_l2_rw_entry (u8 * s, va_list * args)
{
  l2_rw_entry_t *e = va_arg (*args, l2_rw_entry_t *);
  l2_rw_main_t *rw = &l2_rw_main;
  s = format (s, "%d -  mask:%U value:%U\n",
	      e - rw->entries,
	      format_hex_bytes, e->mask,
	      e->rewrite_n_vectors * sizeof (u32x4), format_hex_bytes,
	      e->value, e->rewrite_n_vectors * sizeof (u32x4));
  s =
    format (s, "      hits:%d skip_bytes:%d", e->hit_count,
	    e->skip_n_vectors * sizeof (u32x4));
  return s;
}

static u8 *
format_l2_rw_config (u8 * s, va_list * args)
{
  l2_rw_config_t *c = va_arg (*args, l2_rw_config_t *);
  return format (s, "table-index:%d miss-index:%d",
		 c->table_index, c->miss_index);
}

/* packet trace format function */
static u8 *
format_l2_rw_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_rw_trace_t *t = va_arg (*args, l2_rw_trace_t *);
  return format (s, "l2-rw: sw_if_index %d, table %d, entry %d",
		 t->sw_if_index, t->classify_table_index,
		 t->rewrite_entry_index);
}

always_inline l2_rw_config_t *
l2_rw_get_config (u32 sw_if_index)
{
  l2_rw_main_t *rw = &l2_rw_main;
  if (PREDICT_FALSE (!clib_bitmap_get (rw->configs_bitmap, sw_if_index)))
    {
      vec_validate (rw->configs, sw_if_index);
      rw->configs[sw_if_index].table_index = ~0;
      rw->configs[sw_if_index].miss_index = ~0;
      rw->configs_bitmap =
	clib_bitmap_set (rw->configs_bitmap, sw_if_index, 1);
    }
  return &rw->configs[sw_if_index];
}

static_always_inline void
l2_rw_rewrite (l2_rw_entry_t * rwe, u8 * h)
{
  u32x4u *d = ((u32x4u *) h) + rwe->skip_n_vectors;
  switch (rwe->rewrite_n_vectors)
    {
    case 5:
      d[4] = (d[4] & ~rwe->mask[4]) | rwe->value[4];
      /* FALLTHROUGH */
    case 4:
      d[3] = (d[3] & ~rwe->mask[3]) | rwe->value[3];
      /* FALLTHROUGH */
    case 3:
      d[2] = (d[2] & ~rwe->mask[2]) | rwe->value[2];
      /* FALLTHROUGH */
    case 2:
      d[1] = (d[1] & ~rwe->mask[1]) | rwe->value[1];
      /* FALLTHROUGH */
    case 1:
      d[0] = (d[0] & ~rwe->mask[0]) | rwe->value[0];
      break;
    default:
      abort ();
    }
}

VLIB_NODE_FN (l2_rw_node) (vlib_main_t * vm,
			   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  l2_rw_main_t *rw = &l2_rw_main;
  u32 n_left_from, *from, *to_next, next_index;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  f64 now = vlib_time_now (vlib_get_main ());

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;	/* number of packets to process */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 6 && n_left_to_next >= 2)
	{
	  u32 bi0, next0, sw_if_index0, rwe_index0;
	  u32 bi1, next1, sw_if_index1, rwe_index1;
	  vlib_buffer_t *b0, *b1;
	  ethernet_header_t *h0, *h1;
	  l2_rw_config_t *config0, *config1;
	  u64 hash0, hash1;
	  vnet_classify_table_t *t0, *t1;
	  vnet_classify_entry_t *e0, *e1;
	  l2_rw_entry_t *rwe0, *rwe1;

	  {
	    vlib_buffer_t *p2, *p3, *p4, *p5;
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);

	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_data (p2, LOAD);
	    vlib_prefetch_buffer_data (p3, LOAD);
	  }

	  bi0 = from[0];
	  bi1 = from[1];
	  to_next[0] = bi0;
	  to_next[1] = bi1;
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  h0 = vlib_buffer_get_current (b0);
	  h1 = vlib_buffer_get_current (b1);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
	  config0 = l2_rw_get_config (sw_if_index0);	/*TODO: check sw_if_index0 value */
	  config1 = l2_rw_get_config (sw_if_index1);	/*TODO: check sw_if_index0 value */
	  t0 = pool_elt_at_index (vcm->tables, config0->table_index);
	  t1 = pool_elt_at_index (vcm->tables, config1->table_index);

	  hash0 = vnet_classify_hash_packet (t0, (u8 *) h0);
	  hash1 = vnet_classify_hash_packet (t1, (u8 *) h1);
	  e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
	  e1 = vnet_classify_find_entry (t1, (u8 *) h1, hash1, now);

	  while (!e0 && (t0->next_table_index != ~0))
	    {
	      t0 = pool_elt_at_index (vcm->tables, t0->next_table_index);
	      hash0 = vnet_classify_hash_packet (t0, (u8 *) h0);
	      e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
	    }

	  while (!e1 && (t1->next_table_index != ~0))
	    {
	      t1 = pool_elt_at_index (vcm->tables, t1->next_table_index);
	      hash1 = vnet_classify_hash_packet (t1, (u8 *) h1);
	      e1 = vnet_classify_find_entry (t1, (u8 *) h1, hash1, now);
	    }

	  rwe_index0 = e0 ? e0->opaque_index : config0->miss_index;
	  rwe_index1 = e1 ? e1->opaque_index : config1->miss_index;

	  if (rwe_index0 != ~0)
	    {
	      rwe0 = pool_elt_at_index (rw->entries, rwe_index0);
	      l2_rw_rewrite (rwe0, (u8 *) h0);
	    }
	  if (rwe_index1 != ~0)
	    {
	      rwe1 = pool_elt_at_index (rw->entries, rwe_index1);
	      l2_rw_rewrite (rwe1, (u8 *) h1);
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_rw_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->classify_table_index = config0->table_index;
	      t->rewrite_entry_index = rwe_index0;
	    }

	  if (PREDICT_FALSE ((b1->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_rw_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->sw_if_index = sw_if_index1;
	      t->classify_table_index = config1->table_index;
	      t->rewrite_entry_index = rwe_index1;
	    }

	  /* Update feature bitmap and get next feature index */
	  next0 = vnet_l2_feature_next (b0, rw->feat_next_node_index,
					L2INPUT_FEAT_RW);
	  next1 = vnet_l2_feature_next (b1, rw->feat_next_node_index,
					L2INPUT_FEAT_RW);

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, sw_if_index0, rwe_index0;
	  vlib_buffer_t *b0;
	  ethernet_header_t *h0;
	  l2_rw_config_t *config0;
	  u64 hash0;
	  vnet_classify_table_t *t0;
	  vnet_classify_entry_t *e0;
	  l2_rw_entry_t *rwe0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  h0 = vlib_buffer_get_current (b0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  config0 = l2_rw_get_config (sw_if_index0);	/*TODO: check sw_if_index0 value */
	  t0 = pool_elt_at_index (vcm->tables, config0->table_index);

	  hash0 = vnet_classify_hash_packet (t0, (u8 *) h0);
	  e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);

	  while (!e0 && (t0->next_table_index != ~0))
	    {
	      t0 = pool_elt_at_index (vcm->tables, t0->next_table_index);
	      hash0 = vnet_classify_hash_packet (t0, (u8 *) h0);
	      e0 = vnet_classify_find_entry (t0, (u8 *) h0, hash0, now);
	    }

	  rwe_index0 = e0 ? e0->opaque_index : config0->miss_index;

	  if (rwe_index0 != ~0)
	    {
	      rwe0 = pool_elt_at_index (rw->entries, rwe_index0);
	      l2_rw_rewrite (rwe0, (u8 *) h0);
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_rw_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->classify_table_index = config0->table_index;
	      t->rewrite_entry_index = rwe_index0;
	    }

	  /* Update feature bitmap and get next feature index */
	  next0 = vnet_l2_feature_next (b0, rw->feat_next_node_index,
					L2INPUT_FEAT_RW);

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

#ifndef CLIB_MARCH_VARIANT
int
l2_rw_mod_entry (u32 * index,
		 u8 * mask, u8 * value, u32 len, u32 skip, u8 is_del)
{
  l2_rw_main_t *rw = &l2_rw_main;
  l2_rw_entry_t *e = 0;
  if (*index != ~0)
    {
      if (pool_is_free_index (rw->entries, *index))
	{
	  return -1;
	}
      e = pool_elt_at_index (rw->entries, *index);
    }
  else
    {
      pool_get (rw->entries, e);
      *index = e - rw->entries;
    }

  if (is_del)
    {
      pool_put (rw->entries, e);
      return 0;
    }

  e->skip_n_vectors = skip / sizeof (u32x4);
  skip -= e->skip_n_vectors * sizeof (u32x4);
  e->rewrite_n_vectors = (skip + len - 1) / sizeof (u32x4) + 1;
  vec_alloc_aligned (e->mask, e->rewrite_n_vectors, sizeof (u32x4));
  clib_memset (e->mask, 0, e->rewrite_n_vectors * sizeof (u32x4));
  vec_alloc_aligned (e->value, e->rewrite_n_vectors, sizeof (u32x4));
  clib_memset (e->value, 0, e->rewrite_n_vectors * sizeof (u32x4));

  clib_memcpy (((u8 *) e->value) + skip, value, len);
  clib_memcpy (((u8 *) e->mask) + skip, mask, len);

  int i;
  for (i = 0; i < e->rewrite_n_vectors; i++)
    {
      e->value[i] &= e->mask[i];
    }

  return 0;
}
#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
l2_rw_entry_cli_fn (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 index = ~0;
  u8 *mask = 0;
  u8 *value = 0;
  u32 skip = 0;
  u8 del = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %d", &index))
	;
      else if (unformat (input, "mask %U", unformat_hex_string, &mask))
	;
      else if (unformat (input, "value %U", unformat_hex_string, &value))
	;
      else if (unformat (input, "skip %d", &skip))
	;
      else if (unformat (input, "del"))
	del = 1;
      else
	break;
    }

  if (!mask || !value)
    return clib_error_return (0, "Unspecified mask or value");

  if (vec_len (mask) != vec_len (value))
    return clib_error_return (0, "Mask and value lengths must be identical");

  int ret;
  if ((ret =
       l2_rw_mod_entry (&index, mask, value, vec_len (mask), skip, del)))
    return clib_error_return (0, "Could not add entry");

  return 0;
}

/*?
 * Layer 2-Rewrite node uses classify tables to match packets. Then, using
 * the provisioned mask and value, modifies the packet header.
 *
 * @cliexpar
 * Example of how to add an l2 rewrite entry to change the destination mac of
 * the packet to 00:8a:00:0d:0e:02 (where parameter mask is Ethernet header's
mask,
 * parameter value is Ethernet header's value):
 * @cliexcmd{l2 rewrite entry mask ffffffffffff00000000000000000000 value
008a000d0e0200000000000000000000}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_rw_entry_cli, static) = {
  .path = "l2 rewrite entry",
  .short_help =
  "l2 rewrite entry [index <index>] [mask <hex-mask>] [value <hex-value>] [skip <n_bytes>] [del]",
  .function = l2_rw_entry_cli_fn,
};
/* *INDENT-ON* */

#ifndef CLIB_MARCH_VARIANT
int
l2_rw_interface_set_table (u32 sw_if_index, u32 table_index, u32 miss_index)
{
  l2_rw_config_t *c = l2_rw_get_config (sw_if_index);
  l2_rw_main_t *rw = &l2_rw_main;

  c->table_index = table_index;
  c->miss_index = miss_index;
  u32 feature_bitmap = (table_index == ~0) ? 0 : L2INPUT_FEAT_RW;

  l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_RW, feature_bitmap);

  if (c->table_index == ~0)
    clib_bitmap_set (rw->configs_bitmap, sw_if_index, 0);

  return 0;
}
#endif /* CLIB_MARCH_VARIANT */

static clib_error_t *
l2_rw_interface_cli_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 table_index = ~0;
  u32 sw_if_index = ~0;
  u32 miss_index = ~0;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      unformat (input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index);
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "table %d", &table_index))
	;
      else if (unformat (input, "miss-index %d", &miss_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "You must specify an interface 'iface <interface>'",
			      format_unformat_error, input);
  int ret;
  if ((ret =
       l2_rw_interface_set_table (sw_if_index, table_index, miss_index)))
    return clib_error_return (0, "l2_rw_interface_set_table returned %d",
			      ret);

  return 0;
}

/*?
 * Apply the rule to the interface.The following example shows how to use
classify
 * entry and Layer 2-Rewrite entry to modify the packet ethernet header on the
 * interface
 *
 * @cliexpar
 * Example use the classify to filter packets that do not need to be modified
(where
 * 192.168.68.34 is the destination ip of the data packet, 8080 is the
destination port
 * of the packet):
 * @cliexcmd{classify table mask l3 ip4 dst l4 dst_port}
 * @cliexcmd{classify session acl-hit-next permit table-index 0 match l3 ip4
dst 192.168.68.34 l4 dst_port 8080}
 *
 * @cliexpar
 * Example apply classify and l2 rewrite rules to the interface (where
YusurK2Eth6/0/1/3
 * is interface, \"table 0\" means Table Id is 0, \"miss 0\" means the packet
that matchs
 * the classify. miss will be modified according to the l2 rewrite entry with
index 0):
 * @cliexcmd{set interface l2 rewrite YusurK2Eth6/0/1/3 table 0 miss-index 0}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_rw_interface_cli, static) = {
  .path = "set interface l2 rewrite",
  .short_help =
  "set interface l2 rewrite <interface> [table <table index>] [miss-index <entry-index>]",
  .function = l2_rw_interface_cli_fn,
};
/* *INDENT-ON* */

static clib_error_t *
l2_rw_show_interfaces_cli_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  l2_rw_main_t *rw = &l2_rw_main;
  if (clib_bitmap_count_set_bits (rw->configs_bitmap) == 0)
    vlib_cli_output (vm, "No interface is currently using l2 rewrite\n");

  uword i;
  /* *INDENT-OFF* */
  clib_bitmap_foreach (i, rw->configs_bitmap) {
      vlib_cli_output (vm, "sw_if_index:%d %U\n", i, format_l2_rw_config, &rw->configs[i]);
  }
  /* *INDENT-ON* */
  return 0;
}

/*?
 * This command displays the l2 rewrite entries of the interfaces.
 *
 * @cliexpar
 * Example of how to display the the l2 rewrite rules on the interface:
 * @cliexstart{show l2 rewrite interfaces}
 * sw_if_index:4 table-index:0 miss-index:0
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_rw_show_interfaces_cli, static) = {
  .path = "show l2 rewrite interfaces",
  .short_help =
  "show l2 rewrite interfaces",
  .function = l2_rw_show_interfaces_cli_fn,
};
/* *INDENT-ON* */

static clib_error_t *
l2_rw_show_entries_cli_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2_rw_main_t *rw = &l2_rw_main;
  l2_rw_entry_t *e;
  if (pool_elts (rw->entries) == 0)
    vlib_cli_output (vm, "No entries\n");

  /* *INDENT-OFF* */
  pool_foreach (e, rw->entries) {
    vlib_cli_output (vm, "%U\n", format_l2_rw_entry, e);
  }
  /* *INDENT-ON* */
  return 0;
}

/*?
 * This command displays all l2 rewrite entries.
 *
 * @cliexpar
 * Example of how to display all l2 rewrite entries:
 * @cliexstart{show l2 rewrite entries}
 * 0 -  mask:ffffffffffff00000000000000000000
value:aabbccddeeff00000000000000000000
 *    hits:0 skip_bytes:0
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_rw_show_entries_cli, static) = {
  .path = "show l2 rewrite entries",
  .short_help =
  "show l2 rewrite entries",
  .function = l2_rw_show_entries_cli_fn,
};
/* *INDENT-ON* */

static int
l2_rw_enable_disable (u32 bridge_domain, u8 disable)
{
  u32 mask = L2INPUT_FEAT_RW;
  l2input_set_bridge_features (bridge_domain, mask, disable ? 0 : mask);
  return 0;
}

static clib_error_t *
l2_rw_set_cli_fn (vlib_main_t * vm,
		  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 bridge_domain;
  u8 disable = 0;

  if (unformat_check_input (input) == UNFORMAT_END_OF_INPUT ||
      !unformat (input, "%d", &bridge_domain))
    {
      return clib_error_return (0, "You must specify a bridge domain");
    }

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT &&
      unformat (input, "disable"))
    {
      disable = 1;
    }

  if (l2_rw_enable_disable (bridge_domain, disable))
    return clib_error_return (0, "Could not enable or disable rewrite");

  return 0;
}

/*?
 * Layer 2 rewrite can be enabled and disabled on each interface and on each
bridge-domain.
 * Use this command to manage l2 rewrite on bridge-domain.
 *
 * @cliexpar
 * Example of how to enable rewrite (where 100 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain rewrite 100}
 * Example of how to disable rewrite (where 100 is the bridge-domain-id):
 * @cliexcmd{set bridge-domain rewrite 100 disable}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2_rw_set_cli, static) = {
  .path = "set bridge-domain rewrite",
  .short_help =
  "set bridge-domain rewrite <bridge-domain> [disable]",
  .function = l2_rw_set_cli_fn,
};
/* *INDENT-ON* */

static clib_error_t *
l2_rw_init (vlib_main_t * vm)
{
  l2_rw_main_t *rw = &l2_rw_main;
  rw->configs = 0;
  rw->entries = 0;
  clib_bitmap_alloc (rw->configs_bitmap, 1);
  feat_bitmap_init_next_nodes (vm,
			       l2_rw_node.index,
			       L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       rw->feat_next_node_index);
  return 0;
}

VLIB_INIT_FUNCTION (l2_rw_init);

enum
{
  L2_RW_NEXT_DROP,
  L2_RW_N_NEXT,
};

#define foreach_l2_rw_error               \
_(UNKNOWN, "Unknown error")

typedef enum
{
#define _(sym,str) L2_RW_ERROR_##sym,
  foreach_l2_rw_error
#undef _
    L2_RW_N_ERROR,
} l2_rw_error_t;

static char *l2_rw_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_rw_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l2_rw_node) = {
  .name = "l2-rw",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_rw_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(l2_rw_error_strings),
  .error_strings = l2_rw_error_strings,
  .runtime_data_bytes = 0,
  .n_next_nodes = L2_RW_N_NEXT,
  .next_nodes = { [L2_RW_NEXT_DROP]  = "error-drop"},
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
