/*
 * mdata.c - Buffer metadata change tracker
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <mdata/mdata.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/callback_data.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <mdata/mdata.api_enum.h>
#include <mdata/mdata.api_types.h>

#define REPLY_MSG_ID_BASE mmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

mdata_main_t mdata_main;

/** @file mdata.c
 * buffer metadata change tracker
 */

static mdata_t mdata_none;

/** Metadata tracking callback
    before_or_after: 0 => before, 1=> after
*/
static void
mdata_trace_callback (vlib_node_runtime_perf_callback_data_t * data,
		      vlib_node_runtime_perf_callback_args_t * args)
{
  int i;
  mdata_main_t *mm = &mdata_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u32 *from;
  u32 n_left_from;
  mdata_t *before, *modifies;
  u8 *after;
  vlib_main_t *vm = args->vm;
  vlib_frame_t *frame = args->frame;
  vlib_node_runtime_t *node = args->node;

  if (PREDICT_FALSE (args->call_type == VLIB_NODE_RUNTIME_PERF_RESET))
    return;

  /* Input nodes don't have frames, etc. */
  if (frame == 0)
    return;

  n_left_from = frame->n_vectors;

  if (n_left_from == 0)
    return;

  from = vlib_frame_vector_args (frame);

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;

  if (args->call_type == VLIB_NODE_RUNTIME_PERF_AFTER)
    goto after_pass;

  /* Resize the per-thread "before" vector to cover the current frame */
  vec_reset_length (mm->before_per_thread[vm->thread_index]);
  vec_validate (mm->before_per_thread[vm->thread_index], n_left_from - 1);
  before = mm->before_per_thread[vm->thread_index];
  before->node_index = ~0;

  /* Before we call the dispatch fn, copy metadata. */
  while (n_left_from > 0)
    {
      clib_memcpy_fast (before->mdata, b[0], sizeof (before->mdata));
      b++;
      before++;
      n_left_from--;
    }
  return;

after_pass:

  /* Recover the metadata copy we saved a moment ago */
  before = mm->before_per_thread[vm->thread_index];

  /* We'd better have the same number of buffers... */
  ASSERT (n_left_from == vec_len (before));
  ASSERT (node->node_index);

  clib_spinlock_lock_if_init (&mm->modify_lock);

  /*
   * Resize the per-node accumulator vector as needed
   * Paint the "no data" patter across any nodes we haven't seen yet
   */
  vec_validate_init_empty (mm->modifies, node->node_index, mdata_none);
  modifies = vec_elt_at_index (mm->modifies, node->node_index);
  modifies->node_index = node->node_index;
  before = mm->before_per_thread[vm->thread_index];

  /* Walk the frame */
  while (n_left_from > 0)
    {
      after = (u8 *) b[0];

      /* Compare metadata before and after node dispatch fn */
      for (i = 0; i < ARRAY_LEN (before->mdata); i++)
	{
	  /* Mark mdata octet changed */
	  if (before->mdata[i] != after[i])
	    modifies->mdata[i] = 0xff;
	}

      b++;
      before++;
      n_left_from--;
    }

  clib_spinlock_unlock_if_init (&mm->modify_lock);
}

int
mdata_enable_disable (mdata_main_t * mmp, int enable_disable)
{
  int rv = 0;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  int i;

  if (mmp->modify_lock == 0 && thread_main->n_vlib_mains > 1)
    clib_spinlock_init (&mmp->modify_lock);

  if (vec_len (mmp->before_per_thread) == 0)
    {
      mdata_none.node_index = ~0;
      vec_validate (mmp->before_per_thread, vec_len (vlib_mains) - 1);
    }

  /* Reset the per-node accumulator, see vec_validate_init_empty above */
  vec_reset_length (mmp->modifies);

  for (i = 0; i < vec_len (vlib_mains); i++)
    {
      if (vlib_mains[i] == 0)
	continue;

      clib_callback_data_enable_disable
	(&vlib_mains[i]->vlib_node_runtime_perf_callbacks,
	 mdata_trace_callback, enable_disable);
    }

  return rv;
}

static clib_error_t *
mdata_enable_disable_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  mdata_main_t *mmp = &mdata_main;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable") || unformat (input, "off"))
	enable_disable = 0;
      if (unformat (input, "enable") || unformat (input, "on"))
	enable_disable = 1;
      else
	break;
    }

  rv = mdata_enable_disable (mmp, enable_disable);

  switch (rv)
    {
    case 0:
      break;

    default:
      return clib_error_return (0, "mdata_enable_disable returned %d", rv);
    }
  return 0;
}

/*?
 * This command enables or disables buffer metadata change tracking
 *
 *@cliexpar
 * To enable buffer metadata change tracking:
 *@cliexstart{buffer metadata tracking on}
 * Tracking enabled
 *@cliexend
 *
 *@cliexstart{buffer metadata tracking off}
 * Tracking disabled
 *@cliexend
?*/

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (mdata_enable_disable_command, static) =
{
  .path = "buffer metadata tracking",
  .short_help = "buffer metadata tracking [on][off]",
  .function = mdata_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_mdata_enable_disable_t_handler
  (vl_api_mdata_enable_disable_t * mp)
{
  vl_api_mdata_enable_disable_reply_t *rmp;
  mdata_main_t *mmp = &mdata_main;
  int rv;

  rv = mdata_enable_disable (mmp, (int) (mp->enable_disable));

  REPLY_MACRO (VL_API_MDATA_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <mdata/mdata.api.c>

static clib_error_t *
mdata_init (vlib_main_t * vm)
{
  mdata_main_t *mmp = &mdata_main;
  clib_error_t *error = 0;

  mmp->vlib_main = vm;
  mmp->vnet_main = vnet_get_main ();

  /* Add our API messages to the global name_crc hash table */
  mmp->msg_id_base = setup_message_id_table ();

  return error;
}

VLIB_INIT_FUNCTION (mdata_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Buffer metadata change tracker."
};
/* *INDENT-ON* */


#define foreach_primary_metadata_field          \
_(current_data)                                 \
_(current_length)                               \
_(flags)                                        \
_(flow_id)                                      \
_(ref_count)                                    \
_(buffer_pool_index)                            \
_(error)                                        \
_(next_buffer)                                  \
_(current_config_index)                         \
_(punt_reason)

#define foreach_opaque_metadata_field           \
_(sw_if_index[0])                               \
_(sw_if_index[1])                               \
_(l2_hdr_offset)                                \
_(l3_hdr_offset)                                \
_(l4_hdr_offset)                                \
_(feature_arc_index)                            \
_(ip.adj_index)                                 \
_(ip.flow_hash)                                 \
_(ip.save_protocol)                             \
_(ip.fib_index)                                 \
_(ip.icmp.type)                                 \
_(ip.icmp.code)                                 \
_(ip.icmp.data)                                 \
_(ip.reass.next_index)                          \
_(ip.reass.error_next_index)                    \
_(ip.reass.owner_thread_index)                  \
_(ip.reass.ip_proto)                            \
_(ip.reass.l4_src_port)                         \
_(ip.reass.l4_dst_port)                         \
_(ip.reass.estimated_mtu)                       \
_(ip.reass.fragment_first)                      \
_(ip.reass.fragment_last)                       \
_(ip.reass.range_first)                         \
_(ip.reass.range_last)                          \
_(ip.reass.next_range_bi)                       \
_(ip.reass.ip6_frag_hdr_offset)                 \
_(mpls.ttl)                                     \
_(mpls.exp)                                     \
_(mpls.first)                                   \
_(mpls.save_rewrite_length)                     \
_(mpls.mpls_hdr_length)                         \
_(mpls.bier.n_bytes)                            \
_(l2.feature_bitmap)                            \
_(l2.bd_index)                                  \
_(l2.l2fib_sn)                                  \
_(l2.l2_len)                                    \
_(l2.shg)                                       \
_(l2.bd_age)                                    \
_(l2t.next_index)                               \
_(l2t.session_index)                            \
_(l2_classify.table_index)                      \
_(l2_classify.opaque_index)                     \
_(l2_classify.hash)                             \
_(policer.index)                                \
_(ipsec.sad_index)                              \
_(ipsec.protect_index)                          \
_(map.mtu)                                      \
_(map_t.map_domain_index)			\
_(map_t.v6.saddr)                               \
_(map_t.v6.daddr)                               \
_(map_t.v6.frag_offset)                         \
_(map_t.v6.l4_offset)                           \
_(map_t.v6.l4_protocol)                         \
_(map_t.checksum_offset)			\
_(map_t.mtu)                                    \
_(ip_frag.mtu)                                  \
_(ip_frag.next_index)                           \
_(ip_frag.flags)                                \
_(cop.current_config_index)                     \
_(lisp.overlay_afi)                             \
_(tcp.connection_index)                         \
_(tcp.seq_number)                               \
_(tcp.next_node_opaque)                         \
_(tcp.seq_end)                                  \
_(tcp.ack_number)                               \
_(tcp.hdr_offset)                               \
_(tcp.data_offset)                              \
_(tcp.data_len)                                 \
_(tcp.flags)                                    \
_(snat.flags)

#define foreach_opaque2_metadata_field          \
_(qos.bits)                                     \
_(qos.source)                                   \
_(loop_counter)                                 \
_(gbp.flags)                                    \
_(gbp.sclass)                                   \
_(gso_size)                                     \
_(gso_l4_hdr_sz)                                \
_(pg_replay_timestamp)

static u8 *
format_buffer_metadata_changes (u8 * s, va_list * args)
{
  mdata_main_t *mm = va_arg (*args, mdata_main_t *);
  int verbose = va_arg (*args, int);
  mdata_t *modifies;
  vlib_buffer_t *b;
  vnet_buffer_opaque_t *o;
  vnet_buffer_opaque2_t *o2;
  vlib_node_t *node;
  int i, j;
  int printed;

  clib_spinlock_lock_if_init (&mm->modify_lock);

  for (i = 0; i < vec_len (mm->modifies); i++)
    {
      modifies = vec_elt_at_index (mm->modifies, i);
      node = vlib_get_node (mm->vlib_main, i);

      /* No data for this node? */
      if (modifies->node_index == ~0)
	{
	  if (verbose)
	    s = format (s, "\n%v: no data\n", node->name);
	  continue;
	}

      /* We visited the node, but it may not have changed any metadata... */
      for (j = 0; j < ARRAY_LEN (modifies->mdata); j++)
	{
	  if (modifies->mdata[j])
	    goto found;
	}
      s = format (s, "\n%v: no metadata changes\n", node->name);
      continue;

    found:
      /* Fields which the node modifies will be non-zero */
      b = (vlib_buffer_t *) (modifies->mdata);

      /* Dump primary metadata changes */
      s = format (s, "\n%v: ", node->name);

      printed = 0;
#define _(n) if (b->n) {s = format (s, "%s ", #n); printed = 1;}
      foreach_primary_metadata_field;
#undef _

      if (printed == 0)
	s = format (s, "no vlib_buffer_t metadata changes");

      vec_add1 (s, '\n');

      /*
       * Dump opaque union changes.
       * Hopefully this will give folks a clue about opaque
       * union data conflicts. That's the point of the exercise...
       */
      o = vnet_buffer (b);
      printed = 0;
      s = format (s, "  vnet_buffer_t: ");

#define _(n) if (o->n) {s = format (s, "%s ", #n); printed = 1;}
      foreach_opaque_metadata_field;
#undef _

      if (printed == 0)
	s = format (s, "no changes");

      vec_add1 (s, '\n');

      o2 = vnet_buffer2 (b);
      printed = 0;
      s = format (s, "  vnet_buffer2_t: ");

#define _(n) if (o2->n) {s = format (s, "%s ", #n); printed = 1;}
      foreach_opaque2_metadata_field;
#undef _
      if (printed == 0)
	s = format (s, "no changes");

      vec_add1 (s, '\n');

    }

  clib_spinlock_unlock_if_init (&mm->modify_lock);

  return s;
}

static clib_error_t *
show_metadata_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  int verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %=", &verbose, 1))
	;
      else
	break;
    }

  vlib_cli_output (vm, "%U", format_buffer_metadata_changes, &mdata_main,
		   verbose);
  return 0;
}

/*?
 * This command displays buffer metadata change information
 *@cliexpar
 * How to display buffer metadata change information
 *@cliexstart{show buffer metadata}
 * ethernet-input: current_data current_length flags error
 * vnet_buffer_t: l2_hdr_offset l3_hdr_offset
 * vnet_buffer2_t: no changes
 *@cliexend
?*/

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_metadata_command, static) =
{
  .path = "show buffer metadata",
  .short_help = "show buffer metadata",
  .function = show_metadata_command_fn,
};
/* *INDENT-OFF* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
