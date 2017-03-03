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
/*
 *------------------------------------------------------------------
 * l2sess.c - simple MAC-swap API / debug CLI handling
 *------------------------------------------------------------------
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <acl/l2sess.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vlibsocket/api.h>
#include <vppinfra/timing_wheel.h>

#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_input.h>

void
l2sess_init_next_features (vlib_main_t * vm, l2sess_main_t * sm)
{
#define _(node_name, node_var, is_out, is_ip6, is_track)                 \
  if (is_out)                                                            \
    feat_bitmap_init_next_nodes(vm, node_var.index, L2OUTPUT_N_FEAT,      \
                                l2output_get_feat_names (),               \
                                sm->node_var ## _feat_next_node_index); \
  else                                                                   \
    feat_bitmap_init_next_nodes(vm, node_var.index, L2INPUT_N_FEAT,      \
                                l2input_get_feat_names (),               \
                                sm->node_var ## _feat_next_node_index);

  foreach_l2sess_node
#undef _
}

void
l2sess_add_our_next_nodes (vlib_main_t * vm, l2sess_main_t * sm,
			   u8 * prev_node_name, int add_output_nodes)
{
  vlib_node_t *n;
  n = vlib_get_node_by_name (vm, prev_node_name);
#define _(node_name, node_var, is_out, is_ip6, is_track) \
  if (is_out == add_output_nodes) { \
    u32 idx = vlib_node_add_next_with_slot(vm, n->index, node_var.index, ~0); \
    if (is_track) { \
      sm->next_slot_track_node_by_is_ip6_is_out[is_ip6][is_out] = idx; \
    } \
  }
  foreach_l2sess_node
#undef _
}

void
l2sess_setup_nodes (void)
{
  vlib_main_t *vm = vlib_get_main ();
  l2sess_main_t *sm = &l2sess_main;

  l2sess_init_next_features (vm, sm);

  l2sess_add_our_next_nodes (vm, sm, (u8 *) "l2-input-classify", 0);
  l2sess_add_our_next_nodes (vm, sm, (u8 *) "l2-output-classify", 1);

}

static char *
get_l4_proto_str (int is_ip6, uint8_t l4_proto)
{
  switch (l4_proto)
    {
    case 6:
      return "tcp";
    case 17:
      return "udp";
    case 1:
      return "icmp";
    case 58:
      return "icmp6";
    default:
      return "<?l4-unknown?>";
    }
}

static clib_error_t *
l2sess_show_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  l2sess_main_t *sm = &l2sess_main;
  clib_time_t *ct = &vm->clib_time;
  l2s_session_t *s;
  u64 now = clib_cpu_time_now ();

  vlib_cli_output (vm, "Timing wheel info: \n%U", format_timing_wheel,
		   &sm->timing_wheel, 255);

  pool_foreach (s, sm->sessions, (
				   {
				   f64 ctime =
				   (now -
				    s->create_time) * ct->seconds_per_clock;
				   f64 atime0 =
				   (now -
				    s->side[0].active_time) *
				   ct->seconds_per_clock;
				   f64 atime1 =
				   (now -
				    s->side[1].active_time) *
				   ct->seconds_per_clock;
/*
    f64 ctime = (s->create_time - vm->cpu_time_main_loop_start) * ct->seconds_per_clock;
    f64 atime0 = (s->side[0].active_time - vm->cpu_time_main_loop_start) * ct->seconds_per_clock;
    f64 atime1 = (s->side[1].active_time - vm->cpu_time_main_loop_start) * ct->seconds_per_clock;
*/
				   u8 * out0 =
				   format (0,
					   "%5d: create time: %U pkts/bytes/active time: [ %ld %ld %U : %ld %ld %U ]\n",
					   (s - sm->sessions),
					   format_time_interval, "h:m:s:u",
					   ctime, s->side[0].n_packets,
					   s->side[0].n_bytes,
					   format_time_interval, "h:m:s:u",
					   atime0, s->side[1].n_packets,
					   s->side[1].n_bytes,
					   format_time_interval, "h:m:s:u",
					   atime1); u8 * out1 = 0;
				   if (s->is_ip6)
				   {
				   out1 =
				   format (0, "%s %U :%u <-> %U :%u",
					   get_l4_proto_str (s->is_ip6,
							     s->l4_proto),
					   format_ip6_address,
					   &s->side[0].addr.ip6,
					   s->side[0].port,
					   format_ip6_address,
					   &s->side[1].addr.ip6,
					   s->side[1].port);}
				   else
				   {
				   out1 =
				   format (0, "%s %U :%u <-> %U :%u",
					   get_l4_proto_str (s->is_ip6,
							     s->l4_proto),
					   format_ip4_address,
					   &s->side[0].addr.ip4,
					   s->side[0].port,
					   format_ip4_address,
					   &s->side[1].addr.ip4,
					   s->side[1].port);}
				   vlib_cli_output (vm, "%s       %s", out0,
						    out1); vec_free (out0);
				   vec_free (out1);}
		));
  return 0;
}

static clib_error_t *
l2sess_show_count_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
  l2sess_main_t *sm = &l2sess_main;

  vlib_cli_output (vm, "Timing wheel info: \n%U", format_timing_wheel,
		   &sm->timing_wheel, 255);
  vlib_cli_output (vm, "session pool len: %d, pool elts: %d",
		   pool_len (sm->sessions), pool_elts (sm->sessions));
  vlib_cli_output (vm,
		   "attempted to delete sessions which were already free: %d",
		   sm->counter_attempted_delete_free_session);
  return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l2sess_show_command, static) = {
    .path = "show l2sess",
    .short_help = "show l2sess",
    .function = l2sess_show_command_fn,
};

VLIB_CLI_COMMAND (l2sess_show_count_command, static) = {
    .path = "show l2sess count",
    .short_help = "show l2sess count",
    .function = l2sess_show_count_command_fn,
};
/* *INDENT-OFF* */

static inline u64
time_sec_to_clock( clib_time_t *ct, f64 sec)
{
  return (u64)(((f64)sec)/ct->seconds_per_clock);
}

static clib_error_t * l2sess_init (vlib_main_t * vm)
{
  l2sess_main_t * sm = &l2sess_main;
  clib_error_t * error = 0;
  u64 cpu_time_now = clib_cpu_time_now();


  clib_time_t *ct = &vm->clib_time;
  sm->udp_session_idle_timeout = time_sec_to_clock(ct, UDP_SESSION_IDLE_TIMEOUT_SEC);
  sm->tcp_session_idle_timeout = time_sec_to_clock(ct, TCP_SESSION_IDLE_TIMEOUT_SEC);
  sm->tcp_session_transient_timeout = time_sec_to_clock(ct, TCP_SESSION_TRANSIENT_TIMEOUT_SEC);

  /* The min sched time of 10e-1 causes erroneous behavior... */
  sm->timing_wheel.min_sched_time = 10e-2;
  sm->timing_wheel.max_sched_time = 3600.0*48.0;
  timing_wheel_init (&sm->timing_wheel, cpu_time_now, vm->clib_time.clocks_per_second);
  sm->timer_wheel_next_expiring_time = 0;
  sm->timer_wheel_tick = time_sec_to_clock(ct, sm->timing_wheel.min_sched_time);
  /* Pre-allocate expired nodes. */
  vec_alloc (sm->data_from_advancing_timing_wheel, 32);

  l2sess_setup_nodes();
  l2output_init_output_node_vec (&sm->output_next_nodes.output_node_index_vec);

  return error;
}

VLIB_INIT_FUNCTION (l2sess_init);


