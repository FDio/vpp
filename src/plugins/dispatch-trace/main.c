/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

typedef struct
{
  u8 *pcap_buffer;
} dispatch_trace_thread_t;

typedef struct
{
  u32 enable : 1;
  pcap_main_t dispatch_pcap_main;
  u32 *dispatch_buffer_trace_nodes;
  dispatch_trace_thread_t *threads;
  u32 epoll_input_node_index;
} dispatch_trace_main_t;

dispatch_trace_main_t dispatch_trace_main;

#define VLIB_PCAP_MAJOR_VERSION 1
#define VLIB_PCAP_MINOR_VERSION 0

typedef struct
{
  u8 *filename;
  int enable;
  int status;
  int post_mortem;
  u32 packets_to_capture;
  u32 buffer_trace_node_index;
  u32 buffer_traces_to_capture;
} vlib_pcap_dispatch_trace_args_t;

static u8 *
format_buffer_metadata (u8 *s, va_list *args)
{
  vlib_buffer_t *b = va_arg (*args, vlib_buffer_t *);

  s = format (s, "flags: %U\n", format_vnet_buffer_flags, b);
  s = format (s, "current_data: %d, current_length: %d\n",
	      (i32) (b->current_data), (i32) (b->current_length));
  s = format (
    s, "current_config_index/punt_reason: %d, flow_id: %x, next_buffer: %x\n",
    b->current_config_index, b->flow_id, b->next_buffer);
  s = format (s, "error: %d, ref_count: %d, buffer_pool_index: %d\n",
	      (u32) (b->error), (u32) (b->ref_count),
	      (u32) (b->buffer_pool_index));
  s = format (s, "trace_handle: 0x%x, len_not_first_buf: %d\n",
	      b->trace_handle, b->total_length_not_including_first_buffer);
  return s;
}

#define A(x) vec_add1 (dtt->pcap_buffer, (x))

uword
dispatch_pcap_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame)
{
  int i;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **bufp, *b;
  dispatch_trace_main_t *dtm = &dispatch_trace_main;
  pcap_main_t *pm = &dtm->dispatch_pcap_main;
  dispatch_trace_thread_t *dtt =
    vec_elt_at_index (dtm->threads, vm->thread_index);
  vlib_trace_main_t *tm = &vm->trace_main;
  u32 capture_size;
  vlib_node_t *n;
  i32 n_left;
  f64 time_now = vlib_time_now (vm);
  u32 *from;
  u8 *d;
  u8 string_count;

  /* Input nodes don't have frames yet */
  if (frame == 0 || frame->n_vectors == 0)
    goto done;

  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, frame->n_vectors);
  bufp = bufs;

  n = vlib_get_node (vm, node->node_index);

  for (i = 0; i < frame->n_vectors; i++)
    {
      if (PREDICT_TRUE (pm->n_packets_captured < pm->n_packets_to_capture))
	{
	  b = bufp[i];

	  vec_reset_length (dtt->pcap_buffer);
	  string_count = 0;

	  /* Version, flags */
	  A ((u8) VLIB_PCAP_MAJOR_VERSION);
	  A ((u8) VLIB_PCAP_MINOR_VERSION);
	  A (0 /* string_count */);
	  A (n->protocol_hint);

	  /* Buffer index (big endian) */
	  A ((from[i] >> 24) & 0xff);
	  A ((from[i] >> 16) & 0xff);
	  A ((from[i] >> 8) & 0xff);
	  A ((from[i] >> 0) & 0xff);

	  /* Node name, NULL-terminated ASCII */
	  dtt->pcap_buffer = format (dtt->pcap_buffer, "%v%c", n->name, 0);
	  string_count++;

	  dtt->pcap_buffer =
	    format (dtt->pcap_buffer, "%U%c", format_buffer_metadata, b, 0);
	  string_count++;
	  dtt->pcap_buffer =
	    format (dtt->pcap_buffer, "%U%c", format_vnet_buffer_opaque, b, 0);
	  string_count++;
	  dtt->pcap_buffer = format (dtt->pcap_buffer, "%U%c",
				     format_vnet_buffer_opaque2, b, 0);
	  string_count++;

	  /* Is this packet traced? */
	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      vlib_trace_header_t **h = pool_elt_at_index (
		tm->trace_buffer_pool, vlib_buffer_get_trace_index (b));

	      dtt->pcap_buffer = format (dtt->pcap_buffer, "%U%c",
					 format_vlib_trace, vm, h[0], 0);
	      string_count++;
	    }

	  /* Save the string count */
	  dtt->pcap_buffer[2] = string_count;

	  /* Figure out how many bytes in the pcap trace */
	  capture_size =
	    vec_len (dtt->pcap_buffer) + +vlib_buffer_length_in_chain (vm, b);

	  clib_spinlock_lock_if_init (&pm->lock);
	  n_left = clib_min (capture_size, 16384);
	  d = pcap_add_packet (pm, time_now, n_left, capture_size);

	  /* Copy the header */
	  clib_memcpy_fast (d, dtt->pcap_buffer, vec_len (dtt->pcap_buffer));
	  d += vec_len (dtt->pcap_buffer);

	  n_left = clib_min (vlib_buffer_length_in_chain (vm, b),
			     (16384 - vec_len (dtt->pcap_buffer)));
	  /* Copy the packet data */
	  while (1)
	    {
	      u32 copy_length = clib_min ((u32) n_left, b->current_length);
	      clib_memcpy_fast (d, b->data + b->current_data, copy_length);
	      n_left -= b->current_length;
	      if (n_left <= 0)
		break;
	      d += b->current_length;
	      ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
	      b = vlib_get_buffer (vm, b->next_buffer);
	    }
	  clib_spinlock_unlock_if_init (&pm->lock);
	}
    }
done:
  return node->function (vm, node, frame);
}

static void
pcap_postmortem_reset (vlib_main_t *vm)
{
  dispatch_trace_main_t *dtm = &dispatch_trace_main;
  pcap_main_t *pm = &dtm->dispatch_pcap_main;

  /* Reset the trace buffer and capture count */
  clib_spinlock_lock_if_init (&pm->lock);
  vec_reset_length (pm->pcap_data);
  pm->n_packets_captured = 0;
  if (vec_len (vlib_worker_threads) == 1 && dtm->epoll_input_node_index)
    {
      vlib_node_runtime_t *epoll_input_rt =
	vlib_node_get_runtime (vm, dtm->epoll_input_node_index);
      epoll_input_rt->input_main_loops_per_call = 0;
    }
  clib_spinlock_unlock_if_init (&pm->lock);
}

static void
pcap_postmortem_dump (void)
{
  dispatch_trace_main_t *dtm = &dispatch_trace_main;
  pcap_main_t *pm = &dtm->dispatch_pcap_main;
  clib_error_t *error;

  pm->n_packets_to_capture = pm->n_packets_captured;
  pm->file_name =
    (char *) format (0, "/tmp/dispatch_post_mortem.%d%c", getpid (), 0);
  error = pcap_write (pm);
  pcap_close (pm);
  if (error)
    clib_error_report (error);
  /*
   * We're in the middle of crashing. Don't try to free the filename.
   */
}
static int
vlib_pcap_dispatch_trace_configure (vlib_pcap_dispatch_trace_args_t *a)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  dispatch_trace_main_t *dtm = &dispatch_trace_main;
  pcap_main_t *pm = &dtm->dispatch_pcap_main;
  vlib_trace_main_t *tm;
  vlib_trace_node_t *tn;

  vec_validate (dtm->threads, vtm->n_vlib_mains);

  if (a->status)
    {
      if (dtm->enable)
	{
	  int i;
	  vlib_cli_output (vm,
			   "pcap dispatch capture enabled: %d of %d pkts...",
			   pm->n_packets_captured, pm->n_packets_to_capture);
	  vlib_cli_output (vm, "capture to file %s", pm->file_name);

	  for (i = 0; i < vec_len (dtm->dispatch_buffer_trace_nodes); i++)
	    {
	      vlib_cli_output (
		vm, "Buffer trace of %d pkts from %U enabled...",
		a->buffer_traces_to_capture, format_vlib_node_name, vm,
		dtm->dispatch_buffer_trace_nodes[i]);
	    }
	}
      else
	vlib_cli_output (vm, "pcap dispatch capture disabled");
      return 0;
    }

  /* Consistency checks */

  /* Enable w/ capture already enabled not allowed */
  if (dtm->enable && a->enable)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Disable capture with capture already disabled, not interesting */
  if (dtm->enable == 0 && a->enable == 0)
    return VNET_API_ERROR_VALUE_EXIST;

  /* Change number of packets to capture while capturing */
  if (dtm->enable && a->enable &&
      (pm->n_packets_to_capture != a->packets_to_capture))
    return VNET_API_ERROR_INVALID_VALUE_2;

  /* Independent of enable/disable, to allow buffer trace multi nodes */
  if (a->buffer_trace_node_index != ~0)
    {
      foreach_vlib_main ()
	{
	  tm = &this_vlib_main->trace_main;
	  tm->verbose = 0; /* not sure this ever did anything... */
	  vec_validate (tm->nodes, a->buffer_trace_node_index);
	  tn = tm->nodes + a->buffer_trace_node_index;
	  tn->limit += a->buffer_traces_to_capture;
	  if (a->post_mortem)
	    {
	      tm->filter_flag = FILTER_FLAG_POST_MORTEM;
	      tm->filter_count = ~0;
	    }
	  tm->trace_enable = 1;
	  if (vlib_node_set_dispatch_wrapper (this_vlib_main,
					      dispatch_pcap_trace))
	    clib_warning (0, "Dispatch wrapper already in use on thread %u",
			  this_vlib_main->thread_index);
	}
      vec_add1 (dtm->dispatch_buffer_trace_nodes, a->buffer_trace_node_index);
    }

  if (a->enable)
    {
      /* Clean up from previous run, if any */
      vec_free (pm->file_name);
      vec_free (pm->pcap_data);
      memset (pm, 0, sizeof (*pm));

      vec_validate_aligned (vnet_trace_placeholder, 2048,
			    CLIB_CACHE_LINE_BYTES);
      if (pm->lock == 0)
	clib_spinlock_init (&(pm->lock));

      if (a->filename == 0)
	a->filename = format (0, "/tmp/dispatch.pcap%c", 0);

      pm->file_name = (char *) a->filename;
      pm->n_packets_captured = 0;
      pm->packet_type = PCAP_PACKET_TYPE_vpp;
      pm->n_packets_to_capture = a->packets_to_capture;
      dtm->enable = 1;
    }
  else
    {
      dtm->enable = 0;
      foreach_vlib_main ()
	{
	  tm = &this_vlib_main->trace_main;
	  tm->filter_flag = 0;
	  tm->filter_count = 0;
	  vlib_node_set_dispatch_wrapper (this_vlib_main, 0);
	}
      vec_reset_length (dtm->dispatch_buffer_trace_nodes);
      if (pm->n_packets_captured)
	{
	  clib_error_t *error;
	  pm->n_packets_to_capture = pm->n_packets_captured;
	  vlib_cli_output (vm, "Write %d packets to %s, and stop capture...",
			   pm->n_packets_captured, pm->file_name);
	  error = pcap_write (pm);
	  if (pm->flags & PCAP_MAIN_INIT_DONE)
	    pcap_close (pm);
	  /* Report I/O errors... */
	  if (error)
	    {
	      clib_error_report (error);
	      return VNET_API_ERROR_SYSCALL_ERROR_1;
	    }
	  return 0;
	}
      else
	return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  vlib_node_t *epoll_input_node =
    vlib_get_node_by_name (vm, (u8 *) "unix-epoll-input");

  /* Save the input node index, see the post-mortem callback */
  if (epoll_input_node)
    dtm->epoll_input_node_index = epoll_input_node->index;

  /* main thread only */
  clib_callback_enable_disable (vm->worker_thread_main_loop_callbacks,
				vm->worker_thread_main_loop_callback_tmp,
				vm->worker_thread_main_loop_callback_lock,
				pcap_postmortem_reset, a->post_mortem);
  vlib_add_del_post_mortem_callback (pcap_postmortem_dump, a->post_mortem);

  return 0;
}

static clib_error_t *
dispatch_trace_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_pcap_dispatch_trace_args_t _a, *a = &_a;
  u8 *filename = 0;
  u32 max = 1000;
  int rv;
  int enable = 0;
  int status = 0;
  int post_mortem = 0;
  u32 node_index = ~0, buffer_traces_to_capture = 100;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on %=", &enable, 1))
	;
      else if (unformat (line_input, "enable %=", &enable, 1))
	;
      else if (unformat (line_input, "off %=", &enable, 0))
	;
      else if (unformat (line_input, "disable %=", &enable, 0))
	;
      else if (unformat (line_input, "max %d", &max))
	;
      else if (unformat (line_input, "packets-to-capture %d", &max))
	;
      else if (unformat (line_input, "file %U", unformat_vlib_tmpfile,
			 &filename))
	;
      else if (unformat (line_input, "status %=", &status, 1))
	;
      else if (unformat (line_input, "buffer-trace %U %d", unformat_vlib_node,
			 vm, &node_index, &buffer_traces_to_capture))
	;
      else if (unformat (line_input, "post-mortem %=", &post_mortem, 1))
	;
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, line_input);
	}
    }

  unformat_free (line_input);

  /* no need for memset (a, 0, sizeof (*a)), set all fields here. */
  a->filename = filename;
  a->enable = enable;
  a->status = status;
  a->packets_to_capture = max;
  a->buffer_trace_node_index = node_index;
  a->buffer_traces_to_capture = buffer_traces_to_capture;
  a->post_mortem = post_mortem;

  rv = vlib_pcap_dispatch_trace_configure (a);

  switch (rv)
    {
    case 0:
      break;

    case -7:
      return clib_error_return (0, "dispatch trace already enabled...");

    case -81:
      return clib_error_return (0, "dispatch trace already disabled...");

    case -8:
      return clib_error_return (
	0, "can't change number of records to capture while tracing...");

    case -11:
      return clib_error_return (0, "I/O writing trace capture...");

    case -6:
      return clib_error_return (0, "No packets captured...");

    default:
      vlib_cli_output (vm, "WARNING: trace configure returned %d", rv);
      break;
    }
  return 0;
}

/*?
 * This command is used to start or stop pcap dispatch trace capture, or show
 * the capture status.
 *
 * This command has the following optional parameters:
 *
 * - <b>on|off</b> - Used to start or stop capture.
 *
 * - <b>max <nn></b> - Depth of local buffer. Once '<em>nn</em>' number
 *   of packets have been received, buffer is flushed to file. Once another
 *   '<em>nn</em>' number of packets have been received, buffer is flushed
 *   to file, overwriting previous write. If not entered, value defaults
 *   to 100. Can only be updated if packet capture is off.
 *
 * - <b>file <name></b> - Used to specify the output filename. The file will
 *   be placed in the '<em>/tmp</em>' directory, so only the filename is
 *   supported. Directory should not be entered. If file already exists, file
 *   will be overwritten. If no filename is provided, '<em>/tmp/vpe.pcap</em>'
 *   will be used. Can only be updated if packet capture is off.
 *
 * - <b>status</b> - Displays the current status and configured attributes
 *   associated with a packet capture. If packet capture is in progress,
 *   '<em>status</em>' also will return the number of packets currently in
 *   the local buffer. All additional attributes entered on command line
 *   with '<em>status</em>' will be ignored and not applied.
 *
 * @cliexpar
 * Example of how to display the status of capture when off:
 * @cliexstart{pcap dispatch trace status}
 * max is 100, for any interface to file /tmp/vpe.pcap
 * pcap dispatch capture is off...
 * @cliexend
 * Example of how to start a dispatch trace capture:
 * @cliexstart{pcap dispatch trace on max 35 file dispatchTrace.pcap}
 * pcap dispatch capture on...
 * @cliexend
 * Example of how to start a dispatch trace capture with buffer tracing
 * @cliexstart{pcap dispatch trace on max 10000 file dispatchTrace.pcap
 *   buffer-trace dpdk-input 1000}
 * pcap dispatch capture on...
 * @cliexend
 * Example of how to display the status of a tx packet capture in progress:
 * @cliexstart{pcap trace tx status}
 * max is 35, dispatch trace to file /tmp/vppTest.pcap
 * pcap tx capture is on: 20 of 35 pkts...
 * @cliexend
 * Example of how to stop a tx packet capture:
 * @cliexstart{vppctl pcap dispatch trace off}
 * captured 21 pkts...
 * saved to /tmp/dispatchTrace.pcap...
 * Example of how to start a post-mortem dispatch trace:
 * pcap dispatch trace on max 20000 buffer-trace
 *     dpdk-input 3000000000 post-mortem
 * @cliexend
?*/

VLIB_CLI_COMMAND (pcap_dispatch_trace_command, static) = {
  .path = "pcap dispatch trace",
  .short_help =
    "pcap dispatch trace [on|off] [max <nn>] [file <name>] [status]\n"
    "              [buffer-trace <input-node-name> <nn>][post-mortem]",
  .function = dispatch_trace_command_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Dispatch Trace",
};
