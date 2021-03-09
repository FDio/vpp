#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

typedef struct
{
  u64 in;
  u64 out;
  u64 alloc;
  u64 free;
} bufmon_per_node_data_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  bufmon_per_node_data_t *pnd;
  u32 cur_node;
} bufmon_per_thread_data_t;

typedef struct
{
  bufmon_per_thread_data_t *ptd;
  int enabled;
} bufmon_main_t;

static bufmon_main_t bufmon_main;

static u32
bufmon_alloc_callback (vlib_main_t *vm, vlib_buffer_alloc_op_t op, u32 n)
{
  bufmon_main_t *bm = &bufmon_main;
  bufmon_per_thread_data_t *ptd;
  bufmon_per_node_data_t *pnd;

  if (vm->thread_index >= vec_len (bm->ptd))
    return n;

  ptd = vec_elt_at_index (bm->ptd, vm->thread_index);

  if (ptd->cur_node >= vec_len (ptd->pnd))
    return n;

  pnd = vec_elt_at_index (ptd->pnd, ptd->cur_node);

  switch (op)
    {
    case VLIB_BUFFER_ALLOC:
      pnd->alloc += n;
      break;
    case VLIB_BUFFER_FREE:
      pnd->free += n;
      break;
    }

  return n;
}

static u32
bufmon_count_buffers (vlib_main_t *vm, vlib_frame_t *frame)
{
  vlib_buffer_t *b[VLIB_FRAME_SIZE];
  u32 *from = vlib_frame_vector_args (frame);
  u32 n = frame->n_vectors;
  u32 nc = 0;
  u32 i;

  vlib_get_buffers (vm, from, b, n);

  for (i = 0; i < n; i++)
    {
      if (b[i]->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  vlib_buffer_t *cb;
	  do
	    {
	      cb = vlib_get_buffer (vm, b[i]->next_buffer);
	      nc++;
	    }
	  while (cb->flags & VLIB_BUFFER_NEXT_PRESENT);
	}
    }

  return n + nc;
}

static uword
bufmon_dispatch_wrapper (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame)
{
  vlib_node_main_t *nm = &vm->node_main;
  bufmon_main_t *bm = &bufmon_main;
  bufmon_per_thread_data_t *ptd;
  bufmon_per_node_data_t *pnd;
  int pending_frames;
  uword rv;

  vec_validate_aligned (bm->ptd, vm->thread_index, CLIB_CACHE_LINE_BYTES);
  ptd = vec_elt_at_index (bm->ptd, vm->thread_index);
  vec_validate_aligned (ptd->pnd, node->node_index, CLIB_CACHE_LINE_BYTES);
  pnd = vec_elt_at_index (ptd->pnd, node->node_index);

  if (frame)
    pnd->in += bufmon_count_buffers (vm, frame);

  pending_frames = vec_len (nm->pending_frames);
  ptd->cur_node = node->node_index;

  rv = node->function (vm, node, frame);

  ptd->cur_node = ~0;
  for (; pending_frames < vec_len (nm->pending_frames); pending_frames++)
    {
      vlib_pending_frame_t *p =
	vec_elt_at_index (nm->pending_frames, pending_frames);
      pnd->out += bufmon_count_buffers (vm, vlib_get_frame (vm, p->frame));
    }

  return rv;
}

static void
bufmon_unregister_callbacks (vlib_main_t *vm)
{
  int i;
  vlib_buffer_set_alloc_callback (vm, 0);
  for (i = 0; i < vec_len (vlib_mains); i++)
    vlib_node_set_dispatch_wrapper (vlib_mains[i], 0);
}

static clib_error_t *
bufmon_register_callbacks (vlib_main_t *vm)
{
  int i;

  if (vlib_buffer_set_alloc_callback (vm, bufmon_alloc_callback))
    goto err0;

  for (i = 0; i < vec_len (vlib_mains); i++)
    if (vlib_node_set_dispatch_wrapper (vlib_mains[i],
					bufmon_dispatch_wrapper))
      goto err1;

  return 0;

err1:
  for (i--; i >= 0; i--)
    vlib_node_set_dispatch_wrapper (vlib_mains[i], 0);
err0:
  vlib_buffer_set_alloc_callback (vm, 0);
  return clib_error_return (0, "failed to register callback");
}

static clib_error_t *
bufmon_enable_disable (vlib_main_t *vm, int enable)
{
  bufmon_main_t *bm = &bufmon_main;

  if (enable)
    {
      if (bm->enabled)
	return 0;
      clib_error_t *error = bufmon_register_callbacks (vm);
      if (error)
	return error;
      bm->enabled = 1;
    }
  else
    {
      if (!bm->enabled)
	return 0;
      bufmon_unregister_callbacks (vm);
      bm->enabled = 0;
    }

  return 0;
}

static clib_error_t *
set_buffer_traces (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  int on = 1;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "on"))
	    on = 1;
	  else if (unformat (line_input, "off"))
	    on = 0;
	  else
	    {
	      unformat_free (line_input);
	      return clib_error_return (0, "unknown input `%U'",
					format_unformat_error, line_input);
	    }
	}
      unformat_free (line_input);
    }

  return bufmon_enable_disable (vm, on);
}

VLIB_CLI_COMMAND (set_buffer_traces_command, static) = {
  .path = "set buffer traces",
  .short_help = "set buffer traces [on|off]",
  .function = set_buffer_traces,
};

static clib_error_t *
show_buffer_traces (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  const bufmon_main_t *bm = &bufmon_main;
  const bufmon_per_thread_data_t *ptd;
  const bufmon_per_node_data_t *pnd;
  int verbose = 0;
  int status = 0;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "verbose"))
	    verbose = 1;
	  else if (unformat (line_input, "status"))
	    status = 1;
	  else
	    {
	      unformat_free (line_input);
	      return clib_error_return (0, "unknown input `%U'",
					format_unformat_error, line_input);
	    }
	}
      unformat_free (line_input);
    }

  if (status)
    {
      vlib_cli_output (vm, "buffers tracing is %s",
		       bm->enabled ? "on" : "off");
      return 0;
    }

  vlib_cli_output (vm, "%30s%20s%20s%20s%20s%20s", "Node", "Allocated",
		   "Freed", "In", "Out", "Buffered");
  vec_foreach (ptd, bm->ptd)
    {
      vec_foreach (pnd, ptd->pnd)
	{
	  const u64 in = pnd->alloc + pnd->in;
	  const u64 out = pnd->free + pnd->out;
	  const i64 buffered = in - out;
	  if (0 == in && 0 == out)
	    continue; /* skip nodes w/o activity */
	  if (0 == buffered && !verbose)
	    continue; /* if not verbose, skip nodes w/o buffered buffers */
	  vlib_cli_output (vm, "%30U%20lu%20lu%20lu%20lu%20ld",
			   format_vlib_node_name, vm, pnd - ptd->pnd,
			   pnd->alloc, pnd->free, pnd->in, pnd->out, buffered);
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (show_buffer_traces_command, static) = {
  .path = "show buffer traces",
  .short_help = "show buffer traces [status|verbose]",
  .function = show_buffer_traces,
};

static clib_error_t *
clear_buffer_traces (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  const bufmon_main_t *bm = &bufmon_main;
  const bufmon_per_thread_data_t *ptd;
  const bufmon_per_node_data_t *pnd;

  vec_foreach (ptd, bm->ptd)
    vec_foreach (pnd, ptd->pnd)
      vec_reset_length (pnd);

  return 0;
}

VLIB_CLI_COMMAND (clear_buffers_trace_command, static) = {
  .path = "clear buffer traces",
  .short_help = "clear buffer traces",
  .function = clear_buffer_traces,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Buffers monitoring plugin",
};
