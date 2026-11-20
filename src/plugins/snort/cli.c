/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/interface/cli_types.h>
#include <snort/snort.h>

static clib_error_t *
snort_attach_detach_instance (vlib_main_t *vm, vnet_main_t *vnm,
			      char *instance_name, u32 sw_if_index,
			      int is_enable, int in, int out)
{
  clib_error_t *err = NULL;
  int rv = snort_interface_enable_disable (vm, instance_name, sw_if_index,
					   is_enable, in, out);
  switch (rv)
    {
    case 0:
    case VNET_API_ERROR_FEATURE_ALREADY_ENABLED:
      /* already attached to same instance */
      break;
    case VNET_API_ERROR_INVALID_INTERFACE:
      err = clib_error_return (0,
			       "interface %U is not assigned to snort "
			       "instance %s!",
			       format_vnet_sw_if_index_name, vnm, sw_if_index,
			       instance_name);
      break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      err = clib_error_return (0, "unknown instance '%s'", instance_name);
      break;
    case VNET_API_ERROR_INSTANCE_IN_USE:
      err = clib_error_return (
	0, "interface %U is currently up, set state down first",
	format_vnet_sw_if_index_name, vnm, sw_if_index);
      break;
    default:
      err = clib_error_return (0, "snort_interface_enable_disable returned %d",
			       rv);
      break;
    }
  return err;
}

static const char *
next_instance_name (const cli_arg_t *a, u32 *iter, u32 *value, const char **help)
{
  snort_main_t *sm = &snort_main;

  while (*iter < vec_len (sm->instances))
    {
      u32 i = (*iter)++;

      if (pool_is_free_index (sm->instances, i))
	continue;

      *value = i;
      return (char *) pool_elt_at_index (sm->instances, i)->name;
    }
  return 0;
}

CLIB_CLI_TYPE (cli_type_snort_instance, static) = {
  .name = "instance",
  .help = "name of a snort instance",
  .next_name = next_instance_name,
  .parse = cli_names_parse,
  .complete = cli_names_complete,
};

static const cli_choice_t snort_on_disconnect_choices[] = {
  { "drop", "drop the packets", 1 },
  { "pass", "pass the packets", 0 },
  {},
};

static clib_error_t *
snort_create_instance_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  clib_error_t *err = 0;
  cli_value_t *name = cli_get (ctx, "name");
  u32 queue_size = cli_u64 (ctx, "queue-size", 1024);
  u32 empty_buf_queue_size = cli_u64 (ctx, "empty-buf-queue-size", 64);
  u32 qpairs_per_thread = cli_u64 (ctx, "queues-per-thread", 1);
  u8 drop_on_disconnect = cli_u64 (ctx, "on-disconnect", 1);
  int rv;

  if (!is_pow2 (queue_size))
    return clib_error_return (0, "Queue size must be a power of two");

  rv = snort_instance_create (
    vm,
    &(snort_instance_create_args_t) {
      .log2_queue_sz = min_log2 (queue_size),
      .log2_empty_buf_queue_sz = min_log2 (empty_buf_queue_size),
      .drop_on_disconnect = drop_on_disconnect,
      .drop_bitmap = 1 << DAQ_VPP_VERDICT_BLOCK | 1 << DAQ_VPP_VERDICT_BLACKLIST,
      .qpairs_per_thread = qpairs_per_thread,
    },
    "%v", name->str);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_ENTRY_ALREADY_EXISTS:
      err = clib_error_return (0, "instance '%v' already exists", name->str);
      break;
    case VNET_API_ERROR_SYSCALL_ERROR_1:
      err = clib_error_return (0, "memory fd failure: %U", format_clib_error,
			       clib_mem_get_last_error ());
      break;
    case VNET_API_ERROR_SYSCALL_ERROR_2:
      err = clib_error_return (0, "ftruncate failure");
      break;
    case VNET_API_ERROR_SYSCALL_ERROR_3:
      err = clib_error_return (0, "mmap failure");
      break;
    default:
      err = clib_error_return (0, "snort_instance_create returned %d", rv);
      break;
    }

  return err;
}

VLIB_CLI_COMMAND (snort_create_instance_command, static) = {
  .path = "snort create-instance",
  .short_help = "Create a snort instance",
  .args = CLI_ARGS (
    CLI_KEYWORD ("name", cli_type_string, .help = "instance name"),
    CLI_OPT_KEYWORD ("queue-size", cli_type_u32, .min = 1,
		     .help = "queue size, power of two, default 1024"),
    CLI_OPT_KEYWORD ("queues-per-thread", cli_type_u32, .min = 1, .help = "default 1"),
    CLI_OPT_KEYWORD ("empty-buf-queue-size", cli_type_u32, .min = 1, .help = "default 64"),
    CLI_OPT_KEYWORD ("on-disconnect", cli_type_enum, .choices = snort_on_disconnect_choices,
		     .help = "what to do with packets when the client disconnects, default drop")),
  .handler = snort_create_instance_command_fn,
};

static clib_error_t *
snort_disconnect_client_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  u32 client_index = cli_u64 (ctx, "index", 0);
  int rv = snort_client_disconnect (vm, client_index);

  switch (rv)
    {
    case 0:
      return 0;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "unknown client '%u'", client_index);
    default:
      return clib_error_return (0, "snort_client_disconnect returned %d", rv);
    }
}

VLIB_CLI_COMMAND (snort_disconnect_client_command, static) = {
  .path = "snort disconnect client",
  .short_help = "Disconnect a snort client",
  .args = CLI_ARGS (CLI_VALUE ("index", cli_type_u32, .max = SNORT_INVALID_CLIENT_INDEX - 1,
			       .help = "client index")),
  .handler = snort_disconnect_client_command_fn,
};

static clib_error_t *
snort_delete_instance_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  snort_instance_t *si = snort_get_instance_by_index (cli_index (ctx, "instance"));
  int rv = snort_instance_delete (vm, si->index);

  switch (rv)
    {
    case 0:
      return 0;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "instance '%s' deletion failure", si->name);
    case VNET_API_ERROR_INSTANCE_IN_USE:
      return clib_error_return (0, "instance '%s' has connected client", si->name);
    default:
      return clib_error_return (0, "snort_instance_delete returned %d", rv);
    }
}

VLIB_CLI_COMMAND (snort_delete_instance_command, static) = {
  .path = "snort delete instance",
  .short_help = "Delete a snort instance",
  .args = CLI_ARGS (CLI_VALUE ("instance", cli_type_snort_instance)),
  .handler = snort_delete_instance_command_fn,
};

#define SNORT_ATTACH_ARGS                                                                          \
  CLI_KEYWORD ("instance", cli_type_snort_instance),                                               \
    CLI_KEYWORD ("interface", cli_type_sw_interface),                                              \
    CLI_ONEOF ("direction", 0, CLI_FLAG ("input", .help = "traffic received on the interface"),    \
	       CLI_FLAG ("output", .help = "traffic sent on the interface"),                       \
	       CLI_FLAG ("inout", .help = "traffic in both directions"))

static clib_error_t *
snort_attach_detach_command (cli_ctx_t *ctx, int is_enable)
{
  snort_instance_t *si = snort_get_instance_by_index (cli_index (ctx, "instance"));
  int inout = cli_flag (ctx, "inout");

  return snort_attach_detach_instance (
    vlib_get_main (), vnet_get_main (), (char *) si->name, cli_index (ctx, "interface"), is_enable,
    inout || cli_flag (ctx, "input"), inout || cli_flag (ctx, "output"));
}

static clib_error_t *
snort_attach_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return snort_attach_detach_command (ctx, 1);
}

static clib_error_t *
snort_detach_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  return snort_attach_detach_command (ctx, 0);
}

VLIB_CLI_COMMAND (snort_attach_command, static) = {
  .path = "snort attach",
  .short_help = "Attach a snort instance to an interface",
  .args = CLI_ARGS (SNORT_ATTACH_ARGS),
  .handler = snort_attach_command_fn,
};

VLIB_CLI_COMMAND (snort_detach_command, static) = {
  .path = "snort detach",
  .short_help = "Detach a snort instance from an interface",
  .args = CLI_ARGS (SNORT_ATTACH_ARGS),
  .handler = snort_detach_command_fn,
};

static clib_error_t *
snort_show_instances_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;
  int verbose = cli_flag (ctx, "verbose");

  pool_foreach (si, sm->instances)
    {
      vlib_cli_output (vm, "instance: %s (%u)", si->name, si->index);
      vlib_cli_output (vm, "  shared memory: size %u fd %d", si->shm_size,
		       si->shm_fd);
      vlib_cli_output (vm, "  drop on disconnect: %u", si->drop_on_disconnect);

      vec_foreach_pointer (qp, si->qpairs)
	{
	  u64 n = 0;
	  u8 *s = 0;
	  vlib_cli_output (vm, "  qpair: %u.%u", qp->qpair_id.thread_id,
			   qp->qpair_id.queue_id);
	  vlib_cli_output (vm, "    descriptors: total %u free %u",
			   1 << qp->log2_queue_size, qp->n_free_descs);
	  vlib_cli_output (vm, "    client: %d", qp->client_index);
	  vlib_cli_output (vm, "    cleanup needed: %d", qp->cleanup_needed);
	  vlib_cli_output (vm,
			   "    enqueue: ring_offset %u event_fd %d head %lu",
			   (u8 *) qp->enq_ring - (u8 *) si->shm_base,
			   qp->enq_fd, qp->hdr->enq.head);
	  vlib_cli_output (
	    vm, "    dequeue: ring_offset %u event_fd %d head %lu tail %lu",
	    (u8 *) qp->deq_ring - (u8 *) si->shm_base, qp->deq_fd,
	    qp->hdr->deq.head, qp->deq_tail);

	  vlib_cli_output (vm,
			   "    empty-buf-queue: ring_offset %u ring_size %u "
			   "head %lu tail %lu",
			   (u8 *) qp->empty_buf_ring - (u8 *) si->shm_base,
			   1 << qp->log2_empty_buf_queue_size,
			   qp->hdr->deq.empty_buf_head, qp->empty_buf_tail);

	  for (u32 i = 0; i < DAQ_VPP_MAX_DAQ_VERDICT; i++)
	    if (qp->n_packets_by_verdict[i])
	      {
		n += qp->n_packets_by_verdict[i];
		s =
		  format (s, "%s%U: %lu", s ? ", " : "", format_snort_verdict,
			  i, qp->n_packets_by_verdict[i]);
	      }

	  if (s)
	    vlib_cli_output (vm, "    packets processed: %lu (%v)", n, s);
	  else
	    vlib_cli_output (vm, "    packets processed: 0");
	  vec_free (s);

	  if (verbose)
	    {
	      vlib_cli_output (vm, "   desc   buffer_index   next_index "
				   "  freelist_next                   desc\n");
	      vlib_cli_output (
		vm, "  ====== ============== ============ "
		    "=============== ====================================\n");
	      u32 total_desc = 1 << qp->log2_queue_size;
	      for (u32 i = 0; i < total_desc; i++)
		{
		  snort_qpair_entry_t *qpe = qp->entries + i;
		  daq_vpp_desc_t *d = qp->hdr->descs + i;
		  vlib_cli_output (vm, "  %-6d  %-12u   %-12u  %-14u %U", i,
				   qpe->buffer_index, qpe->next_index,
				   qpe->freelist_next, format_snort_desc, d);
		}
	    }
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (snort_show_instances_command, static) = {
  .path = "show snort instances",
  .short_help = "Show the snort instances",
  .args = CLI_ARGS (CLI_FLAG ("verbose", .help = "show the descriptors of each queue")),
  .handler = snort_show_instances_command_fn,
};

static clib_error_t *
snort_show_interfaces_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  snort_main_t *sm = &snort_main;
  vnet_main_t *vnm = vnet_get_main ();
  snort_instance_t *si;
  u32 sw_if_index;
  u8 *s = 0;

  vec_foreach_index (sw_if_index, sm->input_instance_by_interface)
    {
      si = snort_get_instance_by_index (
	sm->input_instance_by_interface[sw_if_index]);
      if (si)
	s = format (s, "%U:\t%s\n", format_vnet_sw_if_index_name, vnm,
		    sw_if_index, si->name);
    }
  if (vec_len (s))
    vlib_cli_output (vm, "input instances:\n%v", s);

  vec_reset_length (s);

  vec_foreach_index (sw_if_index, sm->output_instance_by_interface)
    {
      si = snort_get_instance_by_index (
	sm->output_instance_by_interface[sw_if_index]);
      if (si)
	s = format (s, "%U:\t%s\n", format_vnet_sw_if_index_name, vnm,
		    sw_if_index, si->name);
    }
  if (vec_len (s))
    vlib_cli_output (vm, "output instances:\n%v", s);

  vec_free (s);

  return 0;
}

VLIB_CLI_COMMAND (snort_show_interfaces_command, static) = {
  .path = "show snort interfaces",
  .short_help = "Show the interfaces snort instances are attached to",
  .handler = snort_show_interfaces_command_fn,
};

static clib_error_t *
snort_show_clients_command_fn (vlib_main_t *vm, cli_ctx_t *ctx)
{
  snort_main_t *sm = &snort_main;
  snort_client_t *c;

  vlib_cli_output (vm, "number of clients: %d", pool_elts (sm->clients));
  pool_foreach (c, sm->clients)
    {
      snort_client_qpair_t *cqp;
      vlib_cli_output (vm, "Client %u", c - sm->clients);
      vlib_cli_output (vm, "  DAQ version: %U", format_snort_daq_version,
		       c->daq_version);
      vlib_cli_output (vm, "  number of intstances: %u", c->n_instances);
      vlib_cli_output (vm, "  mode: %U", format_snort_mode, c->mode);
      vlib_cli_output (vm, "  inputs:");
      vec_foreach (cqp, c->qpairs)
	{
	  snort_instance_t *si;
	  snort_qpair_t *qp;
	  si = snort_get_instance_by_index (cqp->instance_index);
	  qp = *vec_elt_at_index (si->qpairs, cqp->qpair_index);
	  vlib_cli_output (vm, "    %s:%u.%u", si->name,
			   qp->qpair_id.thread_id, qp->qpair_id.queue_id);
	}
    }
  return 0;
}

VLIB_CLI_COMMAND (snort_show_clients_command, static) = {
  .path = "show snort clients",
  .short_help = "Show the snort clients",
  .handler = snort_show_clients_command_fn,
};
