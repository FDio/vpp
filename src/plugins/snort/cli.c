/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
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

static clib_error_t *
snort_create_instance_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *err = 0;
  u8 *name = 0;
  u32 queue_size = 1024;
  u8 drop_on_disconnect = 1;
  int rv = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "queue-size %u", &queue_size))
	;
      else if (unformat (line_input, "on-disconnect drop"))
	drop_on_disconnect = 1;
      else if (unformat (line_input, "on-disconnect pass"))
	drop_on_disconnect = 0;
      else if (unformat (line_input, "name %s", &name))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (!is_pow2 (queue_size))
    {
      err = clib_error_return (0, "Queue size must be a power of two");
      goto done;
    }

  if (!name)
    {
      err = clib_error_return (0, "please specify instance name");
      goto done;
    }

  rv = snort_instance_create (vm,
			      &(snort_instance_create_args_t){
				.log2_queue_sz = min_log2 (queue_size),
				.drop_on_disconnect = drop_on_disconnect,
			      },
			      "%s", name);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_ENTRY_ALREADY_EXISTS:
      err = clib_error_return (0, "instance '%s' already exists", name);
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

done:
  vec_free (name);
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (snort_create_instance_command, static) = {
  .path = "snort create-instance",
  .short_help = "snort create-instance name <name> [queue-size <size>] "
		"[on-disconnect drop|pass]",
  .function = snort_create_instance_command_fn,
};

static clib_error_t *
snort_disconnect_client_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *err = 0;
  u8 *name = 0;
  int rv = 0;
  u32 client_index = SNORT_INVALID_CLIENT_INDEX;

  if (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    unformat (line_input, "%s", &name);

  if (!name)
    {
      err = clib_error_return (0, "please specify client name");
      goto done;
    }

  rv = snort_client_disconnect (vm, client_index);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      err = clib_error_return (0, "unknown client '%s'", name);
      break;
    default:
      err = clib_error_return (0, "snort_client_disconnect returned %d", rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (snort_disconnect_client_command, static) = {
  .path = "snort disconnect client",
  .short_help = "snort disconnect client <index>",
  .function = snort_disconnect_client_command_fn,
};

static clib_error_t *
snort_delete_instance_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *err = 0;
  u8 *name = 0;
  int rv = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "please specify instance name");

  if (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    unformat (line_input, "%s", &name);

  if (!name)
    {
      err = clib_error_return (0, "please specify instance name");
      goto done;
    }

  snort_instance_t *si = snort_get_instance_by_name ((char *) name);
  if (!si)
    err = clib_error_return (0, "unknown instance '%s' requested", name);
  else
    rv = snort_instance_delete (vm, si->index);

  switch (rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
      err = clib_error_return (0, "instance '%s' deletion failure", name);
      break;
    case VNET_API_ERROR_INSTANCE_IN_USE:
      err = clib_error_return (0, "instance '%s' has connected client", name);
      break;
    default:
      err = clib_error_return (0, "snort_instance_delete returned %d", rv);
      break;
    }

done:
  vec_free (name);
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (snort_delete_instance_command, static) = {
  .path = "snort delete instance",
  .short_help = "snort delete instance <name>",
  .function = snort_delete_instance_command_fn,
};

static clib_error_t *
snort_attach_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *err = NULL;
  u8 *name = NULL;
  u32 sw_if_index = ~0;
  int in = 0, out = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (line_input, "instance %s", &name))
	;
      else if (unformat (line_input, "input"))
	in = 1;
      else if (unformat (line_input, "output"))
	out = 1;
      else if (unformat (line_input, "inout"))
	in = out = 1;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      err = clib_error_return (0, "please specify interface");
      goto done;
    }

  if (!name)
    {
      err = clib_error_return (0, "please specify instance");
      goto done;
    }

  snort_attach_detach_instance (vm, vnm, (char *) name, sw_if_index,
				1 /* is_enable */, in, out);

done:
  vec_free (name);
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (snort_attach_command, static) = {
  .path = "snort attach",
  .short_help =
    "snort attach all-instances|(instance <name> [instance <name> [...]]) "
    "interface <if-name> "
    "[input|output|inout]",
  .function = snort_attach_command_fn,
};

static clib_error_t *
snort_detach_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *err = NULL;
  u8 *name = NULL;
  u32 sw_if_index = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "instance %s", &name))
	;
      else if (unformat (line_input, "interface %U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      err = clib_error_return (0, "please specify interface");
      goto done;
    }

  snort_attach_detach_instance (vm, vnm, (char *) name, sw_if_index,
				0 /* is_enable */, 1, 1);

done:
  vec_free (name);
  unformat_free (line_input);
  return err;
}

VLIB_CLI_COMMAND (snort_detach_command, static) = {
  .path = "snort detach",
  .short_help =
    "snort detach all-instances|(instance <name> [instance <name> [...]]) "
    "interface <if-name> ",
  .function = snort_detach_command_fn,
};

static clib_error_t *
snort_show_instances_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  snort_main_t *sm = &snort_main;
  snort_instance_t *si;

  pool_foreach (si, sm->instances)
    {
      vlib_cli_output (vm, "instance: %s (%u)", si->name, si->index);
      vlib_cli_output (vm, "  shared memory: size %u fd %d", si->shm_size,
		       si->shm_fd);
      vec_foreach_pointer (qp, si->qpairs)
	{
	  vlib_cli_output (vm, "  qpair: %u.%u", qp->qpair_id.thread_id,
			   qp->qpair_id.queue_id);
	  vlib_cli_output (vm, "    descriptors: total %u free %u", 1 << qp->log2_queue_size, qp->n_free_descs);
	  vlib_cli_output (vm, "    client: %d", qp->client_index);
	  vlib_cli_output (vm, "    cleanup needed: %d", qp->cleanup_needed);
	  vlib_cli_output (vm,
			   "    enqueue: ring_offset %u event_fd %d head %lu",
			   (u8 *) qp->enq_ring - (u8 *) si->shm_base,
			   qp->enq_fd, qp->hdr->enq_head);
	  vlib_cli_output (
	    vm, "    dequeue: ring_offset %u event_fd %d head %lu tail %lu",
	    (u8 *) qp->deq_ring - (u8 *) si->shm_base, qp->deq_fd,
	    qp->hdr->deq_head, qp->deq_tail);
	}
    }

  return 0;
}

VLIB_CLI_COMMAND (snort_show_instances_command, static) = {
  .path = "show snort instances",
  .short_help = "show snort instances",
  .function = snort_show_instances_command_fn,
};

static clib_error_t *
snort_show_interfaces_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
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
	s = format (s, "%U:\t%s", format_vnet_sw_if_index_name, vnm,
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
	s = format (s, "%U:\t%s", format_vnet_sw_if_index_name, vnm,
		    sw_if_index, si->name);
    }
  if (vec_len (s))
    vlib_cli_output (vm, "output instances:\n%v", s);

  vec_free (s);

  return 0;
}

VLIB_CLI_COMMAND (snort_show_interfaces_command, static) = {
  .path = "show snort interfaces",
  .short_help = "show snort interfaces",
  .function = snort_show_interfaces_command_fn,
};

static clib_error_t *
snort_show_clients_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
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
  .short_help = "show snort clients",
  .function = snort_show_clients_command_fn,
};
