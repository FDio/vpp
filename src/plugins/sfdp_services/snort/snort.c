/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/snort/snort.h>

sfdp_snort_main_t sfdp_snort_main;

static snort_instance_create_fn_t *snort_instance_create_ptr = 0;
static snort_instance_delete_fn_t *snort_instance_delete_ptr = 0;
static snort_instance_get_index_by_name_fn_t *snort_instance_get_index_by_name_ptr = 0;

clib_error_t *
sfdp_snort_set_functions (void)
{
  clib_error_t *err = 0;
  snort_instance_create_ptr = vlib_get_plugin_symbol ("snort_plugin.so", "snort_instance_create");
  if (!snort_instance_create_ptr)
    {
      err = clib_error_return (0, "Could not find symbol snort_instance_create");
      goto done;
    }

  snort_instance_delete_ptr = vlib_get_plugin_symbol ("snort_plugin.so", "snort_instance_delete");
  if (!snort_instance_delete_ptr)
    {
      err = clib_error_return (0, "Could not find symbol snort_instance_delete");
      goto done;
    }

  snort_instance_get_index_by_name_ptr =
    vlib_get_plugin_symbol ("snort_plugin.so", "snort_instance_get_index_by_name");
  if (!snort_instance_get_index_by_name_ptr)
    {
      err = clib_error_return (0, "Could not find symbol snort_instance_get_index_by_name");
      goto done;
    }

done:
  return err;
}

static inline clib_error_t *
sfdp_snort_add_next_node (vlib_main_t *vm, u8 *name)
{
  sfdp_snort_main_t *vsm = &sfdp_snort_main;
  clib_error_t *err = 0;
  u8 *deq_node_name = 0;

  snort_instance_get_index_by_name_ptr (vm, (char *) name, &vsm->instance_index);

  vsm->snort_enq_next_index = vlib_node_add_named_next (vm, sfdp_snort_input.index, "snort-enq");

  deq_node_name = format (0, "snort-deq-%s", name);
  vlib_node_t *node = vlib_get_node_by_name (vm, deq_node_name);

  if (!node)
    {
      err = clib_error_return (0, "snort dequeue node 'snort-deq-%s' not found", name);
      goto done;
    }

  vsm->snort_dequeue_node_index = node->index;
  vsm->snort_dequeue_node_next_index =
    vlib_node_add_named_next (vm, node->index, "sfdp-snort-output");
  if (vsm->snort_dequeue_node_next_index == ~0)
    {
      err = clib_error_return (0, "failed to add snort dequeue next node");
      goto done;
    }

done:
  vec_free (deq_node_name);
  return err;
}

static clib_error_t *
sfdp_snort_create_instance_command_fn (vlib_main_t *vm, unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  sfdp_snort_main_t *vsm = &sfdp_snort_main;
  clib_error_t *err = 0;
  u8 *name = 0;
  u32 queue_size = 1024;
  u32 empty_buf_queue_size = 64;
  u32 qpairs_per_thread = 1;
  u8 drop_on_disconnect = 1;
  int rv = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "queue-size %u", &queue_size))
	;
      else if (unformat (input, "queues-per-thread %u", &qpairs_per_thread))
	;
      else if (unformat (input, "empty-buf-queue-size %u", &empty_buf_queue_size))
	;
      else if (unformat (input, "on-disconnect drop"))
	drop_on_disconnect = 1;
      else if (unformat (input, "on-disconnect pass"))
	drop_on_disconnect = 0;
      else if (unformat (input, "name %s", &name))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
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

  if (snort_instance_create_ptr == 0)
    {
      err = sfdp_snort_set_functions ();
      if (err)
	{
	  err = clib_error_return (err, "snort instance create function not set");
	  goto done;
	}
    }

  rv = snort_instance_create_ptr (
    vm,
    &(snort_instance_create_args_t){
      .log2_queue_sz = min_log2 (queue_size),
      .log2_empty_buf_queue_sz = min_log2 (empty_buf_queue_size),
      .drop_on_disconnect = drop_on_disconnect,
      .drop_bitmap = 1 << SFDP_DAQ_VERDICT_BLOCK | 1 << SFDP_DAQ_VERDICT_BLACKLIST,
      .qpairs_per_thread = qpairs_per_thread,
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

  err = sfdp_snort_add_next_node (vm, name);
  if (err)
    snort_instance_delete_ptr (vm, vsm->instance_index);

done:
  vec_free (name);
  return err;
}

VLIB_CLI_COMMAND (sfdp_snort_create_instance_command, static) = {
  .path = "sfdp snort create-instance",
  .short_help = "sfdp snort create-instance name <name> [queue-size <size>] "
		"[queues-per-thread <n>] [empty-buf-queue-size <size>] "
		"[on-disconnect drop|pass]",
  .function = sfdp_snort_create_instance_command_fn,
};

static clib_error_t *
sfdp_snort_delete_instance_command_fn (vlib_main_t *vm, unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  u16 instance_index = ~0;
  int rv = 0;
  u8 *name = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &name))
	;
      else
	{
	  err = clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
	  goto done;
	}
    }

  if (!name)
    {
      err = clib_error_return (0, "please specify instance name");
      goto done;
    }

  if (snort_instance_get_index_by_name_ptr == 0 || snort_instance_delete_ptr == 0)
    {
      err = sfdp_snort_set_functions ();
      if (err)
	{
	  err = clib_error_return (err, "snort instance delete function not set");
	  goto done;
	}
    }

  rv = snort_instance_get_index_by_name_ptr (vm, (char *) name, &instance_index);
  if (rv < 0)
    {
      err = clib_error_return (0, "snort_instance_get_index_by_name failed: %d, %U", (int) rv,
			       format_vnet_api_errno, rv);
      goto done;
    }

  rv = snort_instance_delete_ptr (vm, instance_index);
  if (rv < 0)
    {
      err = clib_error_return (0, "snort_instance_delete failed: %d,  %U", (int) rv,
			       format_vnet_api_errno, rv);
      goto done;
    }
done:
  vec_free (name);
  return err;
}

VLIB_CLI_COMMAND (sfdp_snort_delete_instance_command, static) = {
  .path = "sfdp snort delete-instance",
  .short_help = "sfdp snort delete-instance name <name>",
  .function = sfdp_snort_delete_instance_command_fn,
};

static clib_error_t *
sfdp_snort_init (vlib_main_t *vm)
{
  sfdp_snort_main_t *vsm = &sfdp_snort_main;

  clib_memset (vsm, 0, sizeof (*vsm));

  vsm->snort_dequeue_node_index = ~0;
  vsm->snort_dequeue_node_next_index = ~0;
  vsm->instance_index = ~0;
  vsm->snort_enq_next_index = ~0;

  return 0;
}

VLIB_INIT_FUNCTION (sfdp_snort_init);
