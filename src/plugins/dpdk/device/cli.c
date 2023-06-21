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

#include <unistd.h>
#include <fcntl.h>

#include <vlib/pci/pci.h>
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/linux/sysfs.c>

#include <vnet/ethernet/ethernet.h>
#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/mpls/packet.h>

#include <dpdk/device/dpdk_priv.h>

/**
 * @file
 * @brief CLI for DPDK Abstraction Layer and pcap Tx Trace.
 *
 * This file contains the source code for CLI for DPDK
 * Abstraction Layer and pcap Tx Trace.
 */


static clib_error_t *
show_dpdk_buffer (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;

  vec_foreach (bp, bm->buffer_pools)
  {
    struct rte_mempool *rmp = dpdk_mempool_by_buffer_pool_index[bp->index];
    if (rmp)
      {
	unsigned count = rte_mempool_avail_count (rmp);
	unsigned free_count = rte_mempool_in_use_count (rmp);

	vlib_cli_output (vm,
			 "name=\"%s\"  available = %7d allocated = %7d total = %7d\n",
			 rmp->name, (u32) count, (u32) free_count,
			 (u32) (count + free_count));
      }
    else
      {
	vlib_cli_output (vm, "rte_mempool is NULL (!)\n");
      }
  }
  return 0;
}

/*?
 * This command displays statistics of each DPDK mempool.
 *
 * @cliexpar
 * Example of how to display DPDK buffer data:
 * @cliexstart{show dpdk buffer}
 * name="mbuf_pool_socket0"  available =   15104 allocated =    1280 total =   16384
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_buffer,static) = {
    .path = "show dpdk buffer",
    .short_help = "show dpdk buffer",
    .function = show_dpdk_buffer,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
show_dpdk_physmem (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{
  clib_error_t *err = 0;
  u32 pipe_max_size;
  int fds[2];
  u8 *s = 0;
  int n, n_try;
  FILE *f;

  err = clib_sysfs_read ("/proc/sys/fs/pipe-max-size", "%u", &pipe_max_size);

  if (err)
    return err;

  if (pipe (fds) == -1)
    return clib_error_return_unix (0, "pipe");

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ	(1024 + 7)
#endif

  if (fcntl (fds[1], F_SETPIPE_SZ, pipe_max_size) == -1)
    {
      err = clib_error_return_unix (0, "fcntl(F_SETPIPE_SZ)");
      goto error;
    }

  if (fcntl (fds[0], F_SETFL, O_NONBLOCK) == -1)
    {
      err = clib_error_return_unix (0, "fcntl(F_SETFL)");
      goto error;
    }

  if ((f = fdopen (fds[1], "a")) == 0)
    {
      err = clib_error_return_unix (0, "fdopen");
      goto error;
    }

  rte_dump_physmem_layout (f);
  fflush (f);

  n = n_try = 4096;
  while (n == n_try)
    {
      uword len = vec_len (s);
      vec_resize (s, len + n_try);

      n = read (fds[0], s + len, n_try);
      if (n < 0 && errno != EAGAIN)
	{
	  err = clib_error_return_unix (0, "read");
	  goto error;
	}
      vec_set_len (s, len + (n < 0 ? 0 : n));
    }

  vlib_cli_output (vm, "%v", s);

error:
  close (fds[0]);
  close (fds[1]);
  vec_free (s);
  return err;
}

/*?
 * This command displays DPDK physmem layout
 *
 * @cliexpar
 * Example of how to display DPDK physmem layout:
 * @cliexstart{show dpdk physmem}
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_physmem,static) = {
    .path = "show dpdk physmem",
    .short_help = "show dpdk physmem",
    .function = show_dpdk_physmem,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
test_dpdk_buffer (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  static u32 *allocated_buffers;
  u32 n_alloc = 0;
  u32 n_free = 0;
  u32 first, actual_alloc;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "allocate %d", &n_alloc))
	;
      else if (unformat (input, "free %d", &n_free))
	;
      else
	break;
    }

  if (n_free)
    {
      if (vec_len (allocated_buffers) < n_free)
	return clib_error_return (0, "Can't free %d, only %d allocated",
				  n_free, vec_len (allocated_buffers));

      first = vec_len (allocated_buffers) - n_free;
      vlib_buffer_free (vm, allocated_buffers + first, n_free);
      vec_set_len (allocated_buffers, first);
    }
  if (n_alloc)
    {
      first = vec_len (allocated_buffers);
      vec_validate (allocated_buffers,
		    vec_len (allocated_buffers) + n_alloc - 1);

      actual_alloc = vlib_buffer_alloc (vm, allocated_buffers + first,
					n_alloc);
      vec_set_len (allocated_buffers, first + actual_alloc);

      if (actual_alloc < n_alloc)
	vlib_cli_output (vm, "WARNING: only allocated %d buffers",
			 actual_alloc);
    }

  vlib_cli_output (vm, "Currently %d buffers allocated",
		   vec_len (allocated_buffers));

  if (allocated_buffers && vec_len (allocated_buffers) == 0)
    vec_free (allocated_buffers);

  return 0;
}

/*?
 * This command tests the allocation and freeing of DPDK buffers.
 * If both '<em>allocate</em>' and '<em>free</em>' are entered on the
 * same command, the '<em>free</em>' is executed first. If no
 * parameters are provided, this command display how many DPDK buffers
 * the test command has allocated.
 *
 * @cliexpar
 * @parblock
 *
 * Example of how to display how many DPDK buffer test command has allocated:
 * @cliexstart{test dpdk buffer}
 * Currently 0 buffers allocated
 * @cliexend
 *
 * Example of how to allocate DPDK buffers using the test command:
 * @cliexstart{test dpdk buffer allocate 10}
 * Currently 10 buffers allocated
 * @cliexend
 *
 * Example of how to free DPDK buffers allocated by the test command:
 * @cliexstart{test dpdk buffer free 10}
 * Currently 0 buffers allocated
 * @cliexend
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_test_dpdk_buffer,static) = {
    .path = "test dpdk buffer",
    .short_help = "test dpdk buffer [allocate <nn>] [free <nn>]",
    .function = test_dpdk_buffer,
    .is_mp_safe = 1,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_desc (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;
  u32 nb_rx_desc = (u32) ~ 0;
  u32 nb_tx_desc = (u32) ~ 0;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	;
      else if (unformat (line_input, "tx %d", &nb_tx_desc))
	;
      else if (unformat (line_input, "rx %d", &nb_rx_desc))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (hw_if_index == (u32) ~ 0)
    {
      error = clib_error_return (0, "please specify valid interface name");
      goto done;
    }

  hw = vnet_get_hw_interface (vnm, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  if ((nb_rx_desc == (u32) ~0 || nb_rx_desc == xd->conf.n_rx_desc) &&
      (nb_tx_desc == (u32) ~0 || nb_tx_desc == xd->conf.n_tx_desc))
    {
      error = clib_error_return (0, "nothing changed");
      goto done;
    }

  if (nb_rx_desc != (u32) ~ 0)
    xd->conf.n_rx_desc = nb_rx_desc;

  if (nb_tx_desc != (u32) ~ 0)
    xd->conf.n_tx_desc = nb_tx_desc;

  dpdk_device_setup (xd);

  if (vec_len (xd->errors))
    return clib_error_return (0, "%U", format_dpdk_device_errors, xd);

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command sets the number of DPDK '<em>rx</em>' and
 * '<em>tx</em>' descriptors for the given physical interface. Use
 * the command '<em>show hardware-interface</em>' to display the
 * current descriptor allocation.
 *
 * @cliexpar
 * Example of how to set the DPDK interface descriptors:
 * @cliexcmd{set dpdk interface descriptors GigabitEthernet0/8/0 rx 512 tx 512}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_desc,static) = {
    .path = "set dpdk interface descriptors",
    .short_help = "set dpdk interface descriptors <interface> [rx <nn>] [tx <nn>]",
    .function = set_dpdk_if_desc,
};
/* *INDENT-ON* */

static clib_error_t *
show_dpdk_version_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
#define _(a,b,c) vlib_cli_output (vm, "%-25s " b, a ":", c);
  _("DPDK Version", "%s", rte_version ());
  _("DPDK EAL init args", "%s", dpdk_config_main.eal_init_args_str);
#undef _
  return 0;
}

/*?
 * This command is used to display the current DPDK version and
 * the list of arguments passed to DPDK when started.
 *
 * @cliexpar
 * Example of how to display how many DPDK buffer test command has allocated:
 * @cliexstart{show dpdk version}
 * DPDK Version:        DPDK 16.11.0
 * DPDK EAL init args:  --in-memory --no-telemetry --file-prefix vpp
 *  -w 0000:00:08.0 -w 0000:00:09.0
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vpe_version_command, static) = {
  .path = "show dpdk version",
  .short_help = "show dpdk version",
  .function = show_dpdk_version_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
dpdk_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_create_if_args_t args = {};

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return NULL;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U %U", unformat_vlib_pci_addr,
		    &args.config.pci_addr, unformat_dpdk_device_config,
		    &args.config))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  dpdk_create_if (vm, &args);

  if (args.error == 0)
    vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
		     vnet_get_main (), args.sw_if_index);

  return args.error;
}

VLIB_CLI_COMMAND (dpdk_create_command, static) = {
  .path = "create interface dpdk",
  .short_help = "create interface dpdk <pci-address> "
		"[num-rx-queues <n>] [num-tx-queues <n>] "
		"[num-rx-desc <n>] [num-tx-desc <n>]",
  .function = dpdk_create_command_fn,
};

static clib_error_t *
dpdk_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  int rv = 0;
  vnet_main_t *vnm = vnet_get_main ();

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "sw_if_index %d", &sw_if_index))
	;
      else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (sw_if_index == ~0)
    return clib_error_return (0,
			      "please specify interface name or sw_if_index");

  rv = dpdk_delete_if (vm, sw_if_index);
  if (rv)
    return clib_error_return (0, "dpdk_delete_if failed");

  return NULL;
}

VLIB_CLI_COMMAND (dpdk_delete_command, static) = {
  .path = "delete interface dpdk",
  .short_help = "delete interface dpdk "
		"{<interface> | sw_if_index <sw_idx>}",
  .function = dpdk_delete_command_fn,
};

/* Dummy function to get us linked in. */
void
dpdk_cli_reference (void)
{
}

clib_error_t *
dpdk_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (dpdk_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
