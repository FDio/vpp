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
#include <dpdk/device/sff8472.h>
#include <vnet/ethernet/sfp.h>

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
VLIB_CLI_COMMAND (cmd_show_dpdk_buffer,static) = {
    .path = "show dpdk buffer",
    .short_help = "show dpdk buffer",
    .function = show_dpdk_buffer,
    .is_mp_safe = 1,
};

static clib_error_t *
show_dpdk_physmem (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{
  clib_error_t *err = 0;
  int fds[2];
  u8 *s = 0;
  int n, n_try;
  FILE *f;

  /*
   * XXX: Pipes on FreeBSD grow dynamically up to 64KB (FreeBSD 15), don't
   * manually tweak this value on FreeBSD at the moment.
   */
#ifdef __linux__
  u32 pipe_max_size;

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
#endif /* __linux__ */

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
VLIB_CLI_COMMAND (cmd_show_dpdk_physmem,static) = {
    .path = "show dpdk physmem",
    .short_help = "show dpdk physmem",
    .function = show_dpdk_physmem,
    .is_mp_safe = 1,
};

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
VLIB_CLI_COMMAND (cmd_test_dpdk_buffer,static) = {
    .path = "test dpdk buffer",
    .short_help = "test dpdk buffer [allocate <nn>] [free <nn>]",
    .function = test_dpdk_buffer,
    .is_mp_safe = 1,
};

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
VLIB_CLI_COMMAND (cmd_set_dpdk_if_desc,static) = {
    .path = "set dpdk interface descriptors",
    .short_help = "set dpdk interface descriptors <interface> [rx <nn>] [tx <nn>]",
    .function = set_dpdk_if_desc,
};

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
VLIB_CLI_COMMAND (show_vpe_version_command, static) = {
  .path = "show dpdk version",
  .short_help = "show dpdk version",
  .function = show_dpdk_version_command_fn,
};

/* Dummy function to get us linked in. */
void
dpdk_cli_reference (void)
{
}

static clib_error_t *
read_dpdk_transceiver_eeprom (vlib_main_t *vm, u32 hw_if_index,
			      u8 **eeprom_data, u32 *eeprom_len,
			      sfp_eeprom_t **se)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  dpdk_device_t *xd;
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dc;
  struct rte_eth_dev_module_info mi = { 0 };
  struct rte_dev_eeprom_info ei = { 0 };

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  dc = vec_elt_at_index (im->device_classes, hi->dev_class_index);
  *se = NULL;

  if (dc->index != dpdk_device_class.index)
    {
      return clib_error_return (0, "Interface %v is not a DPDK interface",
				hi->name);
    }

  if (hi->dev_instance >= vec_len (dm->devices))
    {
      return clib_error_return (0, "Invalid device instance %u",
				hi->dev_instance);
    }

  xd = vec_elt_at_index (dm->devices, hi->dev_instance);

  /* Get module info */
  if (rte_eth_dev_get_module_info (xd->port_id, &mi) != 0)
    {
      return clib_error_return (
	0, "Module info not available for interface %v", hi->name);
    }

  if (mi.eeprom_len < 128 || mi.eeprom_len > 8192)
    {
      return clib_error_return (0, "EEPROM invalid length: %u bytes",
				mi.eeprom_len);
    }

  /* Get EEPROM data */
  *eeprom_data = clib_mem_alloc (mi.eeprom_len);
  ei.length = mi.eeprom_len;
  ei.data = *eeprom_data;

  if (rte_eth_dev_get_module_eeprom (xd->port_id, &ei) != 0)
    {
      clib_mem_free (*eeprom_data);
      *eeprom_data = 0;
      return clib_error_return (0, "EEPROM read error for interface %v",
				hi->name);
    }

  *se = ei.data + (mi.type == RTE_ETH_MODULE_SFF_8436 ? 0x80 : 0);
  *eeprom_len = mi.eeprom_len;
  return 0;
}

static void
show_dpdk_transceiver (vlib_main_t *vm, vnet_hw_interface_t *hi,
		       u8 show_module, u8 show_diag, u8 show_eeprom,
		       u8 is_terse)
{
  clib_error_t *error = 0;
  u8 *eeprom_data = 0;
  u32 eeprom_len = 0;
  sfp_eeprom_t *se = NULL;

  error = read_dpdk_transceiver_eeprom (vm, hi->hw_if_index, &eeprom_data,
					&eeprom_len, &se);
  if (error)
    goto done;

  vlib_cli_output (vm, "Interface: %v", hi->name);

  /* Default to module if none are set */
  if (!show_module && !show_diag && !show_eeprom)
    show_module = 1;

  if (show_eeprom)
    {

      vlib_cli_output (vm, "  EEPROM length: %u bytes", eeprom_len);
      vlib_cli_output (vm, "  EEPROM hexdump:");

      /* Print hexdump */
      for (u32 offset = 0; offset < eeprom_len; offset += 16)
	{
	  u8 *line = format (0, "    %04x: ", offset);

	  /* Print hex bytes */
	  for (u32 j = 0; j < 16 && (offset + j) < eeprom_len; j++)
	    {
	      line = format (line, "%02x ", eeprom_data[offset + j]);
	    }

	  /* Pad to align ASCII section */
	  for (u32 j = (offset + 16 > eeprom_len) ? eeprom_len - offset : 16;
	       j < 16; j++)
	    {
	      line = format (line, "   ");
	    }

	  line = format (line, " |");

	  /* Print ASCII representation */
	  for (u32 j = 0; j < 16 && (offset + j) < eeprom_len; j++)
	    {
	      u8 c = eeprom_data[offset + j];
	      line = format (line, "%c", (c >= 32 && c <= 126) ? c : '.');
	    }

	  line = format (line, "|");
	  vlib_cli_output (vm, "%v", line);
	  vec_free (line);
	}

      vlib_cli_output (vm, "");
    }

  if (show_module)
    {
      sff8472_decode_sfp_eeprom (vm, se, is_terse);
    }

  if (show_diag)
    {
      /* Decode SFF 8472 EEPROM A2 data */
      sff8472_decode_diagnostics (vm, eeprom_data, eeprom_len, is_terse);
    }

done:
  if (eeprom_data)
    clib_mem_free (eeprom_data);
}

static clib_error_t *
show_dpdk_transceiver_cmd (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dc;
  u32 hw_if_index = ~0;
  u8 is_terse = 1;
  u8 show_diag = 0;
  u8 show_module = 0;
  u8 show_eeprom = 0;
  u32 shown = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "diag"))
	show_diag = 1;
      else if (unformat (input, "module"))
	show_module = 1;
      else if (unformat (input, "eeprom"))
	show_eeprom = 1;
      else if (unformat (input, "verbose"))
	is_terse = 0;
      else if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
			 &hw_if_index))
	;
      else
	{
	  return clib_error_return (0, "parse error: '%U'",
				    format_unformat_error, input);
	}
    }

  pool_foreach (hi, im->hw_interfaces)
    {
      dc = vec_elt_at_index (im->device_classes, hi->dev_class_index);
      if (dc->index == dpdk_device_class.index)
	{
	  if (hw_if_index == ~0 || hw_if_index == hi->hw_if_index)
	    {
	      show_dpdk_transceiver (vm, hi, show_module, show_diag,
				     show_eeprom, is_terse);
	      shown++;
	    }
	}
    }
  if (shown == 0)
    return clib_error_return (0, "No DPDK interfaces found");
  return 0;
}

VLIB_CLI_COMMAND (show_dpdk_transceiver_command, static) = {
  .path = "show dpdk transceiver",
  .short_help = "show dpdk transceiver [<interface>] [eeprom] [module] [diag]",
  .function = show_dpdk_transceiver_cmd,
};

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
