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
get_hqos (u32 hw_if_index, u32 subport_id, dpdk_device_t ** xd,
	  dpdk_device_config_t ** devconf)
{
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hw;
  struct rte_eth_dev_info dev_info;
  struct rte_pci_device *pci_dev;
  uword *p = 0;
  clib_error_t *error = NULL;


  if (hw_if_index == (u32) ~ 0)
    {
      error = clib_error_return (0, "please specify valid interface name");
      goto done;
    }

  if (subport_id != 0)
    {
      error = clib_error_return (0, "Invalid subport");
      goto done;
    }

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  *xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rte_eth_dev_info_get ((*xd)->port_id, &dev_info);

  pci_dev = dpdk_get_pci_device (&dev_info);

  if (pci_dev)
    {
      vlib_pci_addr_t pci_addr;

      pci_addr.domain = pci_dev->addr.domain;
      pci_addr.bus = pci_dev->addr.bus;
      pci_addr.slot = pci_dev->addr.devid;
      pci_addr.function = pci_dev->addr.function;

      p =
	hash_get (dm->conf->device_config_index_by_pci_addr, pci_addr.as_u32);
    }

  if (p)
    (*devconf) = pool_elt_at_index (dm->conf->dev_confs, p[0]);
  else
    (*devconf) = &dm->conf->default_devconf;

done:
  return error;
}

static inline clib_error_t *
pcap_trace_command_internal (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd, int rx_tx)
{
#define PCAP_DEF_PKT_TO_CAPTURE (100)

  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  u8 *filename;
  u8 *chroot_filename = 0;
  u32 max = 0;
  int enabled = 0;
  int errorFlag = 0;
  clib_error_t *error = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on"))
	{
	  if (dm->pcap[rx_tx].pcap_enable == 0)
	    {
	      enabled = 1;
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap tx capture already on...");
	      errorFlag = 1;
	      break;
	    }
	}
      else if (unformat (line_input, "off"))
	{
	  if (dm->pcap[rx_tx].pcap_enable)
	    {
	      vlib_cli_output
		(vm, "captured %d pkts...",
		 dm->pcap[rx_tx].pcap_main.n_packets_captured);
	      if (dm->pcap[rx_tx].pcap_main.n_packets_captured)
		{
		  dm->pcap[rx_tx].pcap_main.n_packets_to_capture =
		    dm->pcap[rx_tx].pcap_main.n_packets_captured;
		  error = pcap_write (&dm->pcap[rx_tx].pcap_main);
		  if (error)
		    clib_error_report (error);
		  else
		    vlib_cli_output (vm, "saved to %s...",
				     dm->pcap[rx_tx].pcap_main.file_name);
		}

	      dm->pcap[rx_tx].pcap_enable = 0;
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap tx capture already off...");
	      errorFlag = 1;
	      break;
	    }
	}
      else if (unformat (line_input, "max %d", &max))
	{
	  if (dm->pcap[rx_tx].pcap_enable)
	    {
	      vlib_cli_output
		(vm,
		 "can't change max value while pcap tx capture active...");
	      errorFlag = 1;
	      break;
	    }
	  dm->pcap[rx_tx].pcap_main.n_packets_to_capture = max;
	}
      else if (unformat (line_input, "intfc %U",
			 unformat_vnet_sw_interface, dm->vnet_main,
			 &dm->pcap[rx_tx].pcap_sw_if_index))
	;

      else if (unformat (line_input, "intfc any"))
	{
	  dm->pcap[rx_tx].pcap_sw_if_index = 0;
	}
      else if (unformat (line_input, "file %s", &filename))
	{
	  if (dm->pcap[rx_tx].pcap_enable)
	    {
	      vlib_cli_output
		(vm, "can't change file while pcap tx capture active...");
	      errorFlag = 1;
	      break;
	    }

	  /* Brain-police user path input */
	  if (strstr ((char *) filename, "..")
	      || index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      vlib_cli_output (vm, "Hint: .. and / are not allowed.");
	      vec_free (filename);
	      errorFlag = 1;
	      break;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);
	  vec_free (filename);
	}
      else if (unformat (line_input, "status"))
	{
	  if (dm->pcap[rx_tx].pcap_sw_if_index == 0)
	    {
	      vlib_cli_output
		(vm, "max is %d for any interface to file %s",
		 dm->pcap[rx_tx].pcap_main.n_packets_to_capture ?
		 dm->pcap[rx_tx].pcap_main.n_packets_to_capture
		 : PCAP_DEF_PKT_TO_CAPTURE,
		 dm->pcap[rx_tx].pcap_main.file_name ?
		 (u8 *) dm->pcap[rx_tx].pcap_main.file_name :
		 (u8 *) "/tmp/vpe.pcap");
	    }
	  else
	    {
	      vlib_cli_output (vm, "max is %d for interface %U to file %s",
			       dm->pcap[rx_tx].pcap_main.n_packets_to_capture
			       ? dm->pcap[rx_tx].
			       pcap_main.n_packets_to_capture :
			       PCAP_DEF_PKT_TO_CAPTURE,
			       format_vnet_sw_if_index_name, dm->vnet_main,
			       dm->pcap_sw_if_index,
			       dm->pcap[rx_tx].
			       pcap_main.file_name ? (u8 *) dm->pcap[rx_tx].
			       pcap_main.file_name : (u8 *) "/tmp/vpe.pcap");
	    }

	  if (dm->pcap[rx_tx].pcap_enable == 0)
	    {
	      vlib_cli_output (vm, "pcap %s capture is off...",
			       (rx_tx == VLIB_RX) ? "rx" : "tx");
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap %s capture is on: %d of %d pkts...",
			       (rx_tx == VLIB_RX) ? "rx" : "tx",
			       dm->pcap[rx_tx].pcap_main.n_packets_captured,
			       dm->pcap[rx_tx].
			       pcap_main.n_packets_to_capture);
	    }
	  break;
	}

      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  errorFlag = 1;
	  break;
	}
    }
  unformat_free (line_input);


  if (errorFlag == 0)
    {
      /* Since no error, save configured values. */
      if (chroot_filename)
	{
	  if (dm->pcap[rx_tx].pcap_main.file_name)
	    vec_free (dm->pcap[rx_tx].pcap_main.file_name);
	  vec_add1 (chroot_filename, 0);
	  dm->pcap[rx_tx].pcap_main.file_name = (char *) chroot_filename;
	}

      if (max)
	dm->pcap[rx_tx].pcap_main.n_packets_to_capture = max;

      if (enabled)
	{
	  if (dm->pcap[rx_tx].pcap_main.file_name == 0)
	    dm->pcap[rx_tx].pcap_main.file_name
	      = (char *) format (0, "/tmp/vpe.pcap%c", 0);

	  dm->pcap[rx_tx].pcap_main.n_packets_captured = 0;
	  dm->pcap[rx_tx].pcap_main.packet_type = PCAP_PACKET_TYPE_ethernet;
	  if (dm->pcap[rx_tx].pcap_main.lock == 0)
	    clib_spinlock_init (&(dm->pcap[rx_tx].pcap_main.lock));
	  dm->pcap[rx_tx].pcap_enable = 1;
	  vlib_cli_output (vm, "pcap %s capture on...",
			   rx_tx == VLIB_RX ? "rx" : "tx");
	}
    }
  else if (chroot_filename)
    vec_free (chroot_filename);

  return error;
}

static clib_error_t *
pcap_rx_trace_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return pcap_trace_command_internal (vm, input, cmd, VLIB_RX);
}

static clib_error_t *
pcap_tx_trace_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return pcap_trace_command_internal (vm, input, cmd, VLIB_TX);
}


/*?
 * This command is used to start or stop a packet capture, or show
 * the status of packet capture. Note that both "pcap rx trace" and
 * "pcap tx trace" are implemented. The command syntax is identical,
 * simply substitute rx for tx as needed.
 *
 * This command has the following optional parameters:
 *
 * - <b>on|off</b> - Used to start or stop a packet capture.
 *
 * - <b>max <nn></b> - Depth of local buffer. Once '<em>nn</em>' number
 *   of packets have been received, buffer is flushed to file. Once another
 *   '<em>nn</em>' number of packets have been received, buffer is flushed
 *   to file, overwriting previous write. If not entered, value defaults
 *   to 100. Can only be updated if packet capture is off.
 *
 * - <b>intfc <interface>|any</b> - Used to specify a given interface,
 *   or use '<em>any</em>' to run packet capture on all interfaces.
 *   '<em>any</em>' is the default if not provided. Settings from a previous
 *   packet capture are preserved, so '<em>any</em>' can be used to reset
 *   the interface setting.
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
 * Example of how to display the status of a tx packet capture when off:
 * @cliexstart{pcap tx trace status}
 * max is 100, for any interface to file /tmp/vpe.pcap
 * pcap tx capture is off...
 * @cliexend
 * Example of how to start a tx packet capture:
 * @cliexstart{pcap tx trace on max 35 intfc GigabitEthernet0/8/0 file vppTest.pcap}
 * pcap tx capture on...
 * @cliexend
 * Example of how to display the status of a tx packet capture in progress:
 * @cliexstart{pcap tx trace status}
 * max is 35, for interface GigabitEthernet0/8/0 to file /tmp/vppTest.pcap
 * pcap tx capture is on: 20 of 35 pkts...
 * @cliexend
 * Example of how to stop a tx packet capture:
 * @cliexstart{vppctl pcap tx trace off}
 * captured 21 pkts...
 * saved to /tmp/vppTest.pcap...
 * @cliexend
?*/
/* *INDENT-OFF* */

VLIB_CLI_COMMAND (pcap_tx_trace_command, static) = {
    .path = "pcap tx trace",
    .short_help =
    "pcap tx trace [on|off] [max <nn>] [intfc <interface>|any] [file <name>] [status]",
    .function = pcap_tx_trace_command_fn,
};
VLIB_CLI_COMMAND (pcap_rx_trace_command, static) = {
    .path = "pcap rx trace",
    .short_help =
    "pcap rx trace [on|off] [max <nn>] [intfc <interface>|any] [file <name>] [status]",
    .function = pcap_rx_trace_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
show_dpdk_buffer (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  vlib_buffer_main_t *bm = vm->buffer_main;
  vlib_buffer_pool_t *bp;

  vec_foreach (bp, bm->buffer_pools)
  {
    struct rte_mempool *rmp = bp->external;
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
      _vec_len (s) = len + (n < 0 ? 0 : n);
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
      _vec_len (allocated_buffers) = first;
    }
  if (n_alloc)
    {
      first = vec_len (allocated_buffers);
      vec_validate (allocated_buffers,
		    vec_len (allocated_buffers) + n_alloc - 1);

      actual_alloc = vlib_buffer_alloc (vm, allocated_buffers + first,
					n_alloc);
      _vec_len (allocated_buffers) = first + actual_alloc;

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
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
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

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  if ((xd->flags & DPDK_DEVICE_FLAG_PMD) == 0)
    {
      error =
	clib_error_return (0,
			   "number of descriptors can be set only for "
			   "physical devices");
      goto done;
    }

  if ((nb_rx_desc == (u32) ~ 0 || nb_rx_desc == xd->nb_rx_desc) &&
      (nb_tx_desc == (u32) ~ 0 || nb_tx_desc == xd->nb_tx_desc))
    {
      error = clib_error_return (0, "nothing changed");
      goto done;
    }

  if (nb_rx_desc != (u32) ~ 0)
    xd->nb_rx_desc = nb_rx_desc;

  if (nb_tx_desc != (u32) ~ 0)
    xd->nb_tx_desc = nb_tx_desc;

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

static int
dpdk_device_queue_sort (void *a1, void *a2)
{
  dpdk_device_and_queue_t *dq1 = a1;
  dpdk_device_and_queue_t *dq2 = a2;

  if (dq1->device > dq2->device)
    return 1;
  else if (dq1->device < dq2->device)
    return -1;
  else if (dq1->queue_id > dq2->queue_id)
    return 1;
  else if (dq1->queue_id < dq2->queue_id)
    return -1;
  else
    return 0;
}


static clib_error_t *
show_dpdk_if_hqos_placement (vlib_main_t * vm, unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_and_queue_t *dq;
  int cpu;

  if (tm->n_vlib_mains == 1)
    vlib_cli_output (vm, "All interfaces are handled by main thread");

  for (cpu = 0; cpu < vec_len (dm->devices_by_hqos_cpu); cpu++)
    {
      if (cpu >= dm->hqos_cpu_first_index &&
	  cpu < (dm->hqos_cpu_first_index + dm->hqos_cpu_count))
	vlib_cli_output (vm, "Thread %u (%s at lcore %u):", cpu,
			 vlib_worker_threads[cpu].name,
			 vlib_worker_threads[cpu].cpu_id);

      vec_foreach (dq, dm->devices_by_hqos_cpu[cpu])
      {
	u32 hw_if_index = dm->devices[dq->device].hw_if_index;
	vnet_hw_interface_t *hi =
	  vnet_get_hw_interface (dm->vnet_main, hw_if_index);
	vlib_cli_output (vm, "  %v queue %u", hi->name, dq->queue_id);
      }
    }
  return 0;
}

/*?
 * This command is used to display the thread and core each
 * DPDK output interface and HQoS queue is assigned too.
 *
 * @cliexpar
 * Example of how to display the DPDK output interface and HQoS queue placement:
 * @cliexstart{show dpdk interface hqos placement}
 * Thread 1 (vpp_hqos-threads_0 at lcore 3):
 *   GigabitEthernet0/8/0 queue 0
 * Thread 2 (vpp_hqos-threads_1 at lcore 4):
 *   GigabitEthernet0/9/0 queue 0
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_if_hqos_placement, static) = {
  .path = "show dpdk interface hqos placement",
  .short_help = "show dpdk interface hqos placement",
  .function = show_dpdk_if_hqos_placement,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_hqos_placement (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_and_queue_t *dq;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;
  u32 cpu = (u32) ~ 0;
  int i;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "thread %d", &cpu))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  if (cpu < dm->hqos_cpu_first_index ||
      cpu >= (dm->hqos_cpu_first_index + dm->hqos_cpu_count))
    {
      error = clib_error_return (0, "please specify valid thread id");
      goto done;
    }

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  for (i = 0; i < vec_len (dm->devices_by_hqos_cpu); i++)
    {
      vec_foreach (dq, dm->devices_by_hqos_cpu[i])
      {
	if (hw_if_index == dm->devices[dq->device].hw_if_index)
	  {
	    if (cpu == i)	/* nothing to do */
	      goto done;

	    vec_del1 (dm->devices_by_hqos_cpu[i],
		      dq - dm->devices_by_hqos_cpu[i]);
	    vec_add2 (dm->devices_by_hqos_cpu[cpu], dq, 1);
	    dq->queue_id = 0;
	    dq->device = xd->device_index;

	    vec_sort_with_function (dm->devices_by_hqos_cpu[i],
				    dpdk_device_queue_sort);

	    vec_sort_with_function (dm->devices_by_hqos_cpu[cpu],
				    dpdk_device_queue_sort);

	    goto done;
	  }
      }
    }

  error = clib_error_return (0, "not found");

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to assign a given DPDK output interface and
 * HQoS queue to a different thread. This will not create a thread,
 * so the thread must already exist. Use '<em>/etc/vpp/startup.conf</em>'
 * for the initial thread creation. See @ref qos_doc for more details.
 *
 * @cliexpar
 * Example of how to display the DPDK output interface and HQoS queue placement:
 * @cliexstart{show dpdk interface hqos placement}
 * Thread 1 (vpp_hqos-threads_0 at lcore 3):
 *   GigabitEthernet0/8/0 queue 0
 * Thread 2 (vpp_hqos-threads_1 at lcore 4):
 *   GigabitEthernet0/9/0 queue 0
 * @cliexend
 * Example of how to assign a DPDK output interface and HQoS queue to a thread:
 * @cliexcmd{set dpdk interface hqos placement GigabitEthernet0/8/0 thread 2}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_placement, static) = {
  .path = "set dpdk interface hqos placement",
  .short_help = "set dpdk interface hqos placement <interface> thread <n>",
  .function = set_dpdk_if_hqos_placement,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_hqos_pipe (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;
  u32 subport_id = (u32) ~ 0;
  u32 pipe_id = (u32) ~ 0;
  u32 profile_id = (u32) ~ 0;
  int rv;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "subport %d", &subport_id))
	;
      else if (unformat (line_input, "pipe %d", &pipe_id))
	;
      else if (unformat (line_input, "profile %d", &profile_id))
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

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rv =
    rte_sched_pipe_config (xd->hqos_ht->hqos, subport_id, pipe_id,
			   profile_id);
  if (rv)
    {
      error = clib_error_return (0, "pipe configuration failed");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to change the profile associate with a HQoS pipe. The
 * '<em><profile_id></em>' is zero based. Use the command
 * '<em>show dpdk interface hqos</em>' to display the content of each profile.
 * See @ref qos_doc for more details.
 *
 * @note
 * Currently there is not an API to create a new HQoS pipe profile. One is
 * created by default in the code (search for '<em>hqos_pipe_params_default</em>'').
 * Additional profiles can be created in code and code recompiled. Then use this
 * command to assign it.
 *
 * @cliexpar
 * Example of how to assign a new profile to a HQoS pipe:
 * @cliexcmd{set dpdk interface hqos pipe GigabitEthernet0/8/0 subport 0 pipe 2 profile 1}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_pipe, static) =
{
  .path = "set dpdk interface hqos pipe",
  .short_help = "set dpdk interface hqos pipe <interface> subport <subport_id> pipe <pipe_id> "
                  "profile <profile_id>",
  .function = set_dpdk_if_hqos_pipe,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_hqos_subport (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd = NULL;
  u32 hw_if_index = (u32) ~ 0;
  u32 subport_id = (u32) ~ 0;
  struct rte_sched_subport_params p;
  int rv;
  clib_error_t *error = NULL;
  u32 tb_rate = (u32) ~ 0;
  u32 tb_size = (u32) ~ 0;
  u32 tc_rate[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE] =
    { (u32) ~ 0, (u32) ~ 0, (u32) ~ 0, (u32) ~ 0 };
  u32 tc_period = (u32) ~ 0;
  dpdk_device_config_t *devconf = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "subport %d", &subport_id))
	;
      else if (unformat (line_input, "rate %d", &tb_rate))
	;
      else if (unformat (line_input, "bktsize %d", &tb_size))
	;
      else if (unformat (line_input, "tc0 %d", &tc_rate[0]))
	;
      else if (unformat (line_input, "tc1 %d", &tc_rate[1]))
	;
      else if (unformat (line_input, "tc2 %d", &tc_rate[2]))
	;
      else if (unformat (line_input, "tc3 %d", &tc_rate[3]))
	;
      else if (unformat (line_input, "period %d", &tc_period))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  error = get_hqos (hw_if_index, subport_id, &xd, &devconf);

  if (error == NULL)
    {
      /* Copy the current values over to local structure. */
      memcpy (&p, &devconf->hqos.subport[subport_id], sizeof (p));

      /* Update local structure with input values. */
      if (tb_rate != (u32) ~ 0)
	{
	  p.tb_rate = tb_rate;
	  p.tc_rate[0] = tb_rate;
	  p.tc_rate[1] = tb_rate;
	  p.tc_rate[2] = tb_rate;
	  p.tc_rate[3] = tb_rate;
	}
      if (tb_size != (u32) ~ 0)
	{
	  p.tb_size = tb_size;
	}
      if (tc_rate[0] != (u32) ~ 0)
	{
	  p.tc_rate[0] = tc_rate[0];
	}
      if (tc_rate[1] != (u32) ~ 0)
	{
	  p.tc_rate[1] = tc_rate[1];
	}
      if (tc_rate[2] != (u32) ~ 0)
	{
	  p.tc_rate[2] = tc_rate[2];
	}
      if (tc_rate[3] != (u32) ~ 0)
	{
	  p.tc_rate[3] = tc_rate[3];
	}
      if (tc_period != (u32) ~ 0)
	{
	  p.tc_period = tc_period;
	}

      /* Apply changes. */
      rv = rte_sched_subport_config (xd->hqos_ht->hqos, subport_id, &p);
      if (rv)
	{
	  error = clib_error_return (0, "subport configuration failed");
	  goto done;
	}
      else
	{
	  /* Successfully applied, so save of the input values. */
	  memcpy (&devconf->hqos.subport[subport_id], &p, sizeof (p));
	}
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to set the subport level parameters such as token
 * bucket rate (bytes per seconds), token bucket size (bytes), traffic class
 * rates (bytes per seconds) and token update period (Milliseconds).
 *
 * By default, the '<em>rate</em>' is set to 1250000000 bytes/second (10GbE
 * rate) and each of the four traffic classes is set to 100% of the port rate.
 * If the '<em>rate</em>' is updated by this command, all four traffic classes
 * are assigned the same value. Each of the four traffic classes can be updated
 * individually.
 *
 * @cliexpar
 * Example of how modify the subport attributes for a 1GbE link:
 * @cliexcmd{set dpdk interface hqos subport GigabitEthernet0/8/0 subport 0 rate 125000000}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_subport, static) = {
  .path = "set dpdk interface hqos subport",
  .short_help = "set dpdk interface hqos subport <interface> subport <subport_id> "
                 "[rate <n>] [bktsize <n>] [tc0 <n>] [tc1 <n>] [tc2 <n>] [tc3 <n>] "
                 "[period <n>]",
  .function = set_dpdk_if_hqos_subport,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_hqos_tctbl (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;
  u32 tc = (u32) ~ 0;
  u32 queue = (u32) ~ 0;
  u32 entry = (u32) ~ 0;
  u32 val, i;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "entry %d", &entry))
	;
      else if (unformat (line_input, "tc %d", &tc))
	;
      else if (unformat (line_input, "queue %d", &queue))
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
  if (entry >= 64)
    {
      error = clib_error_return (0, "invalid entry");
      goto done;
    }
  if (tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
      error = clib_error_return (0, "invalid traffic class");
      goto done;
    }
  if (queue >= RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS)
    {
      error = clib_error_return (0, "invalid traffic class queue");
      goto done;
    }

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  /* Detect the set of worker threads */
  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  /* Should never happen, shut up Coverity warning */
  if (p == 0)
    {
      error = clib_error_return (0, "no worker registrations?");
      goto done;
    }

  vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];
  int worker_thread_first = tr->first_index;
  int worker_thread_count = tr->count;

  val = tc * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS + queue;
  for (i = 0; i < worker_thread_count; i++)
    xd->hqos_wt[worker_thread_first + i].hqos_tc_table[entry] = val;

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to set the traffic class translation table. The
 * traffic class translation table is used to map 64 values (0-63) to one of
 * four traffic class and one of four HQoS input queue. Use the '<em>show
 * dpdk interface hqos</em>' command to display the traffic class translation
 * table. See @ref qos_doc for more details.
 *
 * This command has the following parameters:
 *
 * - <b><interface></b> - Used to specify the output interface.
 *
 * - <b>entry <map_val></b> - Mapped value (0-63) to assign traffic class and queue to.
 *
 * - <b>tc <tc_id></b> - Traffic class (0-3) to be used by the provided mapped value.
 *
 * - <b>queue <queue_id></b> - HQoS input queue (0-3) to be used by the provided mapped value.
 *
 * @cliexpar
 * Example of how modify the traffic class translation table:
 * @cliexcmd{set dpdk interface hqos tctbl GigabitEthernet0/8/0 entry 16 tc 2 queue 2}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_tctbl, static) = {
  .path = "set dpdk interface hqos tctbl",
  .short_help = "set dpdk interface hqos tctbl <interface> entry <map_val> tc <tc_id> queue <queue_id>",
  .function = set_dpdk_if_hqos_tctbl,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_hqos_pktfield (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_main_t *dm = &dpdk_main;
  clib_error_t *error = NULL;

  /* Device specific data */
  struct rte_eth_dev_info dev_info;
  struct rte_pci_device *pci_dev;
  dpdk_device_config_t *devconf = 0;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;

  /* Detect the set of worker threads */
  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  /* Should never happen, shut up Coverity warning */
  if (p == 0)
    return clib_error_return (0, "no worker registrations?");

  vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];
  int worker_thread_first = tr->first_index;
  int worker_thread_count = tr->count;

  /* Packet field configuration */
  u64 mask = (u64) ~ 0;
  u32 id = (u32) ~ 0;
  u32 offset = (u32) ~ 0;

  /* HQoS params */
  u32 n_subports_per_port, n_pipes_per_subport, tctbl_size;

  u32 i;

  /* Parse input arguments */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else if (unformat (line_input, "id subport"))
	id = 0;
      else if (unformat (line_input, "id pipe"))
	id = 1;
      else if (unformat (line_input, "id tc"))
	id = 2;
      else if (unformat (line_input, "id %d", &id))
	;
      else if (unformat (line_input, "offset %d", &offset))
	;
      else if (unformat (line_input, "mask %llx", &mask))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  /* Get interface */
  if (hw_if_index == (u32) ~ 0)
    {
      error = clib_error_return (0, "please specify valid interface name");
      goto done;
    }

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rte_eth_dev_info_get (xd->port_id, &dev_info);

  pci_dev = dpdk_get_pci_device (&dev_info);

  if (pci_dev)
    {				/* bonded interface has no pci info */
      vlib_pci_addr_t pci_addr;

      pci_addr.domain = pci_dev->addr.domain;
      pci_addr.bus = pci_dev->addr.bus;
      pci_addr.slot = pci_dev->addr.devid;
      pci_addr.function = pci_dev->addr.function;

      p =
	hash_get (dm->conf->device_config_index_by_pci_addr, pci_addr.as_u32);
    }

  if (p)
    devconf = pool_elt_at_index (dm->conf->dev_confs, p[0]);
  else
    devconf = &dm->conf->default_devconf;

  if (devconf->hqos_enabled == 0)
    {
      vlib_cli_output (vm, "HQoS disabled for this interface");
      goto done;
    }

  n_subports_per_port = devconf->hqos.port.n_subports_per_port;
  n_pipes_per_subport = devconf->hqos.port.n_pipes_per_subport;
  tctbl_size = RTE_DIM (devconf->hqos.tc_table);

  /* Validate packet field configuration: id, offset and mask */
  if (id >= 3)
    {
      error = clib_error_return (0, "invalid packet field id");
      goto done;
    }

  switch (id)
    {
    case 0:
      if (dpdk_hqos_validate_mask (mask, n_subports_per_port) != 0)
	{
	  error = clib_error_return (0, "invalid subport ID mask "
				     "(n_subports_per_port = %u)",
				     n_subports_per_port);
	  goto done;
	}
      break;
    case 1:
      if (dpdk_hqos_validate_mask (mask, n_pipes_per_subport) != 0)
	{
	  error = clib_error_return (0, "invalid pipe ID mask "
				     "(n_pipes_per_subport = %u)",
				     n_pipes_per_subport);
	  goto done;
	}
      break;
    case 2:
    default:
      if (dpdk_hqos_validate_mask (mask, tctbl_size) != 0)
	{
	  error = clib_error_return (0, "invalid TC table index mask "
				     "(TC table size = %u)", tctbl_size);
	  goto done;
	}
    }

  /* Propagate packet field configuration to all workers */
  for (i = 0; i < worker_thread_count; i++)
    switch (id)
      {
      case 0:
	xd->hqos_wt[worker_thread_first + i].hqos_field0_slabpos = offset;
	xd->hqos_wt[worker_thread_first + i].hqos_field0_slabmask = mask;
	xd->hqos_wt[worker_thread_first + i].hqos_field0_slabshr =
	  count_trailing_zeros (mask);
	break;
      case 1:
	xd->hqos_wt[worker_thread_first + i].hqos_field1_slabpos = offset;
	xd->hqos_wt[worker_thread_first + i].hqos_field1_slabmask = mask;
	xd->hqos_wt[worker_thread_first + i].hqos_field1_slabshr =
	  count_trailing_zeros (mask);
	break;
      case 2:
      default:
	xd->hqos_wt[worker_thread_first + i].hqos_field2_slabpos = offset;
	xd->hqos_wt[worker_thread_first + i].hqos_field2_slabmask = mask;
	xd->hqos_wt[worker_thread_first + i].hqos_field2_slabshr =
	  count_trailing_zeros (mask);
      }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to set the packet fields required for classifying the
 * incoming packet. As a result of classification process, packet field
 * information will be mapped to 5 tuples (subport, pipe, traffic class, pipe,
 * color) and stored in packet mbuf.
 *
 * This command has the following parameters:
 *
 * - <b><interface></b> - Used to specify the output interface.
 *
 * - <b>id subport|pipe|tc</b> - Classification occurs across three fields.
 * This parameter indicates which of the three masks are being configured. Legacy
 * code used 0-2 to represent these three fields, so 0-2 is still accepted.
 *   - <b>subport|0</b> - Currently only one subport is supported, so only
 * an empty mask is supported for the subport classification.
 *   - <b>pipe|1</b> - Currently, 4096 pipes per subport are supported, so a
 * 12-bit mask should be configure to map to the 0-4095 pipes.
 *   - <b>tc|2</b> - The translation table (see '<em>set dpdk interface hqos
 * tctbl</em>' command) maps each value (0-63) into one of the 4 traffic classes
 * per pipe. A 6-bit mask should be configure to map this field to a traffic class.
 *
 * - <b>offset <n></b> - Offset in the packet to apply the 64-bit mask for classification.
 * The offset should be on an 8-byte boundary (0,8,16,24..).
 *
 * - <b>mask <hex-mask></b> - 64-bit mask to apply to packet at the given '<em>offset</em>'.
 * Bits must be contiguous and should not include '<em>0x</em>'.
 *
 * The default values for the '<em>pktfield</em>' assumes Ethernet/IPv4/UDP packets with
 * no VLAN. Adjust based on expected packet format and desired classification field.
 * - '<em>subport</em>' is always empty (offset 0 mask 0000000000000000)
 * - By default, '<em>pipe</em>' maps to the UDP payload bits 12 .. 23 (offset 40
 * mask 0000000fff000000)
 * - By default, '<em>tc</em>' maps to the DSCP field in IP header (offset 48 mask
 * 00000000000000fc)
 *
 * @cliexpar
 * Example of how modify the '<em>pipe</em>' classification filter to match VLAN:
 * @cliexcmd{set dpdk interface hqos pktfield GigabitEthernet0/8/0 id pipe offset 8 mask 0000000000000FFF}
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_pktfield, static) = {
  .path = "set dpdk interface hqos pktfield",
  .short_help = "set dpdk interface hqos pktfield <interface> id subport|pipe|tc offset <n> "
                 "mask <hex-mask>",
  .function = set_dpdk_if_hqos_pktfield,
};
/* *INDENT-ON* */

static clib_error_t *
show_dpdk_if_hqos (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  dpdk_device_config_hqos_t *cfg;
  dpdk_device_hqos_per_hqos_thread_t *ht;
  dpdk_device_hqos_per_worker_thread_t *wk;
  u32 *tctbl;
  u32 hw_if_index = (u32) ~ 0;
  u32 profile_id, subport_id, i;
  struct rte_eth_dev_info dev_info;
  struct rte_pci_device *pci_dev;
  dpdk_device_config_t *devconf = 0;
  vlib_thread_registration_t *tr;
  uword *p = 0;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
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
      error = clib_error_return (0, "please specify interface name!!");
      goto done;
    }

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rte_eth_dev_info_get (xd->port_id, &dev_info);

  pci_dev = dpdk_get_pci_device (&dev_info);

  if (pci_dev)
    {				/* bonded interface has no pci info */
      vlib_pci_addr_t pci_addr;

      pci_addr.domain = pci_dev->addr.domain;
      pci_addr.bus = pci_dev->addr.bus;
      pci_addr.slot = pci_dev->addr.devid;
      pci_addr.function = pci_dev->addr.function;

      p =
	hash_get (dm->conf->device_config_index_by_pci_addr, pci_addr.as_u32);
    }

  if (p)
    devconf = pool_elt_at_index (dm->conf->dev_confs, p[0]);
  else
    devconf = &dm->conf->default_devconf;

  if (devconf->hqos_enabled == 0)
    {
      vlib_cli_output (vm, "HQoS disabled for this interface");
      goto done;
    }

  /* Detect the set of worker threads */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");

  /* Should never happen, shut up Coverity warning */
  if (p == 0)
    {
      error = clib_error_return (0, "no worker registrations?");
      goto done;
    }

  tr = (vlib_thread_registration_t *) p[0];

  cfg = &devconf->hqos;
  ht = xd->hqos_ht;
  wk = &xd->hqos_wt[tr->first_index];
  tctbl = wk->hqos_tc_table;

  vlib_cli_output (vm, " Thread:");
  vlib_cli_output (vm, "   Input SWQ size = %u packets", cfg->swq_size);
  vlib_cli_output (vm, "   Enqueue burst size = %u packets",
		   ht->hqos_burst_enq);
  vlib_cli_output (vm, "   Dequeue burst size = %u packets",
		   ht->hqos_burst_deq);

  vlib_cli_output (vm,
		   "   Packet field 0: slab position = %4u, slab bitmask = 0x%016llx   (subport)",
		   wk->hqos_field0_slabpos, wk->hqos_field0_slabmask);
  vlib_cli_output (vm,
		   "   Packet field 1: slab position = %4u, slab bitmask = 0x%016llx   (pipe)",
		   wk->hqos_field1_slabpos, wk->hqos_field1_slabmask);
  vlib_cli_output (vm,
		   "   Packet field 2: slab position = %4u, slab bitmask = 0x%016llx   (tc)",
		   wk->hqos_field2_slabpos, wk->hqos_field2_slabmask);
  vlib_cli_output (vm,
		   "   Packet field 2  tc translation table: ([Mapped Value Range]: tc/queue tc/queue ...)");
  vlib_cli_output (vm,
		   "     [ 0 .. 15]: "
		   "%u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u",
		   tctbl[0] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[0] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[1] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[1] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[2] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[2] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[3] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[3] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[4] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[4] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[5] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[5] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[6] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[6] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[7] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[7] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[8] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[8] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[9] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[9] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[10] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[10] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[11] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[11] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[12] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[12] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[13] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[13] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[14] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[14] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[15] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[15] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);
  vlib_cli_output (vm,
		   "     [16 .. 31]: "
		   "%u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u",
		   tctbl[16] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[16] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[17] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[17] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[18] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[18] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[19] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[19] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[20] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[20] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[21] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[21] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[22] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[22] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[23] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[23] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[24] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[24] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[25] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[25] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[26] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[26] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[27] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[27] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[28] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[28] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[29] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[29] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[30] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[30] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[31] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[31] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);
  vlib_cli_output (vm,
		   "     [32 .. 47]: "
		   "%u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u",
		   tctbl[32] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[32] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[33] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[33] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[34] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[34] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[35] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[35] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[36] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[36] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[37] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[37] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[38] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[38] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[39] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[39] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[40] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[40] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[41] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[41] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[42] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[42] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[43] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[43] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[44] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[44] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[45] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[45] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[46] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[46] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[47] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[47] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);
  vlib_cli_output (vm,
		   "     [48 .. 63]: "
		   "%u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u %u/%u",
		   tctbl[48] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[48] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[49] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[49] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[50] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[50] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[51] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[51] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[52] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[52] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[53] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[53] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[54] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[54] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[55] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[55] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[56] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[56] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[57] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[57] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[58] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[58] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[59] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[59] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[60] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[60] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[61] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[61] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[62] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[62] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[63] / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
		   tctbl[63] % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);
  vlib_cli_output (vm, " Port:");
  vlib_cli_output (vm, "   Rate = %u bytes/second", cfg->port.rate);
  vlib_cli_output (vm, "   MTU = %u bytes", cfg->port.mtu);
  vlib_cli_output (vm, "   Frame overhead = %u bytes",
		   cfg->port.frame_overhead);
  vlib_cli_output (vm, "   Number of subports = %u",
		   cfg->port.n_subports_per_port);
  vlib_cli_output (vm, "   Number of pipes per subport = %u",
		   cfg->port.n_pipes_per_subport);
  vlib_cli_output (vm,
		   "   Packet queue size: TC0 = %u, TC1 = %u, TC2 = %u, TC3 = %u packets",
		   cfg->port.qsize[0], cfg->port.qsize[1], cfg->port.qsize[2],
		   cfg->port.qsize[3]);
  vlib_cli_output (vm, "   Number of pipe profiles = %u",
		   cfg->port.n_pipe_profiles);

  for (subport_id = 0; subport_id < vec_len (cfg->subport); subport_id++)
    {
      vlib_cli_output (vm, " Subport %u:", subport_id);
      vlib_cli_output (vm, "   Rate = %u bytes/second",
		       cfg->subport[subport_id].tb_rate);
      vlib_cli_output (vm, "   Token bucket size = %u bytes",
		       cfg->subport[subport_id].tb_size);
      vlib_cli_output (vm,
		       "   Traffic class rate: TC0 = %u, TC1 = %u, TC2 = %u, TC3 = %u bytes/second",
		       cfg->subport[subport_id].tc_rate[0],
		       cfg->subport[subport_id].tc_rate[1],
		       cfg->subport[subport_id].tc_rate[2],
		       cfg->subport[subport_id].tc_rate[3]);
      vlib_cli_output (vm, "   TC period = %u milliseconds",
		       cfg->subport[subport_id].tc_period);
    }

  for (profile_id = 0; profile_id < vec_len (cfg->pipe); profile_id++)
    {
      vlib_cli_output (vm, " Pipe profile %u:", profile_id);
      vlib_cli_output (vm, "   Rate = %u bytes/second",
		       cfg->pipe[profile_id].tb_rate);
      vlib_cli_output (vm, "   Token bucket size = %u bytes",
		       cfg->pipe[profile_id].tb_size);
      vlib_cli_output (vm,
		       "   Traffic class rate: TC0 = %u, TC1 = %u, TC2 = %u, TC3 = %u bytes/second",
		       cfg->pipe[profile_id].tc_rate[0],
		       cfg->pipe[profile_id].tc_rate[1],
		       cfg->pipe[profile_id].tc_rate[2],
		       cfg->pipe[profile_id].tc_rate[3]);
      vlib_cli_output (vm, "   TC period = %u milliseconds",
		       cfg->pipe[profile_id].tc_period);
#ifdef RTE_SCHED_SUBPORT_TC_OV
      vlib_cli_output (vm, "   TC3 oversubscription_weight = %u",
		       cfg->pipe[profile_id].tc_ov_weight);
#endif

      for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
	{
	  vlib_cli_output (vm,
			   "   TC%u WRR weights: Q0 = %u, Q1 = %u, Q2 = %u, Q3 = %u",
			   i, cfg->pipe[profile_id].wrr_weights[i * 4],
			   cfg->pipe[profile_id].wrr_weights[i * 4 + 1],
			   cfg->pipe[profile_id].wrr_weights[i * 4 + 2],
			   cfg->pipe[profile_id].wrr_weights[i * 4 + 3]);
	}
    }

#ifdef RTE_SCHED_RED
  vlib_cli_output (vm, " Weighted Random Early Detection (WRED):");
  for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
      vlib_cli_output (vm, "   TC%u min: G = %u, Y = %u, R = %u", i,
		       cfg->port.red_params[i][e_RTE_METER_GREEN].min_th,
		       cfg->port.red_params[i][e_RTE_METER_YELLOW].min_th,
		       cfg->port.red_params[i][e_RTE_METER_RED].min_th);

      vlib_cli_output (vm, "   TC%u max: G = %u, Y = %u, R = %u", i,
		       cfg->port.red_params[i][e_RTE_METER_GREEN].max_th,
		       cfg->port.red_params[i][e_RTE_METER_YELLOW].max_th,
		       cfg->port.red_params[i][e_RTE_METER_RED].max_th);

      vlib_cli_output (vm,
		       "   TC%u inverted probability: G = %u, Y = %u, R = %u",
		       i, cfg->port.red_params[i][e_RTE_METER_GREEN].maxp_inv,
		       cfg->port.red_params[i][e_RTE_METER_YELLOW].maxp_inv,
		       cfg->port.red_params[i][e_RTE_METER_RED].maxp_inv);

      vlib_cli_output (vm, "   TC%u weight: R = %u, Y = %u, R = %u", i,
		       cfg->port.red_params[i][e_RTE_METER_GREEN].wq_log2,
		       cfg->port.red_params[i][e_RTE_METER_YELLOW].wq_log2,
		       cfg->port.red_params[i][e_RTE_METER_RED].wq_log2);
    }
#endif

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to display details of an output interface's HQoS
 * settings.
 *
 * @cliexpar
 * Example of how to display HQoS settings for an interfaces:
 * @cliexstart{show dpdk interface hqos GigabitEthernet0/8/0}
 *  Thread:
 *    Input SWQ size = 4096 packets
 *    Enqueue burst size = 256 packets
 *    Dequeue burst size = 220 packets
 *    Packet field 0: slab position =    0, slab bitmask = 0x0000000000000000   (subport)
 *    Packet field 1: slab position =   40, slab bitmask = 0x0000000fff000000   (pipe)
 *    Packet field 2: slab position =    8, slab bitmask = 0x00000000000000fc   (tc)
 *    Packet field 2  tc translation table: ([Mapped Value Range]: tc/queue tc/queue ...)
 *      [ 0 .. 15]: 0/0 0/1 0/2 0/3 1/0 1/1 1/2 1/3 2/0 2/1 2/2 2/3 3/0 3/1 3/2 3/3
 *      [16 .. 31]: 0/0 0/1 0/2 0/3 1/0 1/1 1/2 1/3 2/0 2/1 2/2 2/3 3/0 3/1 3/2 3/3
 *      [32 .. 47]: 0/0 0/1 0/2 0/3 1/0 1/1 1/2 1/3 2/0 2/1 2/2 2/3 3/0 3/1 3/2 3/3
 *      [48 .. 63]: 0/0 0/1 0/2 0/3 1/0 1/1 1/2 1/3 2/0 2/1 2/2 2/3 3/0 3/1 3/2 3/3
 *  Port:
 *    Rate = 1250000000 bytes/second
 *    MTU = 1514 bytes
 *    Frame overhead = 24 bytes
 *    Number of subports = 1
 *    Number of pipes per subport = 4096
 *    Packet queue size: TC0 = 64, TC1 = 64, TC2 = 64, TC3 = 64 packets
 *    Number of pipe profiles = 2
 *  Subport 0:
 *    Rate = 1250000000 bytes/second
 *    Token bucket size = 1000000 bytes
 *    Traffic class rate: TC0 = 1250000000, TC1 = 1250000000, TC2 = 1250000000, TC3 = 1250000000 bytes/second
 *    TC period = 10 milliseconds
 *  Pipe profile 0:
 *    Rate = 305175 bytes/second
 *    Token bucket size = 1000000 bytes
 *    Traffic class rate: TC0 = 305175, TC1 = 305175, TC2 = 305175, TC3 = 305175 bytes/second
 *    TC period = 40 milliseconds
 *    TC0 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
 *    TC1 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
 *    TC2 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
 *    TC3 WRR weights: Q0 = 1, Q1 = 1, Q2 = 1, Q3 = 1
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_if_hqos, static) = {
  .path = "show dpdk interface hqos",
  .short_help = "show dpdk interface hqos <interface>",
  .function = show_dpdk_if_hqos,
};

/* *INDENT-ON* */

static clib_error_t *
show_dpdk_hqos_queue_stats (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
#ifdef RTE_SCHED_COLLECT_STATS
  dpdk_main_t *dm = &dpdk_main;
  u32 hw_if_index = (u32) ~ 0;
  u32 subport = (u32) ~ 0;
  u32 pipe = (u32) ~ 0;
  u32 tc = (u32) ~ 0;
  u32 tc_q = (u32) ~ 0;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  uword *p = 0;
  struct rte_eth_dev_info dev_info;
  dpdk_device_config_t *devconf = 0;
  u32 qindex;
  struct rte_sched_queue_stats stats;
  u16 qlen;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;

      else if (unformat (line_input, "subport %d", &subport))
	;

      else if (unformat (line_input, "pipe %d", &pipe))
	;

      else if (unformat (line_input, "tc %d", &tc))
	;

      else if (unformat (line_input, "tc_q %d", &tc_q))
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
      error = clib_error_return (0, "please specify interface name!!");
      goto done;
    }

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rte_eth_dev_info_get (xd->port_id, &dev_info);
  if (dev_info.pci_dev)
    {				/* bonded interface has no pci info */
      vlib_pci_addr_t pci_addr;

      pci_addr.domain = dev_info.pci_dev->addr.domain;
      pci_addr.bus = dev_info.pci_dev->addr.bus;
      pci_addr.slot = dev_info.pci_dev->addr.devid;
      pci_addr.function = dev_info.pci_dev->addr.function;

      p =
	hash_get (dm->conf->device_config_index_by_pci_addr, pci_addr.as_u32);
    }

  if (p)
    devconf = pool_elt_at_index (dm->conf->dev_confs, p[0]);
  else
    devconf = &dm->conf->default_devconf;

  if (devconf->hqos_enabled == 0)
    {
      vlib_cli_output (vm, "HQoS disabled for this interface");
      goto done;
    }

  /*
   * Figure out which queue to query.  cf rte_sched_port_qindex.  (Not sure why
   * that method isn't made public by DPDK - how _should_ we get the queue ID?)
   */
  qindex = subport * devconf->hqos.port.n_pipes_per_subport + pipe;
  qindex = qindex * RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE + tc;
  qindex = qindex * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS + tc_q;

  if (rte_sched_queue_read_stats (xd->hqos_ht->hqos, qindex, &stats, &qlen) !=
      0)
    {
      error = clib_error_return (0, "failed to read stats");
      goto done;
    }

  vlib_cli_output (vm, "%=24s%=16s", "Stats Parameter", "Value");
  vlib_cli_output (vm, "%=24s%=16d", "Packets", stats.n_pkts);
  vlib_cli_output (vm, "%=24s%=16d", "Packets dropped", stats.n_pkts_dropped);
#ifdef RTE_SCHED_RED
  vlib_cli_output (vm, "%=24s%=16d", "Packets dropped (RED)",
		   stats.n_pkts_red_dropped);
#endif
  vlib_cli_output (vm, "%=24s%=16d", "Bytes", stats.n_bytes);
  vlib_cli_output (vm, "%=24s%=16d", "Bytes dropped", stats.n_bytes_dropped);

#else

  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  vlib_cli_output (vm, "RTE_SCHED_COLLECT_STATS disabled in DPDK");
  goto done;

#endif

done:
  unformat_free (line_input);

  return error;
}

/*?
 * This command is used to display statistics associated with a HQoS traffic class
 * queue.
 *
 * @note
 * Statistic collection by the scheduler is disabled by default in DPDK. In order to
 * turn it on, add the following line to '<em>../vpp/dpdk/Makefile</em>':
 * - <b>$(call set,RTE_SCHED_COLLECT_STATS,y)</b>
 *
 * @cliexpar
 * Example of how to display statistics of HQoS a HQoS traffic class queue:
 * @cliexstart{show dpdk hqos queue GigabitEthernet0/9/0 subport 0 pipe 3181 tc 0 tc_q 0}
 *      Stats Parameter          Value
 *          Packets               140
 *      Packets dropped            0
 *           Bytes               8400
 *       Bytes dropped             0
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_hqos_queue_stats, static) = {
  .path = "show dpdk hqos queue",
  .short_help = "show dpdk hqos queue <interface> subport <subport_id> pipe <pipe_id> tc <tc_id> tc_q <queue_id>",
  .function = show_dpdk_hqos_queue_stats,
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
 * DPDK EAL init args:  -c 1 -n 4 --huge-dir /run/vpp/hugepages --file-prefix vpp -w 0000:00:08.0 -w 0000:00:09.0 --master-lcore 0 --socket-mem 256
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vpe_version_command, static) = {
  .path = "show dpdk version",
  .short_help = "show dpdk version",
  .function = show_dpdk_version_command_fn,
};
/* *INDENT-ON* */

#if CLI_DEBUG

static clib_error_t *
dpdk_validate_buffers_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd_arg)
{
  u32 n_invalid_bufs = 0, uninitialized = 0;
  u32 is_poison = 0, is_test = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "poison"))
	is_poison = 1;
      else if (unformat (input, "trajectory"))
	is_test = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (VLIB_BUFFER_TRACE_TRAJECTORY == 0)
    {
      vlib_cli_output (vm, "Trajectory not enabled. Recompile with "
		       "VLIB_BUFFER_TRACE_TRAJECTORY 1");
      return 0;
    }
  if (is_poison)
    {
      dpdk_buffer_poison_trajectory_all ();
    }
  if (is_test)
    {
      n_invalid_bufs = dpdk_buffer_validate_trajectory_all (&uninitialized);
      if (!n_invalid_bufs)
	vlib_cli_output (vm, "All buffers are valid %d uninitialized",
			 uninitialized);
      else
	vlib_cli_output (vm, "Found %d invalid buffers and %d uninitialized",
			 n_invalid_bufs, uninitialized);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_dpdk_buffers_command, static) =
{
  .path = "test dpdk buffers",
  .short_help = "test dpdk buffers [poison] [trajectory]",
  .function = dpdk_validate_buffers_fn,
};
/* *INDENT-ON* */

#endif

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
