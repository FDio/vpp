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
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/xxhash.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/dpdk/dpdk.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/mpls/packet.h>

#include "dpdk_priv.h"

/**
 * @file
 * @brief CLI for DPDK Abstraction Layer and pcap Tx Trace.
 *
 * This file contains the source code for CLI for DPDK
 * Abstraction Layer and pcap Tx Trace.
 */

static clib_error_t *
pcap_trace_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
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
	  if (dm->tx_pcap_enable == 0)
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
	  if (dm->tx_pcap_enable)
	    {
	      vlib_cli_output (vm, "captured %d pkts...",
			       dm->pcap_main.n_packets_captured + 1);
	      if (dm->pcap_main.n_packets_captured)
		{
		  dm->pcap_main.n_packets_to_capture =
		    dm->pcap_main.n_packets_captured;
		  error = pcap_write (&dm->pcap_main);
		  if (error)
		    clib_error_report (error);
		  else
		    vlib_cli_output (vm, "saved to %s...", dm->pcap_filename);
		}

	      dm->tx_pcap_enable = 0;
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
	  if (dm->tx_pcap_enable)
	    {
	      vlib_cli_output (vm,
			       "can't change max value while pcap tx capture active...");
	      errorFlag = 1;
	      break;
	    }
	}
      else if (unformat (line_input, "intfc %U",
			 unformat_vnet_sw_interface, dm->vnet_main,
			 &dm->pcap_sw_if_index))
	;

      else if (unformat (line_input, "intfc any"))
	{
	  dm->pcap_sw_if_index = 0;
	}
      else if (unformat (line_input, "file %s", &filename))
	{
	  if (dm->tx_pcap_enable)
	    {
	      vlib_cli_output (vm,
			       "can't change file while pcap tx capture active...");
	      errorFlag = 1;
	      break;
	    }

	  /* Brain-police user path input */
	  if (strstr ((char *) filename, "..")
	      || index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      vlib_cli_output (vm,
			       "Hint: Only filename, do not enter directory structure.");
	      vec_free (filename);
	      errorFlag = 1;
	      break;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);
	  vec_free (filename);
	}
      else if (unformat (line_input, "status"))
	{
	  if (dm->pcap_sw_if_index == 0)
	    {
	      vlib_cli_output (vm, "max is %d for any interface to file %s",
			       dm->
			       pcap_pkts_to_capture ? dm->pcap_pkts_to_capture
			       : PCAP_DEF_PKT_TO_CAPTURE,
			       dm->
			       pcap_filename ? dm->pcap_filename : (u8 *)
			       "/tmp/vpe.pcap");
	    }
	  else
	    {
	      vlib_cli_output (vm, "max is %d for interface %U to file %s",
			       dm->
			       pcap_pkts_to_capture ? dm->pcap_pkts_to_capture
			       : PCAP_DEF_PKT_TO_CAPTURE,
			       format_vnet_sw_if_index_name, dm->vnet_main,
			       dm->pcap_sw_if_index,
			       dm->
			       pcap_filename ? dm->pcap_filename : (u8 *)
			       "/tmp/vpe.pcap");
	    }

	  if (dm->tx_pcap_enable == 0)
	    {
	      vlib_cli_output (vm, "pcap tx capture is off...");
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap tx capture is on: %d of %d pkts...",
			       dm->pcap_main.n_packets_captured,
			       dm->pcap_main.n_packets_to_capture);
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
	  if (dm->pcap_filename)
	    vec_free (dm->pcap_filename);
	  vec_add1 (chroot_filename, 0);
	  dm->pcap_filename = chroot_filename;
	}

      if (max)
	dm->pcap_pkts_to_capture = max;


      if (enabled)
	{
	  if (dm->pcap_filename == 0)
	    dm->pcap_filename = format (0, "/tmp/vpe.pcap%c", 0);

	  memset (&dm->pcap_main, 0, sizeof (dm->pcap_main));
	  dm->pcap_main.file_name = (char *) dm->pcap_filename;
	  dm->pcap_main.n_packets_to_capture = PCAP_DEF_PKT_TO_CAPTURE;
	  if (dm->pcap_pkts_to_capture)
	    dm->pcap_main.n_packets_to_capture = dm->pcap_pkts_to_capture;

	  dm->pcap_main.packet_type = PCAP_PACKET_TYPE_ethernet;
	  dm->tx_pcap_enable = 1;
	  vlib_cli_output (vm, "pcap tx capture on...");
	}
    }
  else if (chroot_filename)
    vec_free (chroot_filename);


  return error;
}

/*?
 * This command is used to start or stop a packet capture, or show
 * the status of packet capture.
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
 *   with '<em>status</em>' will be ingnored and not applied.
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
VLIB_CLI_COMMAND (pcap_trace_command, static) = {
    .path = "pcap tx trace",
    .short_help =
    "pcap tx trace [on|off] [max <nn>] [intfc <interface>|any] [file <name>] [status]",
    .function = pcap_trace_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
show_dpdk_buffer (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  struct rte_mempool *rmp;
  int i;

  for (i = 0; i < vec_len (dpdk_main.pktmbuf_pools); i++)
    {
      rmp = dpdk_main.pktmbuf_pools[i];
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_bufferr,static) = {
    .path = "show dpdk buffer",
    .short_help = "show dpdk buffer state",
    .function = show_dpdk_buffer,
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_test_dpdk_buffer,static) = {
    .path = "test dpdk buffer",
    .short_help = "test dpdk buffer [allocate <nn>][free <nn>]",
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

  error = dpdk_port_setup (dm, xd);

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_desc,static) = {
    .path = "set dpdk interface descriptors",
    .short_help = "set dpdk interface descriptors <if-name> [rx <n>] [tx <n>]",
    .function = set_dpdk_if_desc,
};
/* *INDENT-ON* */

static clib_error_t *
show_dpdk_if_placement (vlib_main_t * vm, unformat_input_t * input,
			vlib_cli_command_t * cmd)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_and_queue_t *dq;
  int cpu;

  if (tm->n_vlib_mains == 1)
    vlib_cli_output (vm, "All interfaces are handled by main thread");

  for (cpu = 0; cpu < vec_len (dm->devices_by_cpu); cpu++)
    {
      if (vec_len (dm->devices_by_cpu[cpu]))
	vlib_cli_output (vm, "Thread %u (%s at lcore %u):", cpu,
			 vlib_worker_threads[cpu].name,
			 vlib_worker_threads[cpu].lcore_id);

      /* *INDENT-OFF* */
      vec_foreach(dq, dm->devices_by_cpu[cpu])
        {
          u32 hw_if_index = dm->devices[dq->device].vlib_hw_if_index;
          vnet_hw_interface_t * hi =  vnet_get_hw_interface(dm->vnet_main, hw_if_index);
          vlib_cli_output(vm, "  %v queue %u", hi->name, dq->queue_id);
        }
      /* *INDENT-ON* */
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_if_placement,static) = {
    .path = "show dpdk interface placement",
    .short_help = "show dpdk interface placement",
    .function = show_dpdk_if_placement,
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
set_dpdk_if_placement (vlib_main_t * vm, unformat_input_t * input,
		       vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_and_queue_t *dq;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;
  u32 queue = (u32) 0;
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
      else if (unformat (line_input, "queue %d", &queue))
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
    {
      error = clib_error_return (0, "please specify valid interface name");
      goto done;
    }

  if (cpu < dm->input_cpu_first_index ||
      cpu >= (dm->input_cpu_first_index + dm->input_cpu_count))
    {
      error = clib_error_return (0, "please specify valid thread id");
      goto done;
    }

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  for (i = 0; i < vec_len (dm->devices_by_cpu); i++)
    {
      /* *INDENT-OFF* */
      vec_foreach(dq, dm->devices_by_cpu[i])
        {
          if (hw_if_index == dm->devices[dq->device].vlib_hw_if_index &&
              queue == dq->queue_id)
            {
              if (cpu == i) /* nothing to do */
                goto done;

              vec_del1(dm->devices_by_cpu[i], dq - dm->devices_by_cpu[i]);
              vec_add2(dm->devices_by_cpu[cpu], dq, 1);
              dq->queue_id = queue;
              dq->device = xd->device_index;
              xd->cpu_socket_id_by_queue[queue] =
                rte_lcore_to_socket_id(vlib_worker_threads[cpu].lcore_id);

              vec_sort_with_function(dm->devices_by_cpu[i],
                                     dpdk_device_queue_sort);

              vec_sort_with_function(dm->devices_by_cpu[cpu],
                                     dpdk_device_queue_sort);

              if (vec_len(dm->devices_by_cpu[i]) == 0)
                vlib_node_set_state (vlib_mains[i], dpdk_input_node.index,
                                     VLIB_NODE_STATE_DISABLED);

              if (vec_len(dm->devices_by_cpu[cpu]) == 1)
                vlib_node_set_state (vlib_mains[cpu], dpdk_input_node.index,
                                     VLIB_NODE_STATE_POLLING);

              goto done;
            }
        }
      /* *INDENT-ON* */
    }

  error = clib_error_return (0, "not found");

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_placement,static) = {
    .path = "set dpdk interface placement",
    .short_help = "set dpdk interface placement <if-name> [queue <n>]  thread <n>",
    .function = set_dpdk_if_placement,
};
/* *INDENT-ON* */

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
      if (vec_len (dm->devices_by_hqos_cpu[cpu]))
	vlib_cli_output (vm, "Thread %u (%s at lcore %u):", cpu,
			 vlib_worker_threads[cpu].name,
			 vlib_worker_threads[cpu].lcore_id);

      vec_foreach (dq, dm->devices_by_hqos_cpu[cpu])
      {
	u32 hw_if_index = dm->devices[dq->device].vlib_hw_if_index;
	vnet_hw_interface_t *hi =
	  vnet_get_hw_interface (dm->vnet_main, hw_if_index);
	vlib_cli_output (vm, "  %v queue %u", hi->name, dq->queue_id);
      }
    }
  return 0;
}

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
	if (hw_if_index == dm->devices[dq->device].vlib_hw_if_index)
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_placement, static) = {
  .path = "set dpdk interface hqos placement",
  .short_help = "set dpdk interface hqos placement <if-name> thread <n>",
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_pipe, static) =
{
  .path = "set dpdk interface hqos pipe",
  .short_help = "set dpdk interface hqos pipe <if-name> subport <n> pipe <n> "
                  "profile <n>",
  .function = set_dpdk_if_hqos_pipe,
};
/* *INDENT-ON* */

static clib_error_t *
set_dpdk_if_hqos_subport (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  dpdk_main_t *dm = &dpdk_main;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;
  u32 subport_id = (u32) ~ 0;
  struct rte_sched_subport_params p = {
    .tb_rate = 1250000000,	/* 10GbE */
    .tb_size = 1000000,
    .tc_rate = {1250000000, 1250000000, 1250000000, 1250000000},
    .tc_period = 10,
  };
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
      else if (unformat (line_input, "rate %d", &p.tb_rate))
	{
	  p.tc_rate[0] = p.tb_rate;
	  p.tc_rate[1] = p.tb_rate;
	  p.tc_rate[2] = p.tb_rate;
	  p.tc_rate[3] = p.tb_rate;
	}
      else if (unformat (line_input, "bktsize %d", &p.tb_size))
	;
      else if (unformat (line_input, "tc0 %d", &p.tc_rate[0]))
	;
      else if (unformat (line_input, "tc1 %d", &p.tc_rate[1]))
	;
      else if (unformat (line_input, "tc2 %d", &p.tc_rate[2]))
	;
      else if (unformat (line_input, "tc3 %d", &p.tc_rate[3]))
	;
      else if (unformat (line_input, "period %d", &p.tc_period))
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

  rv = rte_sched_subport_config (xd->hqos_ht->hqos, subport_id, &p);
  if (rv)
    {
      error = clib_error_return (0, "subport configuration failed");
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_subport, static) = {
  .path = "set dpdk interface hqos subport",
  .short_help = "set dpdk interface hqos subport <if-name> subport <n> "
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
      error = clib_error_return (0, "invalid traffic class");
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_tctbl, static) = {
  .path = "set dpdk interface hqos tctbl",
  .short_help = "set dpdk interface hqos tctbl <if-name> entry <n> tc <n> queue <n>",
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

  rte_eth_dev_info_get (xd->device_index, &dev_info);
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
	  __builtin_ctzll (mask);
	break;
      case 1:
	xd->hqos_wt[worker_thread_first + i].hqos_field1_slabpos = offset;
	xd->hqos_wt[worker_thread_first + i].hqos_field1_slabmask = mask;
	xd->hqos_wt[worker_thread_first + i].hqos_field1_slabshr =
	  __builtin_ctzll (mask);
	break;
      case 2:
      default:
	xd->hqos_wt[worker_thread_first + i].hqos_field2_slabpos = offset;
	xd->hqos_wt[worker_thread_first + i].hqos_field2_slabmask = mask;
	xd->hqos_wt[worker_thread_first + i].hqos_field2_slabshr =
	  __builtin_ctzll (mask);
      }

done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_dpdk_if_hqos_pktfield, static) = {
  .path = "set dpdk interface hqos pktfield",
  .short_help = "set dpdk interface hqos pktfield <if-name> id <n> offset <n> "
                 "mask <n>",
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
  u32 profile_id, i;
  struct rte_eth_dev_info dev_info;
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

  rte_eth_dev_info_get (xd->device_index, &dev_info);
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
		   "   Packet field 0: slab position = %4u, slab bitmask = 0x%016llx",
		   wk->hqos_field0_slabpos, wk->hqos_field0_slabmask);
  vlib_cli_output (vm,
		   "   Packet field 1: slab position = %4u, slab bitmask = 0x%016llx",
		   wk->hqos_field1_slabpos, wk->hqos_field1_slabmask);
  vlib_cli_output (vm,
		   "   Packet field 2: slab position = %4u, slab bitmask = 0x%016llx",
		   wk->hqos_field2_slabpos, wk->hqos_field2_slabmask);
  vlib_cli_output (vm, "   Packet field 2 translation table:");
  vlib_cli_output (vm, "     [ 0 .. 15]: "
		   "%2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u",
		   tctbl[0], tctbl[1], tctbl[2], tctbl[3],
		   tctbl[4], tctbl[5], tctbl[6], tctbl[7],
		   tctbl[8], tctbl[9], tctbl[10], tctbl[11],
		   tctbl[12], tctbl[13], tctbl[14], tctbl[15]);
  vlib_cli_output (vm, "     [16 .. 31]: "
		   "%2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u",
		   tctbl[16], tctbl[17], tctbl[18], tctbl[19],
		   tctbl[20], tctbl[21], tctbl[22], tctbl[23],
		   tctbl[24], tctbl[25], tctbl[26], tctbl[27],
		   tctbl[28], tctbl[29], tctbl[30], tctbl[31]);
  vlib_cli_output (vm, "     [32 .. 47]: "
		   "%2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u",
		   tctbl[32], tctbl[33], tctbl[34], tctbl[35],
		   tctbl[36], tctbl[37], tctbl[38], tctbl[39],
		   tctbl[40], tctbl[41], tctbl[42], tctbl[43],
		   tctbl[44], tctbl[45], tctbl[46], tctbl[47]);
  vlib_cli_output (vm, "     [48 .. 63]: "
		   "%2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u %2u",
		   tctbl[48], tctbl[49], tctbl[50], tctbl[51],
		   tctbl[52], tctbl[53], tctbl[54], tctbl[55],
		   tctbl[56], tctbl[57], tctbl[58], tctbl[59],
		   tctbl[60], tctbl[61], tctbl[62], tctbl[63]);

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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_if_hqos, static) = {
  .path = "show dpdk interface hqos",
  .short_help = "show dpdk interface hqos <if-name>",
  .function = show_dpdk_if_hqos,
};

/* *INDENT-ON* */

static clib_error_t *
show_dpdk_hqos_queue_stats (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
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
  clib_error_t *error = NULL;

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

  rte_eth_dev_info_get (xd->device_index, &dev_info);
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


done:
  unformat_free (line_input);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_hqos_queue_stats, static) = {
  .path = "show dpdk hqos queue",
  .short_help = "show dpdk hqos queue <if-name> subport <subport> pipe <pipe> tc <tc> tc_q <tc_q>",
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

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_vpe_version_command, static) = {
  .path = "show dpdk version",
  .short_help = "show dpdk version information",
  .function = show_dpdk_version_command_fn,
};
/* *INDENT-ON* */

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
