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

static clib_error_t *
pcap_trace_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  dpdk_main_t *dm = &dpdk_main;
  u8 *filename;
  u32 max;
  int matched = 0;
  clib_error_t *error = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "on"))
	{
	  if (dm->tx_pcap_enable == 0)
	    {
	      if (dm->pcap_filename == 0)
		dm->pcap_filename = format (0, "/tmp/vpe.pcap%c", 0);

	      memset (&dm->pcap_main, 0, sizeof (dm->pcap_main));
	      dm->pcap_main.file_name = (char *) dm->pcap_filename;
	      dm->pcap_main.n_packets_to_capture = 100;
	      if (dm->pcap_pkts_to_capture)
		dm->pcap_main.n_packets_to_capture = dm->pcap_pkts_to_capture;

	      dm->pcap_main.packet_type = PCAP_PACKET_TYPE_ethernet;
	      dm->tx_pcap_enable = 1;
	      matched = 1;
	      vlib_cli_output (vm, "pcap tx capture on...");
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap tx capture already on...");
	    }
	  matched = 1;
	}
      else if (unformat (input, "off"))
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
	    }
	  else
	    {
	      vlib_cli_output (vm, "pcap tx capture already off...");
	    }

	  dm->tx_pcap_enable = 0;
	  matched = 1;
	}
      else if (unformat (input, "max %d", &max))
	{
	  dm->pcap_pkts_to_capture = max;
	  matched = 1;
	}

      else if (unformat (input, "intfc %U",
			 unformat_vnet_sw_interface, dm->vnet_main,
			 &dm->pcap_sw_if_index))
	matched = 1;
      else if (unformat (input, "intfc any"))
	{
	  dm->pcap_sw_if_index = 0;
	  matched = 1;
	}
      else if (unformat (input, "file %s", &filename))
	{
	  u8 *chroot_filename;
	  /* Brain-police user path input */
	  if (strstr ((char *) filename, "..")
	      || index ((char *) filename, '/'))
	    {
	      vlib_cli_output (vm, "illegal characters in filename '%s'",
			       filename);
	      continue;
	    }

	  chroot_filename = format (0, "/tmp/%s%c", filename, 0);
	  vec_free (filename);

	  if (dm->pcap_filename)
	    vec_free (dm->pcap_filename);
	  vec_add1 (filename, 0);
	  dm->pcap_filename = chroot_filename;
	  matched = 1;
	}
      else if (unformat (input, "status"))
	{
	  if (dm->tx_pcap_enable == 0)
	    {
	      vlib_cli_output (vm, "pcap tx capture is off...");
	      continue;
	    }

	  vlib_cli_output (vm, "pcap tx capture: %d of %d pkts...",
			   dm->pcap_main.n_packets_captured,
			   dm->pcap_main.n_packets_to_capture);
	  matched = 1;
	}

      else
	break;
    }

  if (matched == 0)
    return clib_error_return (0, "unknown input `%U'",
			      format_unformat_error, input);

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (pcap_trace_command, static) = {
    .path = "pcap tx trace",
    .short_help =
    "pcap tx trace on off max <nn> intfc <intfc> file <name> status",
    .function = pcap_trace_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
show_dpdk_buffer (vlib_main_t * vm, unformat_input_t * input,
		  vlib_cli_command_t * cmd)
{
  struct rte_mempool *rmp;
  int i;

  for (i = 0; i < vec_len (vm->buffer_main->pktmbuf_pools); i++)
    {
      rmp = vm->buffer_main->pktmbuf_pools[i];
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

static void
show_dpdk_device_stats (vlib_main_t * vm, dpdk_device_t * xd)
{
  vlib_cli_output (vm,
		   "device_index %d\n"
		   "  last_burst_sz           %d\n"
		   "  max_burst_sz            %d\n"
		   "  full_frames_cnt         %u\n"
		   "  consec_full_frames_cnt  %u\n"
		   "  congestion_cnt          %d\n"
		   "  last_poll_time          %llu\n"
		   "  max_poll_delay          %llu\n"
		   "  discard_cnt             %u\n"
		   "  total_packet_cnt        %u\n",
		   xd->device_index,
		   xd->efd_agent.last_burst_sz,
		   xd->efd_agent.max_burst_sz,
		   xd->efd_agent.full_frames_cnt,
		   xd->efd_agent.consec_full_frames_cnt,
		   xd->efd_agent.congestion_cnt,
		   xd->efd_agent.last_poll_time,
		   xd->efd_agent.max_poll_delay,
		   xd->efd_agent.discard_cnt, xd->efd_agent.total_packet_cnt);

  u32 device_queue_sz = rte_eth_rx_queue_count (xd->device_index,
						0 /* queue_id */ );
  vlib_cli_output (vm, "  device_queue_sz         %u\n", device_queue_sz);
}

static void
show_efd_config (vlib_main_t * vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  dpdk_main_t *dm = &dpdk_main;

  vlib_cli_output (vm,
		   "dpdk:   (0x%04x) enabled:%d monitor:%d drop_all:%d\n"
		   "  dpdk_queue_hi_thresh          %d\n"
		   "  consec_full_frames_hi_thresh  %d\n"
		   "---------\n"
		   "worker: (0x%04x) enabled:%d monitor:%d\n"
		   "  worker_queue_hi_thresh        %d\n",
		   dm->efd.enabled,
		   ((dm->efd.enabled & DPDK_EFD_DISCARD_ENABLED) ? 1 : 0),
		   ((dm->efd.enabled & DPDK_EFD_MONITOR_ENABLED) ? 1 : 0),
		   ((dm->efd.enabled & DPDK_EFD_DROPALL_ENABLED) ? 1 : 0),
		   dm->efd.queue_hi_thresh,
		   dm->efd.consec_full_frames_hi_thresh,
		   tm->efd.enabled,
		   ((tm->efd.enabled & VLIB_EFD_DISCARD_ENABLED) ? 1 : 0),
		   ((dm->efd.enabled & VLIB_EFD_MONITOR_ENABLED) ? 1 : 0),
		   tm->efd.queue_hi_thresh);
  vlib_cli_output (vm,
		   "---------\n"
		   "ip_prec_bitmap   0x%02x\n"
		   "mpls_exp_bitmap  0x%02x\n"
		   "vlan_cos_bitmap  0x%02x\n",
		   tm->efd.ip_prec_bitmap,
		   tm->efd.mpls_exp_bitmap, tm->efd.vlan_cos_bitmap);
}

static clib_error_t *
show_efd (vlib_main_t * vm,
	  unformat_input_t * input, vlib_cli_command_t * cmd)
{

  if (unformat (input, "config"))
    {
      show_efd_config (vm);
    }
  else if (unformat (input, "dpdk"))
    {
      dpdk_main_t *dm = &dpdk_main;
      dpdk_device_t *xd;
      u32 device_id = ~0;

      (void) unformat (input, "device %d", &device_id);
	/* *INDENT-OFF* */
        vec_foreach (xd, dm->devices)
	  {
            if ((xd->device_index == device_id) || (device_id == ~0))
	      {
                show_dpdk_device_stats(vm, xd);
              }
          }
	/* *INDENT-ON* */
    }
  else if (unformat (input, "worker"))
    {
      vlib_thread_main_t *tm = vlib_get_thread_main ();
      vlib_frame_queue_t *fq;
      vlib_thread_registration_t *tr;
      int thread_id;
      u32 num_workers = 0;
      u32 first_worker_index = 0;
      uword *p;

      p = hash_get_mem (tm->thread_registrations_by_name, "workers");
      ASSERT (p);
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
	{
	  num_workers = tr->count;
	  first_worker_index = tr->first_index;
	}

      vlib_cli_output (vm,
		       "num_workers               %d\n"
		       "first_worker_index        %d\n"
		       "vlib_frame_queues[%d]:\n",
		       num_workers, first_worker_index, tm->n_vlib_mains);

      for (thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++)
	{
	  fq = vlib_frame_queues[thread_id];
	  if (fq)
	    {
	      vlib_cli_output (vm,
			       "%2d: frames_queued         %u\n"
			       "    frames_queued_hint    %u\n"
			       "    enqueue_full_events   %u\n"
			       "    enqueue_efd_discards  %u\n",
			       thread_id,
			       (fq->tail - fq->head),
			       (fq->tail - fq->head_hint),
			       fq->enqueue_full_events,
			       fq->enqueue_efd_discards);
	    }
	}
    }
  else if (unformat (input, "help"))
    {
      vlib_cli_output (vm, "Usage: show efd config | "
		       "dpdk [device <id>] | worker\n");
    }
  else
    {
      show_efd_config (vm);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_efd_command, static) = {
  .path = "show efd",
  .short_help = "Show efd [device <id>] | [config]",
  .function = show_efd,
};
/* *INDENT-ON* */

static clib_error_t *
clear_efd (vlib_main_t * vm,
	   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_t *fq;
  int thread_id;

    /* *INDENT-OFF* */
    vec_foreach (xd, dm->devices)
      {
        xd->efd_agent.last_burst_sz = 0;
        xd->efd_agent.max_burst_sz = 0;
        xd->efd_agent.full_frames_cnt = 0;
        xd->efd_agent.consec_full_frames_cnt = 0;
        xd->efd_agent.congestion_cnt = 0;
        xd->efd_agent.last_poll_time = 0;
        xd->efd_agent.max_poll_delay = 0;
        xd->efd_agent.discard_cnt = 0;
        xd->efd_agent.total_packet_cnt = 0;
      }
    /* *INDENT-ON* */

  for (thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++)
    {
      fq = vlib_frame_queues[thread_id];
      if (fq)
	{
	  fq->enqueue_full_events = 0;
	  fq->enqueue_efd_discards = 0;
	}
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_efd_command,static) = {
  .path = "clear efd",
  .short_help = "Clear early-fast-discard counters",
  .function = clear_efd,
};
/* *INDENT-ON* */

static clib_error_t *
parse_op_and_prec (vlib_main_t * vm, unformat_input_t * input,
		   vlib_cli_command_t * cmd,
		   char *prec_type, u8 * prec_bitmap)
{
  clib_error_t *error = NULL;
  u8 op = 0;
  u8 prec = 0;

  if (unformat (input, "ge"))
    {
      op = EFD_OPERATION_GREATER_OR_EQUAL;
    }
  else if (unformat (input, "lt"))
    {
      op = EFD_OPERATION_LESS_THAN;
    }
  else if (unformat (input, "help"))
    {
      vlib_cli_output (vm, "enter operation [ge | lt] and precedence <0-7>)");
      return (error);
    }
  else
    {
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }

  if (unformat (input, "%u", &prec))
    {
      if (prec > 7)
	{
	  return clib_error_return (0, "precedence %d is out of range <0-7>",
				    prec);
	}
    }
  else
    {
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }

  set_efd_bitmap (prec_bitmap, prec, op);

  vlib_cli_output (vm,
		   "EFD will be set for %s precedence %s%u%s.",
		   prec_type,
		   (op == EFD_OPERATION_LESS_THAN) ? "less than " : "",
		   prec,
		   (op ==
		    EFD_OPERATION_GREATER_OR_EQUAL) ? " and greater" : "");

  return (error);
}


static clib_error_t *
set_efd (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
  dpdk_main_t *dm = &dpdk_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error = NULL;
  vlib_node_runtime_t *rt = vlib_node_get_runtime (vm, dpdk_input_node.index);

  if (unformat (input, "enable"))
    {
      if (unformat (input, "dpdk"))
	{
	  dm->efd.enabled |= DPDK_EFD_DISCARD_ENABLED;
	}
      else if (unformat (input, "worker"))
	{
	  tm->efd.enabled |= VLIB_EFD_DISCARD_ENABLED;
	}
      else if (unformat (input, "monitor"))
	{
	  dm->efd.enabled |= DPDK_EFD_MONITOR_ENABLED;
	  tm->efd.enabled |= VLIB_EFD_MONITOR_ENABLED;
	}
      else if (unformat (input, "drop_all"))
	{
	  dm->efd.enabled |= DPDK_EFD_DROPALL_ENABLED;
	}
      else if (unformat (input, "default"))
	{
	  dm->efd.enabled = (DPDK_EFD_DISCARD_ENABLED |
			     DPDK_EFD_MONITOR_ENABLED);
	  tm->efd.enabled = (VLIB_EFD_DISCARD_ENABLED |
			     VLIB_EFD_MONITOR_ENABLED);
	}
      else
	{
	  return clib_error_return (0, "Usage: set efd enable [dpdk | "
				    "worker | monitor | drop_all | default]");
	}
    }
  else if (unformat (input, "disable"))
    {
      if (unformat (input, "dpdk"))
	{
	  dm->efd.enabled &= ~DPDK_EFD_DISCARD_ENABLED;
	}
      else if (unformat (input, "worker"))
	{
	  tm->efd.enabled &= ~VLIB_EFD_DISCARD_ENABLED;
	}
      else if (unformat (input, "monitor"))
	{
	  dm->efd.enabled &= ~DPDK_EFD_MONITOR_ENABLED;
	  tm->efd.enabled &= ~VLIB_EFD_MONITOR_ENABLED;
	}
      else if (unformat (input, "drop_all"))
	{
	  dm->efd.enabled &= ~DPDK_EFD_DROPALL_ENABLED;
	}
      else if (unformat (input, "all"))
	{
	  dm->efd.enabled = 0;
	  tm->efd.enabled = 0;
	}
      else
	{
	  return clib_error_return (0, "Usage: set efd disable [dpdk | "
				    "worker | monitor | drop_all | all]");
	}
    }
  else if (unformat (input, "worker_queue_hi_thresh"))
    {
      u32 mark;
      if (unformat (input, "%u", &mark))
	{
	  tm->efd.queue_hi_thresh = mark;
	}
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }
  else if (unformat (input, "dpdk_device_hi_thresh"))
    {
      u32 thresh;
      if (unformat (input, "%u", &thresh))
	{
	  dm->efd.queue_hi_thresh = thresh;
	}
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }
  else if (unformat (input, "consec_full_frames_hi_thresh"))
    {
      u32 thresh;
      if (unformat (input, "%u", &thresh))
	{
	  dm->efd.consec_full_frames_hi_thresh = thresh;
	}
      else
	{
	  return clib_error_return (0, "unknown input `%U'",
				    format_unformat_error, input);
	}
    }
  else if (unformat (input, "ip-prec"))
    {
      return (parse_op_and_prec (vm, input, cmd,
				 "ip", &tm->efd.ip_prec_bitmap));
    }
  else if (unformat (input, "mpls-exp"))
    {
      return (parse_op_and_prec (vm, input, cmd,
				 "mpls", &tm->efd.mpls_exp_bitmap));
    }
  else if (unformat (input, "vlan-cos"))
    {
      return (parse_op_and_prec (vm, input, cmd,
				 "vlan", &tm->efd.vlan_cos_bitmap));
    }
  else if (unformat (input, "help"))
    {
      vlib_cli_output (vm,
		       "Usage:\n"
		       "  set efd enable <dpdk | worker | monitor | drop_all | default> |\n"
		       "  set efd disable <dpdk | worker | monitor | drop_all | all> |\n"
		       "  set efd <ip-prec | mpls-exp | vlan-cos> <ge | lt> <0-7>\n"
		       "  set efd worker_queue_hi_thresh <0-32> |\n"
		       "  set efd dpdk_device_hi_thresh <0-%d> |\n"
		       "  set efd consec_full_frames_hi_thresh <count> |\n",
		       DPDK_NB_RX_DESC_10GE);
    }
  else
    {
      return clib_error_return (0, "unknown input `%U'",
				format_unformat_error, input);
    }

  if (dm->efd.enabled)
    rt->function = dpdk_input_efd_multiarch_select ();
  else if (dm->use_rss)
    rt->function = dpdk_input_rss_multiarch_select ();
  else
    rt->function = dpdk_input_multiarch_select ();

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_set_efd,static) = {
    .path = "set efd",
    .short_help = "set early-fast-discard commands",
    .function = set_efd,
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
  clib_error_t *rv;

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
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  if ((xd->flags & DPDK_DEVICE_FLAG_PMD) == 0)
    return clib_error_return (0, "number of descriptors can be set only for "
			      "physical devices");

  if ((nb_rx_desc == (u32) ~ 0 || nb_rx_desc == xd->nb_rx_desc) &&
      (nb_tx_desc == (u32) ~ 0 || nb_tx_desc == xd->nb_tx_desc))
    return clib_error_return (0, "nothing changed");

  if (nb_rx_desc != (u32) ~ 0)
    xd->nb_rx_desc = nb_rx_desc;

  if (nb_tx_desc != (u32) ~ 0)
    xd->nb_rx_desc = nb_rx_desc;

  rv = dpdk_port_setup (dm, xd);

  return rv;
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
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  if (cpu < dm->input_cpu_first_index ||
      cpu >= (dm->input_cpu_first_index + dm->input_cpu_count))
    return clib_error_return (0, "please specify valid thread id");

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
                return 0;

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

              return 0;
            }
        }
      /* *INDENT-ON* */
    }

  return clib_error_return (0, "not found");
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
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  if (cpu < dm->hqos_cpu_first_index ||
      cpu >= (dm->hqos_cpu_first_index + dm->hqos_cpu_count))
    return clib_error_return (0, "please specify valid thread id");

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  for (i = 0; i < vec_len (dm->devices_by_hqos_cpu); i++)
    {
      vec_foreach (dq, dm->devices_by_hqos_cpu[i])
      {
	if (hw_if_index == dm->devices[dq->device].vlib_hw_if_index)
	  {
	    if (cpu == i)	/* nothing to do */
	      return 0;

	    vec_del1 (dm->devices_by_hqos_cpu[i],
		      dq - dm->devices_by_hqos_cpu[i]);
	    vec_add2 (dm->devices_by_hqos_cpu[cpu], dq, 1);
	    dq->queue_id = 0;
	    dq->device = xd->device_index;

	    vec_sort_with_function (dm->devices_by_hqos_cpu[i],
				    dpdk_device_queue_sort);

	    vec_sort_with_function (dm->devices_by_hqos_cpu[cpu],
				    dpdk_device_queue_sort);

	    return 0;
	  }
      }
    }

  return clib_error_return (0, "not found");
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
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rv =
    rte_sched_pipe_config (xd->hqos_ht->hqos, subport_id, pipe_id,
			   profile_id);
  if (rv)
    return clib_error_return (0, "pipe configuration failed");

  return 0;
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
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  rv = rte_sched_subport_config (xd->hqos_ht->hqos, subport_id, &p);
  if (rv)
    return clib_error_return (0, "subport configuration failed");

  return 0;
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
  u32 entry, tc, queue, val, i;

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
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");
  if (entry >= 64)
    return clib_error_return (0, "invalid entry");
  if (tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    return clib_error_return (0, "invalid traffic class");
  if (queue >= RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS)
    return clib_error_return (0, "invalid traffic class");

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  /* Detect the set of worker threads */
  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];
  int worker_thread_first = tr->first_index;
  int worker_thread_count = tr->count;

  val = tc * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS + queue;
  for (i = 0; i < worker_thread_count; i++)
    xd->hqos_wt[worker_thread_first + i].hqos_tc_table[entry] = val;

  return 0;
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

  /* Device specific data */
  struct rte_eth_dev_info dev_info;
  dpdk_device_config_t *devconf = 0;
  vnet_hw_interface_t *hw;
  dpdk_device_t *xd;
  u32 hw_if_index = (u32) ~ 0;

  /* Detect the set of worker threads */
  uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  vlib_thread_registration_t *tr = (vlib_thread_registration_t *) p[0];
  int worker_thread_first = tr->first_index;
  int worker_thread_count = tr->count;

  /* Packet field configuration */
  u64 mask;
  u32 id, offset;

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
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  /* Get interface */
  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify valid interface name");

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
      return 0;
    }

  n_subports_per_port = devconf->hqos.port.n_subports_per_port;
  n_pipes_per_subport = devconf->hqos.port.n_pipes_per_subport;
  tctbl_size = RTE_DIM (devconf->hqos.tc_table);

  /* Validate packet field configuration: id, offset and mask */
  if (id >= 3)
    return clib_error_return (0, "invalid packet field id");

  switch (id)
    {
    case 0:
      if (dpdk_hqos_validate_mask (mask, n_subports_per_port) != 0)
	return clib_error_return (0, "invalid subport ID mask "
				  "(n_subports_per_port = %u)",
				  n_subports_per_port);
      break;
    case 1:
      if (dpdk_hqos_validate_mask (mask, n_pipes_per_subport) != 0)
	return clib_error_return (0, "invalid pipe ID mask "
				  "(n_pipes_per_subport = %u)",
				  n_pipes_per_subport);
      break;
    case 2:
    default:
      if (dpdk_hqos_validate_mask (mask, tctbl_size) != 0)
	return clib_error_return (0, "invalid TC table index mask "
				  "(TC table size = %u)", tctbl_size);
    }

  /* Propagate packet field configuration to all workers */
  for (i = 0; i < worker_thread_count; i++)
    switch (id)
      {
      case 0:
	xd->hqos_wt[worker_thread_first + i].hqos_field0_slabpos = offset;
	xd->hqos_wt[worker_thread_first + i].hqos_field0_slabmask = mask;
	break;
      case 1:
	xd->hqos_wt[worker_thread_first + i].hqos_field1_slabpos = offset;
	xd->hqos_wt[worker_thread_first + i].hqos_field1_slabmask = mask;
	break;
      case 2:
      default:
	xd->hqos_wt[worker_thread_first + i].hqos_field2_slabpos = offset;
	xd->hqos_wt[worker_thread_first + i].hqos_field2_slabmask = mask;
      }

  return 0;
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

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat
	  (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
	   &hw_if_index))
	;
      else
	return clib_error_return (0, "parse error: '%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);

  if (hw_if_index == (u32) ~ 0)
    return clib_error_return (0, "please specify interface name!!");

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
      return 0;
    }

  /* Detect the set of worker threads */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
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

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cmd_show_dpdk_if_hqos, static) = {
  .path = "show dpdk interface hqos",
  .short_help = "show dpdk interface hqos <if-name>",
  .function = show_dpdk_if_hqos,
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
