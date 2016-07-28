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
#include <vnet/mpls-gre/packet.h>

#include "dpdk_priv.h"

static clib_error_t *
pcap_trace_command_fn (vlib_main_t * vm,
     unformat_input_t * input,
     vlib_cli_command_t * cmd)
{
  dpdk_main_t * dm = &dpdk_main;
  u8 * filename;
  u32 max;
  int matched = 0;
  clib_error_t * error = 0;

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
                               dm->pcap_main.n_packets_captured+1);
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
          u8 * chroot_filename;
          /* Brain-police user path input */
          if (strstr((char *)filename, "..") || index((char *)filename, '/'))
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

VLIB_CLI_COMMAND (pcap_trace_command, static) = {
    .path = "pcap tx trace",
    .short_help =
    "pcap tx trace on off max <nn> intfc <intfc> file <name> status",
    .function = pcap_trace_command_fn,
};


static clib_error_t *
show_dpdk_buffer (vlib_main_t * vm, unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  struct rte_mempool * rmp;
  int i;

  for(i = 0; i < vec_len(vm->buffer_main->pktmbuf_pools); i++)
    {
      rmp = vm->buffer_main->pktmbuf_pools[i];
      if (rmp)
        {
#if RTE_VERSION >= RTE_VERSION_NUM(16, 7, 0, 0)
          unsigned count = rte_mempool_avail_count(rmp);
          unsigned free_count = rte_mempool_in_use_count(rmp);
#else
          unsigned count = rte_mempool_count(rmp);
          unsigned free_count = rte_mempool_free_count(rmp);
#endif

          vlib_cli_output(vm, "name=\"%s\"  available = %7d allocated = %7d total = %7d\n",
                          rmp->name, (u32)count, (u32)free_count,
                          (u32)(count+free_count));
        }
      else
        {
           vlib_cli_output(vm, "rte_mempool is NULL (!)\n");
        }
    }
  return 0;
}

VLIB_CLI_COMMAND (cmd_show_dpdk_bufferr,static) = {
    .path = "show dpdk buffer",
    .short_help = "show dpdk buffer state",
    .function = show_dpdk_buffer,
    .is_mp_safe = 1,
};

static clib_error_t *
test_dpdk_buffer (vlib_main_t * vm, unformat_input_t * input,
                 vlib_cli_command_t * cmd)
{
  static u32 * allocated_buffers;
  u32 n_alloc = 0;
  u32 n_free = 0;
  u32 first, actual_alloc;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
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

      first = vec_len(allocated_buffers) - n_free;
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

  if (allocated_buffers && vec_len(allocated_buffers) == 0)
    vec_free(allocated_buffers);

  return 0;
}

VLIB_CLI_COMMAND (cmd_test_dpdk_buffer,static) = {
    .path = "test dpdk buffer",
    .short_help = "test dpdk buffer [allocate <nn>][free <nn>]",
    .function = test_dpdk_buffer,
    .is_mp_safe = 1,
};

static void
show_dpdk_device_stats (vlib_main_t * vm, dpdk_device_t * xd)
{
    vlib_cli_output(vm,
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
                    xd->efd_agent.discard_cnt,
                    xd->efd_agent.total_packet_cnt);

    u32 device_queue_sz = rte_eth_rx_queue_count(xd->device_index,
                                                 0 /* queue_id */);
    vlib_cli_output(vm,
                    "  device_queue_sz         %u\n",
                    device_queue_sz);
}

static void
show_efd_config (vlib_main_t * vm)
{
    vlib_thread_main_t * tm = vlib_get_thread_main();
    dpdk_main_t * dm = &dpdk_main;

    vlib_cli_output(vm,
                    "dpdk:   (0x%04x) enabled:%d monitor:%d drop_all:%d\n"
                    "  dpdk_queue_hi_thresh          %d\n"
                    "  consec_full_frames_hi_thresh  %d\n"
                    "---------\n"
                    "worker: (0x%04x) enabled:%d monitor:%d\n"
                    "  worker_queue_hi_thresh        %d\n",
                    dm->efd.enabled,
                    ((dm->efd.enabled & DPDK_EFD_DISCARD_ENABLED) ? 1:0),
                    ((dm->efd.enabled & DPDK_EFD_MONITOR_ENABLED) ? 1:0),
                    ((dm->efd.enabled & DPDK_EFD_DROPALL_ENABLED) ? 1:0),
                    dm->efd.queue_hi_thresh,
                    dm->efd.consec_full_frames_hi_thresh,
                    tm->efd.enabled,
                    ((tm->efd.enabled & VLIB_EFD_DISCARD_ENABLED) ? 1:0),
                    ((dm->efd.enabled & VLIB_EFD_MONITOR_ENABLED) ? 1:0),
                    tm->efd.queue_hi_thresh);
    vlib_cli_output(vm,
                    "---------\n"
                    "ip_prec_bitmap   0x%02x\n"
                    "mpls_exp_bitmap  0x%02x\n"
                    "vlan_cos_bitmap  0x%02x\n",
                    tm->efd.ip_prec_bitmap,
                    tm->efd.mpls_exp_bitmap,
                    tm->efd.vlan_cos_bitmap);
}

static clib_error_t *
show_efd (vlib_main_t * vm,
          unformat_input_t * input,
          vlib_cli_command_t * cmd)
{

    if (unformat(input, "config")) {
        show_efd_config(vm);
    } else if (unformat(input, "dpdk")) {
        dpdk_main_t * dm = &dpdk_main;
        dpdk_device_t * xd;
        u32 device_id = ~0;

        unformat(input, "device %d", &device_id);
        vec_foreach (xd, dm->devices) {
            if ((xd->device_index == device_id) || (device_id == ~0)) {
                show_dpdk_device_stats(vm, xd);
            }
        }
    } else if (unformat(input, "worker")) {
        vlib_thread_main_t * tm = vlib_get_thread_main();
        vlib_frame_queue_t *fq;
        vlib_thread_registration_t * tr;
        int thread_id;
        u32 num_workers = 0;
        u32 first_worker_index = 0;
        uword * p;

        p = hash_get_mem (tm->thread_registrations_by_name, "workers");
        ASSERT (p);
        tr = (vlib_thread_registration_t *) p[0];
        if (tr)
          {
            num_workers = tr->count;
            first_worker_index = tr->first_index;
          }

        vlib_cli_output(vm,
                        "num_workers               %d\n"
                        "first_worker_index        %d\n"
                        "vlib_frame_queues[%d]:\n",
                        num_workers,
                        first_worker_index,
                        tm->n_vlib_mains);

        for (thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++) {
            fq = vlib_frame_queues[thread_id];
            if (fq) {
                vlib_cli_output(vm,
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
    } else if (unformat(input, "help")) {
        vlib_cli_output(vm, "Usage: show efd config | "
                        "dpdk [device <id>] | worker\n");
    } else {
        show_efd_config(vm);
    }

    return 0;
}

VLIB_CLI_COMMAND (show_efd_command, static) = {
  .path = "show efd",
  .short_help = "Show efd [device <id>] | [config]",
  .function = show_efd,
};

static clib_error_t *
clear_efd (vlib_main_t * vm,
           unformat_input_t * input,
           vlib_cli_command_t * cmd)
{
    dpdk_main_t * dm = &dpdk_main;
    dpdk_device_t * xd;
    vlib_thread_main_t * tm = vlib_get_thread_main();
    vlib_frame_queue_t *fq;
    int thread_id;

    vec_foreach (xd, dm->devices) {
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

    for (thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++) {
        fq = vlib_frame_queues[thread_id];
        if (fq) {
            fq->enqueue_full_events = 0;
            fq->enqueue_efd_discards = 0;
        }
    }

    return 0;
}

VLIB_CLI_COMMAND (clear_efd_command,static) = {
  .path = "clear efd",
  .short_help = "Clear early-fast-discard counters",
  .function = clear_efd,
};

static clib_error_t *
parse_op_and_prec (vlib_main_t *vm, unformat_input_t *input,
                   vlib_cli_command_t *cmd,
                   char *prec_type, u8 *prec_bitmap)
{
    clib_error_t * error = NULL;
    u8 op = 0;
    u8 prec = 0;

    if (unformat(input, "ge")) {
        op = EFD_OPERATION_GREATER_OR_EQUAL;
    } else if (unformat(input, "lt")) {
        op = EFD_OPERATION_LESS_THAN;
    } else if (unformat(input, "help")) {
        vlib_cli_output(vm,
            "enter operation [ge | lt] and precedence <0-7>)");
        return (error);
    } else {
        return clib_error_return(0, "unknown input `%U'",
                                  format_unformat_error, input);
    }

    if (unformat (input, "%u", &prec)) {
         if (prec > 7) {
             return clib_error_return(0, "precedence %d is out of range <0-7>",
                                      prec);
         }
    } else {
        return clib_error_return(0, "unknown input `%U'",
                                 format_unformat_error, input);
    }

    set_efd_bitmap(prec_bitmap, prec, op);

    vlib_cli_output(vm,
        "EFD will be set for %s precedence %s%u%s.",
        prec_type,
        (op == EFD_OPERATION_LESS_THAN) ? "less than " : "",
        prec,
        (op == EFD_OPERATION_GREATER_OR_EQUAL) ? " and greater" : "");

    return (error);
}


static clib_error_t *
set_efd (vlib_main_t *vm, unformat_input_t *input,
          vlib_cli_command_t *cmd)
{
    dpdk_main_t * dm = &dpdk_main;
    vlib_thread_main_t * tm = vlib_get_thread_main();
    clib_error_t * error = NULL;
    vlib_node_runtime_t * rt = vlib_node_get_runtime (vm, dpdk_input_node.index);

    if (unformat(input, "enable")) {
        if (unformat(input, "dpdk")) {
            dm->efd.enabled |= DPDK_EFD_DISCARD_ENABLED;
        } else if (unformat(input, "worker")) {
            tm->efd.enabled |= VLIB_EFD_DISCARD_ENABLED;
        } else if (unformat(input, "monitor")) {
            dm->efd.enabled |= DPDK_EFD_MONITOR_ENABLED;
            tm->efd.enabled |= VLIB_EFD_MONITOR_ENABLED;
        } else if (unformat(input, "drop_all")) {
            dm->efd.enabled |= DPDK_EFD_DROPALL_ENABLED;
        } else if (unformat(input, "default")) {
            dm->efd.enabled = (DPDK_EFD_DISCARD_ENABLED |
                               DPDK_EFD_MONITOR_ENABLED);
            tm->efd.enabled = (VLIB_EFD_DISCARD_ENABLED |
                               VLIB_EFD_MONITOR_ENABLED);
        } else {
            return clib_error_return(0, "Usage: set efd enable [dpdk | "
                                     "worker | monitor | drop_all | default]");
        }
    } else if (unformat(input, "disable")) {
        if (unformat(input, "dpdk")) {
            dm->efd.enabled &= ~DPDK_EFD_DISCARD_ENABLED;
        } else if (unformat(input, "worker")) {
            tm->efd.enabled &= ~VLIB_EFD_DISCARD_ENABLED;
        } else if (unformat(input, "monitor")) {
            dm->efd.enabled &= ~DPDK_EFD_MONITOR_ENABLED;
            tm->efd.enabled &= ~VLIB_EFD_MONITOR_ENABLED;
        } else if (unformat(input, "drop_all")) {
            dm->efd.enabled &= ~DPDK_EFD_DROPALL_ENABLED;
        } else  if (unformat(input, "all")) {
            dm->efd.enabled = 0;
            tm->efd.enabled = 0;
        } else {
            return clib_error_return(0, "Usage: set efd disable [dpdk | "
                                     "worker | monitor | drop_all | all]");
        }
    } else if (unformat(input, "worker_queue_hi_thresh")) {
        u32 mark;
        if (unformat (input, "%u", &mark)) {
            tm->efd.queue_hi_thresh = mark;
        } else {
            return clib_error_return(0, "unknown input `%U'",
                                     format_unformat_error, input);
        }
    } else if (unformat(input, "dpdk_device_hi_thresh")) {
        u32 thresh;
        if (unformat (input, "%u", &thresh)) {
            dm->efd.queue_hi_thresh = thresh;
        } else {
            return clib_error_return(0, "unknown input `%U'",
                                     format_unformat_error, input);
        }
    } else if (unformat(input, "consec_full_frames_hi_thresh")) {
        u32 thresh;
        if (unformat (input, "%u", &thresh)) {
            dm->efd.consec_full_frames_hi_thresh = thresh;
        } else {
            return clib_error_return(0, "unknown input `%U'",
                                     format_unformat_error, input);
        }
    } else if (unformat(input, "ip-prec")) {
        return (parse_op_and_prec(vm, input, cmd,
                                 "ip", &tm->efd.ip_prec_bitmap));
    } else if (unformat(input, "mpls-exp")) {
        return (parse_op_and_prec(vm, input, cmd,
                                 "mpls", &tm->efd.mpls_exp_bitmap));
    } else if (unformat(input, "vlan-cos")) {
        return (parse_op_and_prec(vm, input, cmd,
                                 "vlan", &tm->efd.vlan_cos_bitmap));
    } else if (unformat(input, "help")) {
        vlib_cli_output(vm,
            "Usage:\n"
            "  set efd enable <dpdk | worker | monitor | drop_all | default> |\n"
            "  set efd disable <dpdk | worker | monitor | drop_all | all> |\n"
            "  set efd <ip-prec | mpls-exp | vlan-cos> <ge | lt> <0-7>\n"
            "  set efd worker_queue_hi_thresh <0-32> |\n"
            "  set efd dpdk_device_hi_thresh <0-%d> |\n"
            "  set efd consec_full_frames_hi_thresh <count> |\n",
            DPDK_NB_RX_DESC_10GE);
    } else {
        return clib_error_return(0, "unknown input `%U'",
                                  format_unformat_error, input);
    }

    if (dm->efd.enabled)
	rt->function = dpdk_input_efd_multiarch_select();
    else if (dm->use_rss)
	rt->function = dpdk_input_rss_multiarch_select();
    else
	rt->function = dpdk_input_multiarch_select();

    return error;
}

VLIB_CLI_COMMAND (cmd_set_efd,static) = {
    .path = "set efd",
    .short_help = "set early-fast-discard commands",
    .function = set_efd,
};

static clib_error_t *
set_dpdk_if_desc (vlib_main_t *vm, unformat_input_t *input,
          vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  dpdk_main_t * dm = &dpdk_main;
  vnet_hw_interface_t * hw;
  dpdk_device_t * xd;
  u32 hw_if_index = (u32) ~0;
  u32 nb_rx_desc = (u32) ~0;
  u32 nb_tx_desc = (u32) ~0;
  clib_error_t * rv;

  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
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

  if (hw_if_index == (u32) ~0)
    return clib_error_return (0, "please specify valid interface name");

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  if (xd->dev_type != VNET_DPDK_DEV_ETH)
    return clib_error_return (0, "number of descriptors can be set only for "
                              "physical devices");

  if ((nb_rx_desc == (u32) ~0 || nb_rx_desc == xd->nb_rx_desc) &&
      (nb_tx_desc == (u32) ~0 || nb_tx_desc == xd->nb_tx_desc))
    return clib_error_return (0, "nothing changed");

  if (nb_rx_desc != (u32) ~0)
        xd->nb_rx_desc = nb_rx_desc;

  if (nb_tx_desc != (u32) ~0)
        xd->nb_rx_desc = nb_rx_desc;

  rv = dpdk_port_setup(dm, xd);

  return rv;
}

VLIB_CLI_COMMAND (cmd_set_dpdk_if_desc,static) = {
    .path = "set dpdk interface descriptors",
    .short_help = "set dpdk interface descriptors <if-name> [rx <n>] [tx <n>]",
    .function = set_dpdk_if_desc,
};

static clib_error_t *
show_dpdk_if_placement (vlib_main_t *vm, unformat_input_t *input,
          vlib_cli_command_t *cmd)
{
  vlib_thread_main_t * tm = vlib_get_thread_main();
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_and_queue_t * dq;
  int cpu;

  if (tm->n_vlib_mains == 1)
    vlib_cli_output(vm, "All interfaces are handled by main thread");

  for(cpu = 0; cpu < vec_len(dm->devices_by_cpu); cpu++)
    {
      if (vec_len(dm->devices_by_cpu[cpu]))
        vlib_cli_output(vm, "Thread %u (%s at lcore %u):", cpu,
                        vlib_worker_threads[cpu].name,
                        vlib_worker_threads[cpu].dpdk_lcore_id);

      vec_foreach(dq, dm->devices_by_cpu[cpu])
        {
          u32 hw_if_index = dm->devices[dq->device].vlib_hw_if_index;
          vnet_hw_interface_t * hi =  vnet_get_hw_interface(dm->vnet_main, hw_if_index);
          vlib_cli_output(vm, "  %v queue %u", hi->name, dq->queue_id);
        }
    }
  return 0;
}

VLIB_CLI_COMMAND (cmd_show_dpdk_if_placement,static) = {
    .path = "show dpdk interface placement",
    .short_help = "show dpdk interface placement",
    .function = show_dpdk_if_placement,
};

static int
dpdk_device_queue_sort(void * a1, void * a2)
{
  dpdk_device_and_queue_t * dq1 = a1;
  dpdk_device_and_queue_t * dq2 = a2;

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
set_dpdk_if_placement (vlib_main_t *vm, unformat_input_t *input,
          vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_and_queue_t * dq;
  vnet_hw_interface_t * hw;
  dpdk_device_t * xd;
  u32 hw_if_index = (u32) ~0;
  u32 queue = (u32) 0;
  u32 cpu = (u32) ~0;
  int i;

  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "%U", unformat_vnet_hw_interface, dm->vnet_main,
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

  if (hw_if_index == (u32) ~0)
    return clib_error_return (0, "please specify valid interface name");

  if (cpu < dm->input_cpu_first_index ||
      cpu >= (dm->input_cpu_first_index + dm->input_cpu_count))
    return clib_error_return (0, "please specify valid thread id");

  hw = vnet_get_hw_interface (dm->vnet_main, hw_if_index);
  xd = vec_elt_at_index (dm->devices, hw->dev_instance);

  for(i = 0; i < vec_len(dm->devices_by_cpu); i++)
    {
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
                rte_lcore_to_socket_id(vlib_worker_threads[cpu].dpdk_lcore_id);

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
    }

  return clib_error_return (0, "not found");
}

VLIB_CLI_COMMAND (cmd_set_dpdk_if_placement,static) = {
    .path = "set dpdk interface placement",
    .short_help = "set dpdk interface placement <if-name> [queue <n>]  thread <n>",
    .function = set_dpdk_if_placement,
};

clib_error_t *
dpdk_cli_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (dpdk_cli_init);
