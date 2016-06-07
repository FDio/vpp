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

#ifndef MAX
#define MAX(a,b) ((a) < (b) ? (b) : (a))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

/*
 * At least in certain versions of ESXi, vmware e1000's don't honor the
 * "strip rx CRC" bit. Set this flag to work around that bug FOR UNIT TEST ONLY.
 *
 * If wireshark complains like so:
 *
 * "Frame check sequence: 0x00000000 [incorrect, should be <hex-num>]"
 * and you're using ESXi emulated e1000's, set this flag FOR UNIT TEST ONLY.
 *
 * Note: do NOT check in this file with this workaround enabled! You'll lose
 * actual data from e.g. 10xGE interfaces. The extra 4 bytes annoy
 * wireshark, but they're harmless...
 */
#define VMWARE_LENGTH_BUG_WORKAROUND 0

static inline
void vlib_put_handoff_queue_elt (vlib_frame_queue_elt_t * hf)
{
  CLIB_MEMORY_BARRIER();
  hf->valid = 1;
}

static char * dpdk_error_strings[] = {
#define _(n,s) s,
    foreach_dpdk_error
#undef _
};

always_inline void
dpdk_rx_next_and_error_from_mb_flags_x1 (dpdk_device_t *xd, struct rte_mbuf *mb,
                                         vlib_buffer_t *b0,
					 u8 * next0, u8 * error0)
{
  u8 is0_ip4, is0_ip6, is0_mpls, n0;
  uint16_t mb_flags = mb->ol_flags;

  if (PREDICT_FALSE(mb_flags & (
#ifdef RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS
       PKT_EXT_RX_PKT_ERROR | PKT_EXT_RX_BAD_FCS   |
#endif /* RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS */
        PKT_RX_IP_CKSUM_BAD  | PKT_RX_L4_CKSUM_BAD
    ))) 
    {
      /* some error was flagged. determine the drop reason */ 
      n0 = DPDK_RX_NEXT_DROP;
      *error0 = 
#ifdef RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS
        (mb_flags & PKT_EXT_RX_PKT_ERROR) ? DPDK_ERROR_RX_PACKET_ERROR : 
        (mb_flags & PKT_EXT_RX_BAD_FCS) ? DPDK_ERROR_RX_BAD_FCS : 
#endif /* RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS */
        (mb_flags & PKT_RX_IP_CKSUM_BAD) ? DPDK_ERROR_IP_CHECKSUM_ERROR : 
        (mb_flags & PKT_RX_L4_CKSUM_BAD) ? DPDK_ERROR_L4_CHECKSUM_ERROR : 
        DPDK_ERROR_NONE;
    }
  else
    {
      *error0 = DPDK_ERROR_NONE;
      if (xd->per_interface_next_index != ~0)
	n0 = xd->per_interface_next_index;
      else if (mb_flags & PKT_RX_VLAN_PKT)
	n0 = DPDK_RX_NEXT_ETHERNET_INPUT;
      else
	{
	  n0 = DPDK_RX_NEXT_ETHERNET_INPUT;
#if RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0)
	  is0_ip4 = RTE_ETH_IS_IPV4_HDR(mb->packet_type) != 0;
#else
	  is0_ip4 = (mb_flags & (PKT_RX_IPV4_HDR | PKT_RX_IPV4_HDR_EXT)) != 0;
#endif

	  if (PREDICT_TRUE(is0_ip4))
	    n0 = DPDK_RX_NEXT_IP4_INPUT;
	  else
	    {
#if RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0)
	      is0_ip6 = RTE_ETH_IS_IPV6_HDR(mb->packet_type) != 0;
#else
	      is0_ip6 = 
		      (mb_flags & (PKT_RX_IPV6_HDR | PKT_RX_IPV6_HDR_EXT)) != 0;
#endif
              if (PREDICT_TRUE(is0_ip6))
	        n0 = DPDK_RX_NEXT_IP6_INPUT;
              else
                {
                  ethernet_header_t *h0 = (ethernet_header_t *) b0->data;
                  is0_mpls = (h0->type == clib_host_to_net_u16(ETHERNET_TYPE_MPLS_UNICAST));
	          n0 = is0_mpls ? DPDK_RX_NEXT_MPLS_INPUT : n0;
                }
	    }
	}
    }
  *next0 = n0;
}

void dpdk_rx_trace (dpdk_main_t * dm,
                    vlib_node_runtime_t * node,
                    dpdk_device_t * xd,
                    u16 queue_id,
                    u32 * buffers,
                    uword n_buffers)
{
  vlib_main_t * vm = vlib_get_main();
  u32 * b, n_left;
  u8 next0;

  n_left = n_buffers;
  b = buffers;

  while (n_left >= 1)
    {
      u32 bi0;
      vlib_buffer_t * b0;
      dpdk_rx_dma_trace_t * t0;
      struct rte_mbuf *mb;
      u8 error0;

      bi0 = b[0];
      n_left -= 1;

      b0 = vlib_get_buffer (vm, bi0);
      mb = rte_mbuf_from_vlib_buffer(b0);
      dpdk_rx_next_and_error_from_mb_flags_x1 (xd, mb, b0,
					       &next0, &error0);
      vlib_trace_buffer (vm, node, next0, b0, /* follow_chain */ 0);
      t0 = vlib_add_trace (vm, node, b0, sizeof (t0[0]));
      t0->queue_index = queue_id;
      t0->device_index = xd->device_index;
      t0->buffer_index = bi0;

      clib_memcpy (&t0->mb, mb, sizeof (t0->mb));
      clib_memcpy (&t0->buffer, b0, sizeof (b0[0]) - sizeof (b0->pre_data));
      clib_memcpy (t0->buffer.pre_data, b0->data, sizeof (t0->buffer.pre_data));

#ifdef RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS
      /*
       * Clear overloaded TX offload flags when a DPDK driver
       * is using them for RX flags (e.g. Cisco VIC Ethernet driver)
       */
      mb->ol_flags &= PKT_EXT_RX_CLR_TX_FLAGS_MASK;
#endif /* RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS */

      b += 1;
    }
}

/*
 * dpdk_efd_update_counters()
 * Update EFD (early-fast-discard) counters
 */
void dpdk_efd_update_counters (dpdk_device_t *xd,
                               u32 n_buffers,
                               u16 enabled)
{
  if (enabled & DPDK_EFD_MONITOR_ENABLED)
    {
      u64 now = clib_cpu_time_now();
      if (xd->efd_agent.last_poll_time > 0)
        {
          u64 elapsed_time = (now - xd->efd_agent.last_poll_time);
          if (elapsed_time > xd->efd_agent.max_poll_delay)
            xd->efd_agent.max_poll_delay = elapsed_time;
        }
      xd->efd_agent.last_poll_time = now;
    }
  
  xd->efd_agent.total_packet_cnt += n_buffers;
  xd->efd_agent.last_burst_sz = n_buffers;

  if (n_buffers > xd->efd_agent.max_burst_sz)
    xd->efd_agent.max_burst_sz = n_buffers;

  if (PREDICT_FALSE(n_buffers == VLIB_FRAME_SIZE))
    {
      xd->efd_agent.full_frames_cnt++;
      xd->efd_agent.consec_full_frames_cnt++;
    }
  else
    {
      xd->efd_agent.consec_full_frames_cnt = 0;
    }
}

/* is_efd_discardable()
 *   returns non zero DPDK error if packet meets early-fast-discard criteria,
 *           zero otherwise
 */
u32 is_efd_discardable (vlib_thread_main_t *tm,
                        vlib_buffer_t * b0,
                        struct rte_mbuf *mb)
{
  ethernet_header_t *eh = (ethernet_header_t *) b0->data;

  if (eh->type == clib_host_to_net_u16(ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ipv4 =
          (ip4_header_t *)&(b0->data[sizeof(ethernet_header_t)]);
      u8 pkt_prec = (ipv4->tos >> 5);
          
      return (tm->efd.ip_prec_bitmap & (1 << pkt_prec) ?
                  DPDK_ERROR_IPV4_EFD_DROP_PKTS : DPDK_ERROR_NONE);
    }
  else if (eh->type == clib_net_to_host_u16(ETHERNET_TYPE_IP6))
    {
      ip6_header_t *ipv6 =
          (ip6_header_t *)&(b0->data[sizeof(ethernet_header_t)]);
      u8 pkt_tclass =
          ((ipv6->ip_version_traffic_class_and_flow_label >> 20) & 0xff);
          
      return (tm->efd.ip_prec_bitmap & (1 << pkt_tclass) ?
                  DPDK_ERROR_IPV6_EFD_DROP_PKTS : DPDK_ERROR_NONE);
    }
  else if (eh->type == clib_net_to_host_u16(ETHERNET_TYPE_MPLS_UNICAST))
    {
      mpls_unicast_header_t *mpls =
          (mpls_unicast_header_t *)&(b0->data[sizeof(ethernet_header_t)]);
      u8 pkt_exp = ((mpls->label_exp_s_ttl >> 9) & 0x07);

      return (tm->efd.mpls_exp_bitmap & (1 << pkt_exp) ?
                  DPDK_ERROR_MPLS_EFD_DROP_PKTS : DPDK_ERROR_NONE);
    }
  else if ((eh->type == clib_net_to_host_u16(ETHERNET_TYPE_VLAN)) ||
           (eh->type == clib_net_to_host_u16(ETHERNET_TYPE_DOT1AD)))
    {
      ethernet_vlan_header_t *vlan =
          (ethernet_vlan_header_t *)&(b0->data[sizeof(ethernet_header_t)]);
      u8 pkt_cos = ((vlan->priority_cfi_and_id >> 13) & 0x07);

      return (tm->efd.vlan_cos_bitmap & (1 << pkt_cos) ?
                  DPDK_ERROR_VLAN_EFD_DROP_PKTS : DPDK_ERROR_NONE);
    }

  return DPDK_ERROR_NONE;
}

/*
 * This function is used when there are no worker threads.
 * The main thread performs IO and forwards the packets. 
 */
static inline u32 dpdk_device_input ( dpdk_main_t * dm, 
                                      dpdk_device_t * xd,
                                      vlib_node_runtime_t * node,
                                      u32 cpu_index,
                                      u16 queue_id,
                                      int use_efd)
{
  u32 n_buffers;
  u32 next_index = DPDK_RX_NEXT_ETHERNET_INPUT;
  u32 n_left_to_next, * to_next;
  u32 mb_index;
  vlib_main_t * vm = vlib_get_main();
  uword n_rx_bytes = 0;
  u32 n_trace, trace_cnt __attribute__((unused));
  vlib_buffer_free_list_t * fl;
  u8 efd_discard_burst = 0;
  u32 buffer_flags_template;
  
  if (xd->admin_up == 0)
    return 0;

  n_buffers = dpdk_rx_burst(dm, xd, queue_id);

  if (n_buffers == 0)
    {
      /* check if EFD (dpdk) is enabled */
      if (PREDICT_FALSE(use_efd && dm->efd.enabled))
        {
          /* reset a few stats */
          xd->efd_agent.last_poll_time = 0;
          xd->efd_agent.last_burst_sz = 0;
        }
      return 0;
    }

  buffer_flags_template = dm->buffer_flags_template;

  vec_reset_length (xd->d_trace_buffers);
  trace_cnt = n_trace = vlib_get_trace_count (vm, node);

  fl = vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

  /*
   * DAW-FIXME: VMXNET3 device stop/start doesn't work, 
   * therefore fake the stop in the dpdk driver by
   * silently dropping all of the incoming pkts instead of 
   * stopping the driver / hardware.
   */
  if (PREDICT_FALSE(xd->admin_up != 1))
    {
      for (mb_index = 0; mb_index < n_buffers; mb_index++)
	rte_pktmbuf_free (xd->rx_vectors[queue_id][mb_index]);
      
      return 0;
    }

  /* Check for congestion if EFD (Early-Fast-Discard) is enabled
   * in any mode (e.g. dpdk, monitor, or drop_all)
   */
  if (PREDICT_FALSE(use_efd && dm->efd.enabled))
    {
      /* update EFD counters */
      dpdk_efd_update_counters(xd, n_buffers, dm->efd.enabled);

      if (PREDICT_FALSE(dm->efd.enabled & DPDK_EFD_DROPALL_ENABLED))
        {
          /* discard all received packets */
          for (mb_index = 0; mb_index < n_buffers; mb_index++)
            rte_pktmbuf_free(xd->rx_vectors[queue_id][mb_index]);

          xd->efd_agent.discard_cnt += n_buffers;
          increment_efd_drop_counter(vm, 
                                     DPDK_ERROR_VLAN_EFD_DROP_PKTS,
                                     n_buffers);

          return 0;
        }
      
      if (PREDICT_FALSE(xd->efd_agent.consec_full_frames_cnt >=
                        dm->efd.consec_full_frames_hi_thresh))
        {
          u32 device_queue_sz = rte_eth_rx_queue_count(xd->device_index,
                                                       queue_id);
          if (device_queue_sz >= dm->efd.queue_hi_thresh)
            {
              /* dpdk device queue has reached the critical threshold */
              xd->efd_agent.congestion_cnt++;

              /* apply EFD to packets from the burst */
              efd_discard_burst = 1;
            }
        }
    }
  
  mb_index = 0;

  while (n_buffers > 0)
    {
      u32 bi0;
      u8 next0, error0;
      u32 l3_offset0;
      vlib_buffer_t * b0, * b_seg, * b_chain = 0;
      u32 cntr_type;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_buffers > 0 && n_left_to_next > 0)
        {
	  u8 nb_seg = 1;
          struct rte_mbuf *mb = xd->rx_vectors[queue_id][mb_index];
	  struct rte_mbuf *mb_seg = mb->next;

          if (PREDICT_TRUE(n_buffers > 2))
          {
              struct rte_mbuf *pfmb = xd->rx_vectors[queue_id][mb_index+2];
              vlib_buffer_t *bp = vlib_buffer_from_rte_mbuf(pfmb);
              CLIB_PREFETCH (pfmb, CLIB_CACHE_LINE_BYTES, STORE);
              CLIB_PREFETCH (bp, CLIB_CACHE_LINE_BYTES, STORE);
          }

          ASSERT(mb);

          b0 = vlib_buffer_from_rte_mbuf(mb);

          /* check whether EFD is looking for packets to discard */
          if (PREDICT_FALSE(efd_discard_burst))
            {
              vlib_thread_main_t * tm = vlib_get_thread_main();

              if (PREDICT_TRUE(cntr_type = is_efd_discardable(tm, b0, mb)))
                {
                  rte_pktmbuf_free(mb);
                  xd->efd_agent.discard_cnt++;
                  increment_efd_drop_counter(vm, 
                                             cntr_type,
                                             1);
                  n_buffers--;
                  mb_index++;
                  continue;
                }
            }

          /* Prefetch one next segment if it exists. */
          if (PREDICT_FALSE(mb->nb_segs > 1))
            {
              struct rte_mbuf *pfmb = mb->next;
              vlib_buffer_t *bp = vlib_buffer_from_rte_mbuf(pfmb);
              CLIB_PREFETCH (pfmb, CLIB_CACHE_LINE_BYTES, LOAD);
              CLIB_PREFETCH (bp, CLIB_CACHE_LINE_BYTES, STORE);
	      b_chain = b0;
            }

          vlib_buffer_init_for_free_list (b0, fl);
          b0->clone_count = 0;
          
          bi0 = vlib_get_buffer_index (vm, b0);

          to_next[0] = bi0;
          to_next++;
          n_left_to_next--;
          
	  dpdk_rx_next_and_error_from_mb_flags_x1 (xd, mb, b0,
						   &next0, &error0);
#ifdef RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS
	  /*
	   * Clear overloaded TX offload flags when a DPDK driver
	   * is using them for RX flags (e.g. Cisco VIC Ethernet driver)
	   */

	  if (PREDICT_TRUE(trace_cnt == 0))
	    mb->ol_flags &= PKT_EXT_RX_CLR_TX_FLAGS_MASK;
	  else
	    trace_cnt--;
#endif /* RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS */

	  b0->error = node->errors[error0];

	  l3_offset0 = ((next0 == DPDK_RX_NEXT_IP4_INPUT ||
			 next0 == DPDK_RX_NEXT_IP6_INPUT ||
			 next0 == DPDK_RX_NEXT_MPLS_INPUT) ? 
			sizeof (ethernet_header_t) : 0);

          b0->current_data = l3_offset0;
          /* Some drivers like fm10k receive frames with
             mb->data_off > RTE_PKTMBUF_HEADROOM */
          b0->current_data += mb->data_off - RTE_PKTMBUF_HEADROOM;
          b0->current_length = mb->data_len - l3_offset0;

          b0->flags = buffer_flags_template;

          if (VMWARE_LENGTH_BUG_WORKAROUND)
              b0->current_length -= 4;

          vnet_buffer(b0)->sw_if_index[VLIB_RX] = xd->vlib_sw_if_index;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = (u32)~0;
	  n_rx_bytes += mb->pkt_len;

          /* Process subsequent segments of multi-segment packets */
	  while ((mb->nb_segs > 1) && (nb_seg < mb->nb_segs))
	    {
	      ASSERT(mb_seg != 0);

	      b_seg = vlib_buffer_from_rte_mbuf(mb_seg);
	      vlib_buffer_init_for_free_list (b_seg, fl);
              b_seg->clone_count = 0;

	      ASSERT((b_seg->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
	      ASSERT(b_seg->current_data == 0);

              /*
               * The driver (e.g. virtio) may not put the packet data at the start
               * of the segment, so don't assume b_seg->current_data == 0 is correct.
               */
              b_seg->current_data = (mb_seg->buf_addr + mb_seg->data_off) - (void *)b_seg->data;

	      b_seg->current_length = mb_seg->data_len;
	      b0->total_length_not_including_first_buffer +=
		mb_seg->data_len;

	      b_chain->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      b_chain->next_buffer = vlib_get_buffer_index (vm, b_seg);

	      b_chain = b_seg;
	      mb_seg = mb_seg->next;
	      nb_seg++;
	    } 

          /*
           * Turn this on if you run into
           * "bad monkey" contexts, and you want to know exactly
           * which nodes they've visited... See main.c...
           */
          VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b0);

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
          if (PREDICT_FALSE (n_trace > mb_index))
            vec_add1 (xd->d_trace_buffers, bi0);
          n_buffers--;
          mb_index++;
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (PREDICT_FALSE (vec_len (xd->d_trace_buffers) > 0))
    {
      dpdk_rx_trace (dm, node, xd, queue_id, xd->d_trace_buffers,
                     vec_len (xd->d_trace_buffers));
      vlib_set_trace_count (vm, node, n_trace - vec_len (xd->d_trace_buffers));
    }
  
  vlib_increment_combined_counter 
    (vnet_get_main()->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     cpu_index, 
     xd->vlib_sw_if_index,
     mb_index, n_rx_bytes);

  dpdk_worker_t * dw = vec_elt_at_index(dm->workers, cpu_index);
  dw->aggregate_rx_packets += mb_index;

  return mb_index;
}

static inline void poll_rate_limit(dpdk_main_t * dm)
{
  /* Limit the poll rate by sleeping for N msec between polls */
  if (PREDICT_FALSE (dm->poll_sleep != 0))
  {
    struct timespec ts, tsrem;

    ts.tv_sec = 0;
    ts.tv_nsec = 1000*1000*dm->poll_sleep; /* 1ms */

    while (nanosleep(&ts, &tsrem) < 0)
      {
        ts = tsrem;
      }
  }
}

static uword
dpdk_input (vlib_main_t * vm,
	    vlib_node_runtime_t * node,
	    vlib_frame_t * f)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  uword n_rx_packets = 0;
  dpdk_device_and_queue_t * dq;
  u32 cpu_index = os_get_cpu_number();

  /*
   * Poll all devices on this cpu for input/interrupts.
   */
  vec_foreach (dq, dm->devices_by_cpu[cpu_index])
    {
      xd = vec_elt_at_index(dm->devices, dq->device);
      ASSERT(dq->queue_id == 0);
      n_rx_packets += dpdk_device_input (dm, xd, node, cpu_index, 0, 0);
    }

  poll_rate_limit(dm);

  return n_rx_packets;
}

uword
dpdk_input_rss (vlib_main_t * vm,
      vlib_node_runtime_t * node,
      vlib_frame_t * f)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  uword n_rx_packets = 0;
  dpdk_device_and_queue_t * dq;
  u32 cpu_index = os_get_cpu_number();

  /*
   * Poll all devices on this cpu for input/interrupts.
   */
  vec_foreach (dq, dm->devices_by_cpu[cpu_index])
    {
      xd = vec_elt_at_index(dm->devices, dq->device);
      n_rx_packets += dpdk_device_input (dm, xd, node, cpu_index, dq->queue_id, 0);
    }

  poll_rate_limit(dm);

  return n_rx_packets;
}

uword
dpdk_input_efd (vlib_main_t * vm,
      vlib_node_runtime_t * node,
      vlib_frame_t * f)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  uword n_rx_packets = 0;
  dpdk_device_and_queue_t * dq;
  u32 cpu_index = os_get_cpu_number();

  /*
   * Poll all devices on this cpu for input/interrupts.
   */
  vec_foreach (dq, dm->devices_by_cpu[cpu_index])
    {
      xd = vec_elt_at_index(dm->devices, dq->device);
      n_rx_packets += dpdk_device_input (dm, xd, node, cpu_index, dq->queue_id, 1);
    }

  poll_rate_limit(dm);

  return n_rx_packets;
}


VLIB_REGISTER_NODE (dpdk_input_node) = {
  .function = dpdk_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "dpdk-input",

  /* Will be enabled if/when hardware is detected. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_dpdk_rx_dma_trace,

  .n_errors = DPDK_N_ERROR,
  .error_strings = dpdk_error_strings,

  .n_next_nodes = DPDK_RX_N_NEXT,
  .next_nodes = {
    [DPDK_RX_NEXT_DROP] = "error-drop",
    [DPDK_RX_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [DPDK_RX_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [DPDK_RX_NEXT_IP6_INPUT] = "ip6-input",
    [DPDK_RX_NEXT_MPLS_INPUT] = "mpls-gre-input",
  },
};


/* handle dpdk_input_rss alternative function */
VLIB_NODE_FUNCTION_MULTIARCH_CLONE(dpdk_input)
VLIB_NODE_FUNCTION_MULTIARCH_CLONE(dpdk_input_rss)
VLIB_NODE_FUNCTION_MULTIARCH_CLONE(dpdk_input_efd)

/* this macro defines dpdk_input_rss_multiarch_select() */
CLIB_MULTIARCH_SELECT_FN(dpdk_input);
CLIB_MULTIARCH_SELECT_FN(dpdk_input_rss);
CLIB_MULTIARCH_SELECT_FN(dpdk_input_efd);

/*
 * Override the next nodes for the dpdk input nodes.
 * Must be invoked prior to VLIB_INIT_FUNCTION calls.
 */
void dpdk_set_next_node (dpdk_rx_next_t next, char *name)
{
  vlib_node_registration_t *r = &dpdk_input_node;
  vlib_node_registration_t *r_io = &dpdk_io_input_node;
  vlib_node_registration_t *r_handoff = &handoff_dispatch_node;

  switch (next)
    {
    case DPDK_RX_NEXT_IP4_INPUT:
    case DPDK_RX_NEXT_IP6_INPUT:
    case DPDK_RX_NEXT_MPLS_INPUT:
    case DPDK_RX_NEXT_ETHERNET_INPUT:
      r->next_nodes[next] = name;
      r_io->next_nodes[next] = name;
      r_handoff->next_nodes[next] = name;
      break;

    default:
      clib_warning ("%s: illegal next %d\n", __FUNCTION__, next);
      break;
    }
}

inline vlib_frame_queue_elt_t * 
vlib_get_handoff_queue_elt (u32 vlib_worker_index) 
{
  vlib_frame_queue_t *fq;
  vlib_frame_queue_elt_t *elt;
  u64 new_tail;
  
  fq = vlib_frame_queues[vlib_worker_index];
  ASSERT (fq);

  new_tail = __sync_add_and_fetch (&fq->tail, 1);

  /* Wait until a ring slot is available */
  while (new_tail >= fq->head_hint + fq->nelts)
      vlib_worker_thread_barrier_check ();

  elt = fq->elts + (new_tail & (fq->nelts-1));

  /* this would be very bad... */
  while (elt->valid) 
    ;

  elt->msg_type = VLIB_FRAME_QUEUE_ELT_DISPATCH_FRAME;
  elt->last_n_vectors = elt->n_vectors = 0;

  return elt;
}

static inline vlib_frame_queue_elt_t *
dpdk_get_handoff_queue_elt ( 
    u32 vlib_worker_index, 
    vlib_frame_queue_elt_t ** handoff_queue_elt_by_worker_index)
{
  vlib_frame_queue_elt_t *elt;

  if (handoff_queue_elt_by_worker_index [vlib_worker_index])
      return handoff_queue_elt_by_worker_index [vlib_worker_index];

  elt = vlib_get_handoff_queue_elt (vlib_worker_index);

  handoff_queue_elt_by_worker_index [vlib_worker_index] = elt;

  return elt;
}

static inline vlib_frame_queue_t *
is_vlib_handoff_queue_congested (
    u32 vlib_worker_index,
    u32 queue_hi_thresh,
    vlib_frame_queue_t ** handoff_queue_by_worker_index)
{
  vlib_frame_queue_t *fq;

  fq = handoff_queue_by_worker_index [vlib_worker_index];
  if (fq != (vlib_frame_queue_t *)(~0)) 
      return fq;
  
  fq = vlib_frame_queues[vlib_worker_index];
  ASSERT (fq);

  if (PREDICT_FALSE(fq->tail >= (fq->head_hint + queue_hi_thresh))) {
    /* a valid entry in the array will indicate the queue has reached
     * the specified threshold and is congested
     */
    handoff_queue_by_worker_index [vlib_worker_index] = fq;
    fq->enqueue_full_events++;
    return fq;
  }

  return NULL;
}

static inline u64 ipv4_get_key (ip4_header_t *ip)
{
   u64  hash_key;

   hash_key = *((u64*)(&ip->address_pair)) ^ ip->protocol;

   return hash_key;
}

static inline u64 ipv6_get_key (ip6_header_t *ip)
{
   u64  hash_key;

   hash_key = ip->src_address.as_u64[0] ^
              rotate_left(ip->src_address.as_u64[1],13) ^
              rotate_left(ip->dst_address.as_u64[0],26) ^
              rotate_left(ip->dst_address.as_u64[1],39) ^
              ip->protocol;

   return hash_key;
}


#define MPLS_BOTTOM_OF_STACK_BIT_MASK   0x00000100U
#define MPLS_LABEL_MASK                 0xFFFFF000U

static inline u64 mpls_get_key (mpls_unicast_header_t *m)
{
   u64                     hash_key;
   u8                      ip_ver;


   /* find the bottom of the MPLS label stack. */
   if (PREDICT_TRUE(m->label_exp_s_ttl & 
                    clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK))) {
       goto bottom_lbl_found;
   }
   m++;

   if (PREDICT_TRUE(m->label_exp_s_ttl & 
                    clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK))) {
       goto bottom_lbl_found;
   }
   m++;

   if (m->label_exp_s_ttl & clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK)) {
       goto bottom_lbl_found;
   }
   m++;

   if (m->label_exp_s_ttl & clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK)) {
       goto bottom_lbl_found;
   }
   m++;

   if (m->label_exp_s_ttl & clib_net_to_host_u32(MPLS_BOTTOM_OF_STACK_BIT_MASK)) {
       goto bottom_lbl_found;
   }
   
   /* the bottom label was not found - use the last label */
   hash_key = m->label_exp_s_ttl & clib_net_to_host_u32(MPLS_LABEL_MASK);

   return hash_key;
   

bottom_lbl_found:
   m++;
   ip_ver = (*((u8 *)m) >> 4);

   /* find out if it is IPV4 or IPV6 header */
   if (PREDICT_TRUE(ip_ver == 4)) {
       hash_key = ipv4_get_key((ip4_header_t *)m);
   } else if (PREDICT_TRUE(ip_ver == 6)) {
       hash_key = ipv6_get_key((ip6_header_t *)m);
   } else {
       /* use the bottom label */
       hash_key = (m-1)->label_exp_s_ttl & clib_net_to_host_u32(MPLS_LABEL_MASK);
   }

   return hash_key;

}

static inline u64 eth_get_key (ethernet_header_t *h0)
{
   u64 hash_key;


   if (PREDICT_TRUE(h0->type) == clib_host_to_net_u16(ETHERNET_TYPE_IP4)) {
       hash_key = ipv4_get_key((ip4_header_t *)(h0+1));
   } else if (h0->type == clib_host_to_net_u16(ETHERNET_TYPE_IP6)) {
       hash_key = ipv6_get_key((ip6_header_t *)(h0+1));
   } else if (h0->type == clib_host_to_net_u16(ETHERNET_TYPE_MPLS_UNICAST)) {
       hash_key = mpls_get_key((mpls_unicast_header_t *)(h0+1));
   } else if ((h0->type == clib_host_to_net_u16(ETHERNET_TYPE_VLAN)) || 
              (h0->type == clib_host_to_net_u16(ETHERNET_TYPE_DOT1AD))) {
       ethernet_vlan_header_t * outer = (ethernet_vlan_header_t *)(h0 + 1);
       
       outer = (outer->type == clib_host_to_net_u16(ETHERNET_TYPE_VLAN)) ? 
                                  outer+1 : outer;
       if (PREDICT_TRUE(outer->type) == clib_host_to_net_u16(ETHERNET_TYPE_IP4)) {
           hash_key = ipv4_get_key((ip4_header_t *)(outer+1));
       } else if (outer->type == clib_host_to_net_u16 (ETHERNET_TYPE_IP6)) {
           hash_key = ipv6_get_key((ip6_header_t *)(outer+1));
       } else if (outer->type == clib_host_to_net_u16(ETHERNET_TYPE_MPLS_UNICAST)) {
           hash_key = mpls_get_key((mpls_unicast_header_t *)(outer+1));
       }  else {
           hash_key = outer->type; 
       }
   } else {
       hash_key  = 0;
   }

   return hash_key;
}

/*
 * This function is used when dedicated IO threads feed the worker threads.
 *
 * Devices are allocated to this thread based on instances and instance_id.
 * If instances==0 then the function automatically determines the number
 * of instances of this thread, and allocates devices between them. 
 * If instances != 0, then instance_id must be in the range 0..instances-1.
 * The function allocates devices among the specified number of instances,
 * with this thread having the given instance id. This option is used for 
 * splitting devices among differently named "io"-type threads.
 */
void dpdk_io_thread (vlib_worker_thread_t * w,
                     u32 instances,
                     u32 instance_id,
                     char *worker_name,
                     dpdk_io_thread_callback_t callback)
{
  vlib_main_t * vm = vlib_get_main();
  vlib_thread_main_t * tm = vlib_get_thread_main();
  vlib_thread_registration_t * tr;
  dpdk_main_t * dm = &dpdk_main;
  char *io_name = w->registration->name;
  dpdk_device_t * xd;
  dpdk_device_t ** my_devices = 0;
  vlib_frame_queue_elt_t ** handoff_queue_elt_by_worker_index = 0;
  vlib_frame_queue_t ** congested_handoff_queue_by_worker_index = 0;
  vlib_frame_queue_elt_t * hf = 0;
  int i;
  u32 n_left_to_next_worker = 0, * to_next_worker = 0;
  u32 next_worker_index = 0;
  u32 current_worker_index = ~0;
  u32 cpu_index = os_get_cpu_number();
  u32 num_workers = 0;
  u32 num_devices = 0;
  uword * p;
  u16 queue_id = 0;
  vlib_node_runtime_t * node_trace = 0;
  u32 first_worker_index = 0;
  u32 buffer_flags_template;
  
  /* Wait until the dpdk init sequence is complete */
  while (dm->io_thread_release == 0)
    vlib_worker_thread_barrier_check();

  clib_time_init (&vm->clib_time);

  p = hash_get_mem (tm->thread_registrations_by_name, worker_name);
  ASSERT (p);
  tr = (vlib_thread_registration_t *) p[0];
  if (tr) 
    {
      num_workers = tr->count;
      first_worker_index = tr->first_index;
    }

  /* Allocate devices to this thread */
  if (instances == 0) 
    {
      /* auto-assign */
      instance_id = w->instance_id;

      p = hash_get_mem (tm->thread_registrations_by_name, io_name);
      tr = (vlib_thread_registration_t *) p[0];
      /* Otherwise, how did we get here */
      ASSERT (tr && tr->count);
      instances = tr->count;
    }
  else
    {
      /* manually assign */
      ASSERT (instance_id < instances);
    }

  vec_validate (handoff_queue_elt_by_worker_index,
                first_worker_index + num_workers - 1);

  vec_validate_init_empty (congested_handoff_queue_by_worker_index,
                           first_worker_index + num_workers - 1,
                           (vlib_frame_queue_t *)(~0));

  buffer_flags_template = dm->buffer_flags_template;

  /* And handle them... */
  while (1)
    {
      u32 n_buffers;
      u32 mb_index;
      uword n_rx_bytes = 0;
      u32 n_trace, trace_cnt __attribute__((unused));
      vlib_buffer_free_list_t * fl;
      u32 hash;
      u64 hash_key;
      u8 efd_discard_burst;

      vlib_worker_thread_barrier_check ();

      /* Invoke callback if supplied */
      if (PREDICT_FALSE(callback != NULL))
          callback(vm);

      if (PREDICT_FALSE(vec_len(dm->devices) != num_devices))
      {
        vec_reset_length(my_devices);
        vec_foreach (xd, dm->devices)
          {
            if (((xd - dm->devices) % tr->count) == instance_id)
              {
                fprintf(stderr, "i/o thread %d (cpu %d) takes port %d\n",
                        instance_id, (int) os_get_cpu_number(), (int) (xd - dm->devices));
                vec_add1 (my_devices, xd);
              }
          }
        num_devices = vec_len(dm->devices);
      }

      for (i = 0; i < vec_len (my_devices); i++)
      {
          xd = my_devices[i];

	  if (!xd->admin_up)
	    continue;

          n_buffers = dpdk_rx_burst(dm, xd, 0 /* queue_id */);

          if (n_buffers == 0)
            {
              /* check if EFD (dpdk) is enabled */
              if (PREDICT_FALSE(dm->efd.enabled))
                {
                  /* reset a few stats */
                  xd->efd_agent.last_poll_time = 0;
                  xd->efd_agent.last_burst_sz = 0;
                }
              continue;
            }

          trace_cnt = n_trace = 0;
          if (PREDICT_FALSE(vm->trace_main.trace_active_hint))
            {
              /*
               * packet tracing is triggered on the dpdk-input node for
               * ease-of-use. Re-fetch the node_runtime for dpdk-input
               * in case it has changed.
               */
              node_trace = vlib_node_get_runtime (vm, dpdk_input_node.index);

              vec_reset_length (xd->d_trace_buffers);
              trace_cnt = n_trace = vlib_get_trace_count (vm, node_trace);
            }
        
          /*
           * DAW-FIXME: VMXNET3 device stop/start doesn't work, 
           * therefore fake the stop in the dpdk driver by
           * silently dropping all of the incoming pkts instead of 
           * stopping the driver / hardware.
           */
          if (PREDICT_FALSE(xd->admin_up != 1))
            {
              for (mb_index = 0; mb_index < n_buffers; mb_index++)
                rte_pktmbuf_free (xd->rx_vectors[queue_id][mb_index]);
              continue;
            }

          /* reset EFD action for the burst */
          efd_discard_burst = 0;
          
          /* Check for congestion if EFD (Early-Fast-Discard) is enabled
           * in any mode (e.g. dpdk, monitor, or drop_all)
           */
          if (PREDICT_FALSE(dm->efd.enabled))
            {
              /* update EFD counters */
              dpdk_efd_update_counters(xd, n_buffers, dm->efd.enabled);

              if (PREDICT_FALSE(dm->efd.enabled & DPDK_EFD_DROPALL_ENABLED))
                {
                  /* drop all received packets */
                  for (mb_index = 0; mb_index < n_buffers; mb_index++)
                    rte_pktmbuf_free(xd->rx_vectors[queue_id][mb_index]);

                  xd->efd_agent.discard_cnt += n_buffers;
                  increment_efd_drop_counter(vm, 
                                             DPDK_ERROR_VLAN_EFD_DROP_PKTS,
                                             n_buffers);

                  continue;
                }

              if (PREDICT_FALSE(xd->efd_agent.consec_full_frames_cnt >=
                                dm->efd.consec_full_frames_hi_thresh))
                {
                  u32 device_queue_sz = rte_eth_rx_queue_count(xd->device_index,
                                                               queue_id);
                  if (device_queue_sz >= dm->efd.queue_hi_thresh)
                    {
                      /* dpdk device queue has reached the critical threshold */
                      xd->efd_agent.congestion_cnt++;

                      /* apply EFD to packets from the burst */
                      efd_discard_burst = 1;
                    }
                }
            }

          fl = vlib_buffer_get_free_list 
            (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
        
          mb_index = 0;

          while (n_buffers > 0)
            {
              u32 bi0;
              u8 next0, error0;
              u32 l3_offset0;
              vlib_buffer_t * b0, * b_seg, * b_chain = 0;
              ethernet_header_t * h0;
              u8 nb_seg = 1;
              struct rte_mbuf *mb = xd->rx_vectors[queue_id][mb_index];
              struct rte_mbuf *mb_seg = mb->next;
                
              if (PREDICT_TRUE(n_buffers > 1))
                {
                  struct rte_mbuf *pfmb = xd->rx_vectors[queue_id][mb_index+2];
                  vlib_buffer_t *bp = vlib_buffer_from_rte_mbuf(pfmb);
                  CLIB_PREFETCH (pfmb, CLIB_CACHE_LINE_BYTES, LOAD);
                  CLIB_PREFETCH (bp, CLIB_CACHE_LINE_BYTES, STORE);
                  CLIB_PREFETCH (bp->data, CLIB_CACHE_LINE_BYTES, LOAD);
                }
                
              b0 = vlib_buffer_from_rte_mbuf(mb);

              /* check whether EFD is looking for packets to discard */
              if (PREDICT_FALSE(efd_discard_burst))
                {
                  u32 cntr_type;
                  if (PREDICT_TRUE(cntr_type = is_efd_discardable(tm, b0, mb)))
                    {
                      rte_pktmbuf_free(mb);
                      xd->efd_agent.discard_cnt++;
                      increment_efd_drop_counter(vm, 
                                                 cntr_type,
                                                 1);

                      n_buffers--;
                      mb_index++;
                      continue;
                    }
                }
              
              /* Prefetch one next segment if it exists */
              if (PREDICT_FALSE(mb->nb_segs > 1))
                {
                  struct rte_mbuf *pfmb = mb->next;
                  vlib_buffer_t *bp = vlib_buffer_from_rte_mbuf(pfmb);
                  CLIB_PREFETCH (pfmb, CLIB_CACHE_LINE_BYTES, LOAD);
                  CLIB_PREFETCH (bp, CLIB_CACHE_LINE_BYTES, STORE);
                  b_chain = b0;
                }

              bi0 = vlib_get_buffer_index (vm, b0);
              vlib_buffer_init_for_free_list (b0, fl);
              b0->clone_count = 0;

              dpdk_rx_next_and_error_from_mb_flags_x1 (xd, mb, b0,
                                                       &next0, &error0);
#ifdef RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS
              /*
               * Clear overloaded TX offload flags when a DPDK driver
               * is using them for RX flags (e.g. Cisco VIC Ethernet driver)
               */
              if (PREDICT_TRUE(trace_cnt == 0))
                mb->ol_flags &= PKT_EXT_RX_CLR_TX_FLAGS_MASK;
              else
                trace_cnt--;
#endif /* RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS */

              if (error0)
                  clib_warning ("bi %d error %d", bi0, error0);

              b0->error = 0;

              l3_offset0 = ((next0 == DPDK_RX_NEXT_IP4_INPUT ||
                             next0 == DPDK_RX_NEXT_IP6_INPUT || 
                             next0 == DPDK_RX_NEXT_MPLS_INPUT) ? 
                            sizeof (ethernet_header_t) : 0);

              b0->current_data = l3_offset0;
              /* Some drivers like fm10k receive frames with
                 mb->data_off > RTE_PKTMBUF_HEADROOM */
              b0->current_data += mb->data_off - RTE_PKTMBUF_HEADROOM;
              b0->current_length = mb->data_len - l3_offset0;

              b0->flags = buffer_flags_template;

              if (VMWARE_LENGTH_BUG_WORKAROUND)
                  b0->current_length -= 4;
                
              vnet_buffer(b0)->sw_if_index[VLIB_RX] = xd->vlib_sw_if_index;
              vnet_buffer(b0)->sw_if_index[VLIB_TX] = (u32)~0;
              vnet_buffer(b0)->io_handoff.next_index = next0;
              n_rx_bytes += mb->pkt_len;

              /* Process subsequent segments of multi-segment packets */
              while ((mb->nb_segs > 1) && (nb_seg < mb->nb_segs))
                {
                  ASSERT(mb_seg != 0);
 
                  b_seg = vlib_buffer_from_rte_mbuf(mb_seg);
                  vlib_buffer_init_for_free_list (b_seg, fl);
                  b_seg->clone_count = 0;
 
                  ASSERT((b_seg->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
                  ASSERT(b_seg->current_data == 0);
 
                  /*
                   * The driver (e.g. virtio) may not put the packet data at the start
                   * of the segment, so don't assume b_seg->current_data == 0 is correct.
                   */
                  b_seg->current_data = (mb_seg->buf_addr + mb_seg->data_off) - (void *)b_seg->data;

                  b_seg->current_length = mb_seg->data_len;
                  b0->total_length_not_including_first_buffer +=
                    mb_seg->data_len;
 
                  b_chain->flags |= VLIB_BUFFER_NEXT_PRESENT;
                  b_chain->next_buffer = vlib_get_buffer_index (vm, b_seg);
 
                  b_chain = b_seg;
                  mb_seg = mb_seg->next;
                  nb_seg++;
                }

              /*
               * Turn this on if you run into
               * "bad monkey" contexts, and you want to know exactly
               * which nodes they've visited... See main.c...
               */
              VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b0);
 
              if (PREDICT_FALSE (n_trace > mb_index))
                vec_add1 (xd->d_trace_buffers, bi0);

              next_worker_index = first_worker_index;

              /* 
               * Force unknown traffic onto worker 0, 
               * and into ethernet-input. $$$$ add more hashes.
               */
              h0 = (ethernet_header_t *) b0->data;

              /* Compute ingress LB hash */
              hash_key = eth_get_key(h0);
              hash = (u32)clib_xxhash(hash_key);

              if (PREDICT_TRUE (is_pow2(num_workers)))
                next_worker_index += hash & (num_workers - 1);
              else
                next_worker_index += hash % num_workers;

              /* if EFD is enabled and not already discarding from dpdk,
               * check the worker ring/queue for congestion
               */
              if (PREDICT_FALSE(tm->efd.enabled && !efd_discard_burst))
                {
                  vlib_frame_queue_t *fq;

                  /* fq will be valid if the ring is congested */
                  fq = is_vlib_handoff_queue_congested(
                      next_worker_index, tm->efd.queue_hi_thresh,
                      congested_handoff_queue_by_worker_index);
                  
                  if (PREDICT_FALSE(fq != NULL))
                    {
                      u32 cntr_type;
                      if (PREDICT_TRUE(cntr_type =
                                       is_efd_discardable(tm, b0, mb)))
                        {
                          /* discard the packet */
                          fq->enqueue_efd_discards++;
                          increment_efd_drop_counter(vm, cntr_type, 1);
                          rte_pktmbuf_free(mb);
                          n_buffers--;
                          mb_index++;
                          continue;
                        }
                    }
                }
              
              if (next_worker_index != current_worker_index)
                {
                  if (hf)
                    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

                  hf = dpdk_get_handoff_queue_elt(
                           next_worker_index,
                           handoff_queue_elt_by_worker_index);
                      
                  n_left_to_next_worker = VLIB_FRAME_SIZE - hf->n_vectors;
                  to_next_worker = &hf->buffer_index[hf->n_vectors];
                  current_worker_index = next_worker_index;
                }
              
              /* enqueue to correct worker thread */
              to_next_worker[0] = bi0;
              to_next_worker++;
              n_left_to_next_worker--;

              if (n_left_to_next_worker == 0)
                {
                  hf->n_vectors = VLIB_FRAME_SIZE;
                  vlib_put_handoff_queue_elt(hf);
                  current_worker_index = ~0;
                  handoff_queue_elt_by_worker_index[next_worker_index] = 0;
                  hf = 0;
                }
                  
              n_buffers--;
              mb_index++;
            }

          if (PREDICT_FALSE (vec_len (xd->d_trace_buffers) > 0))
            {
              /* credit the trace to the trace node */
              dpdk_rx_trace (dm, node_trace, xd, queue_id, xd->d_trace_buffers,
                             vec_len (xd->d_trace_buffers));
              vlib_set_trace_count (vm, node_trace, n_trace - vec_len (xd->d_trace_buffers));
            }

          vlib_increment_combined_counter 
            (vnet_get_main()->interface_main.combined_sw_if_counters
             + VNET_INTERFACE_COUNTER_RX,
             cpu_index, 
             xd->vlib_sw_if_index,
             mb_index, n_rx_bytes);

          dpdk_worker_t * dw = vec_elt_at_index(dm->workers, cpu_index);
          dw->aggregate_rx_packets += mb_index;
        }

      if (hf)
        hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

      /* Ship frames to the worker nodes */
      for (i = 0; i < vec_len (handoff_queue_elt_by_worker_index); i++)
        {
          if (handoff_queue_elt_by_worker_index[i])
            {
              hf = handoff_queue_elt_by_worker_index[i];
              /* 
               * It works better to let the handoff node
               * rate-adapt, always ship the handoff queue element.
               */
              if (1 || hf->n_vectors == hf->last_n_vectors)
                {
                  vlib_put_handoff_queue_elt(hf);
                  handoff_queue_elt_by_worker_index[i] = 0;
                }
              else
                hf->last_n_vectors = hf->n_vectors;
            }
          congested_handoff_queue_by_worker_index[i] = (vlib_frame_queue_t *)(~0);
        }
      hf = 0;
      current_worker_index = ~0;

      vlib_increment_main_loop_counter (vm);
    }
}

/*
 * This function is used when the main thread performs IO and feeds the
 * worker threads.
 */
static uword
dpdk_io_input (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * f)
{
  dpdk_main_t * dm = &dpdk_main;
  dpdk_device_t * xd;
  vlib_thread_main_t * tm = vlib_get_thread_main();
  uword n_rx_packets = 0;
  static vlib_frame_queue_elt_t ** handoff_queue_elt_by_worker_index;
  static vlib_frame_queue_t ** congested_handoff_queue_by_worker_index = 0;
  vlib_frame_queue_elt_t * hf = 0;
  int i;
  u32 n_left_to_next_worker = 0, * to_next_worker = 0;
  u32 next_worker_index = 0;
  u32 current_worker_index = ~0;
  u32 cpu_index = os_get_cpu_number();
  static int num_workers_set;
  static u32 num_workers;
  u16 queue_id = 0;
  vlib_node_runtime_t * node_trace;
  static u32 first_worker_index;
  u32 buffer_flags_template;

  if (PREDICT_FALSE(num_workers_set == 0))
    {
      uword * p;
      vlib_thread_registration_t * tr;
      /* Only the standard vnet worker threads are supported */
      p = hash_get_mem (tm->thread_registrations_by_name, "workers");
      tr = (vlib_thread_registration_t *) p[0];
      if (tr) 
        {
          num_workers = tr->count;
          first_worker_index = tr->first_index;
        }
      num_workers_set = 1;
    }

  if (PREDICT_FALSE(handoff_queue_elt_by_worker_index == 0))
    {
      vec_validate (handoff_queue_elt_by_worker_index, tm->n_vlib_mains - 1);
      
      vec_validate_init_empty (congested_handoff_queue_by_worker_index,
                               first_worker_index + num_workers - 1,
                               (vlib_frame_queue_t *)(~0));
    }

  /* packet tracing is triggered on the dpdk-input node for ease-of-use */
  node_trace = vlib_node_get_runtime (vm, dpdk_input_node.index);

  buffer_flags_template = dm->buffer_flags_template;

  vec_foreach (xd, dm->devices)
    {
      u32 n_buffers;
      u32 mb_index;
      uword n_rx_bytes = 0;
      u32 n_trace, trace_cnt __attribute__((unused));
      vlib_buffer_free_list_t * fl;
      u32 hash;
      u64 hash_key;
      u8 efd_discard_burst = 0;

      if (!xd->admin_up)
	continue;

      n_buffers = dpdk_rx_burst(dm, xd, queue_id );

      if (n_buffers == 0)
        {
          /* check if EFD (dpdk) is enabled */
          if (PREDICT_FALSE(dm->efd.enabled))
            {
              /* reset a few stats */
              xd->efd_agent.last_poll_time = 0;
              xd->efd_agent.last_burst_sz = 0;
            }
          continue;
        }

      vec_reset_length (xd->d_trace_buffers);
      trace_cnt = n_trace = vlib_get_trace_count (vm, node_trace);
        
      /*
       * DAW-FIXME: VMXNET3 device stop/start doesn't work, 
       * therefore fake the stop in the dpdk driver by
       * silently dropping all of the incoming pkts instead of 
       * stopping the driver / hardware.
       */
      if (PREDICT_FALSE(xd->admin_up != 1))
        {
          for (mb_index = 0; mb_index < n_buffers; mb_index++)
            rte_pktmbuf_free (xd->rx_vectors[queue_id][mb_index]);
          continue;
        }

      /* Check for congestion if EFD (Early-Fast-Discard) is enabled
       * in any mode (e.g. dpdk, monitor, or drop_all)
       */
      if (PREDICT_FALSE(dm->efd.enabled))
        {
          /* update EFD counters */
          dpdk_efd_update_counters(xd, n_buffers, dm->efd.enabled);

          if (PREDICT_FALSE(dm->efd.enabled & DPDK_EFD_DROPALL_ENABLED))
            {
              /* discard all received packets */
              for (mb_index = 0; mb_index < n_buffers; mb_index++)
                rte_pktmbuf_free(xd->rx_vectors[queue_id][mb_index]);

              xd->efd_agent.discard_cnt += n_buffers;
              increment_efd_drop_counter(vm, 
                                         DPDK_ERROR_VLAN_EFD_DROP_PKTS,
                                         n_buffers);
            
              continue;
            }
          
          if (PREDICT_FALSE(xd->efd_agent.consec_full_frames_cnt >=
                            dm->efd.consec_full_frames_hi_thresh))
            {
              u32 device_queue_sz = rte_eth_rx_queue_count(xd->device_index,
                                                           queue_id);
              if (device_queue_sz >= dm->efd.queue_hi_thresh)
                {
                  /* dpdk device queue has reached the critical threshold */
                  xd->efd_agent.congestion_cnt++;

                  /* apply EFD to packets from the burst */
                  efd_discard_burst = 1;
                }
            }
        }
      
      fl = vlib_buffer_get_free_list 
        (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
          
      mb_index = 0;

      while (n_buffers > 0)
        {
          u32 bi0;
          u8 next0, error0;
          u32 l3_offset0;
          vlib_buffer_t * b0, * b_seg, * b_chain = 0;
          ethernet_header_t * h0;
          u8 nb_seg = 1;
          struct rte_mbuf *mb = xd->rx_vectors[queue_id][mb_index];
          struct rte_mbuf *mb_seg = mb->next;

          if (PREDICT_TRUE(n_buffers > 1))
            {
              struct rte_mbuf *pfmb = xd->rx_vectors[queue_id][mb_index+2];
              vlib_buffer_t *bp = vlib_buffer_from_rte_mbuf(pfmb);
              CLIB_PREFETCH (pfmb, CLIB_CACHE_LINE_BYTES, LOAD);
              CLIB_PREFETCH (bp, CLIB_CACHE_LINE_BYTES, STORE);
              CLIB_PREFETCH (bp->data, CLIB_CACHE_LINE_BYTES, LOAD);
            }

          b0 = vlib_buffer_from_rte_mbuf(mb);

          /* check whether EFD is looking for packets to discard */
          if (PREDICT_FALSE(efd_discard_burst))
            {
              u32 cntr_type;
              if (PREDICT_TRUE(cntr_type = is_efd_discardable(tm, b0, mb)))
                {
                  rte_pktmbuf_free(mb);
                  xd->efd_agent.discard_cnt++;
                  increment_efd_drop_counter(vm, 
                                             cntr_type,
                                             1);

                  n_buffers--;
                  mb_index++;
                  continue;
                }
            }

          /* Prefetch one next segment if it exists */
          if (PREDICT_FALSE(mb->nb_segs > 1))
            {
              struct rte_mbuf *pfmb = mb->next;
              vlib_buffer_t *bp = vlib_buffer_from_rte_mbuf(pfmb);
              CLIB_PREFETCH (pfmb, CLIB_CACHE_LINE_BYTES, LOAD);
              CLIB_PREFETCH (bp, CLIB_CACHE_LINE_BYTES, STORE);
              b_chain = b0;
            }

          bi0 = vlib_get_buffer_index (vm, b0);
          vlib_buffer_init_for_free_list (b0, fl);
          b0->clone_count = 0;

          dpdk_rx_next_and_error_from_mb_flags_x1 (xd, mb, b0,
                                                   &next0, &error0);
#ifdef RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS
          /*
           * Clear overloaded TX offload flags when a DPDK driver
           * is using them for RX flags (e.g. Cisco VIC Ethernet driver)
           */
          if (PREDICT_TRUE(trace_cnt == 0))
            mb->ol_flags &= PKT_EXT_RX_CLR_TX_FLAGS_MASK;
          else
            trace_cnt--;
#endif /* RTE_LIBRTE_MBUF_EXT_RX_OLFLAGS */

          if (error0)
            clib_warning ("bi %d error %d", bi0, error0);

          b0->error = 0;

          l3_offset0 = ((next0 == DPDK_RX_NEXT_IP4_INPUT ||
                         next0 == DPDK_RX_NEXT_IP6_INPUT || 
                         next0 == DPDK_RX_NEXT_MPLS_INPUT) ? 
                        sizeof (ethernet_header_t) : 0);

          b0->current_data = l3_offset0;
          b0->current_length = mb->data_len - l3_offset0;

          b0->flags = buffer_flags_template;
                
          if (VMWARE_LENGTH_BUG_WORKAROUND)
              b0->current_length -= 4;

          vnet_buffer(b0)->sw_if_index[VLIB_RX] = xd->vlib_sw_if_index;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = (u32)~0;
          vnet_buffer(b0)->io_handoff.next_index = next0;
          n_rx_bytes += mb->pkt_len;

          /* Process subsequent segments of multi-segment packets */
          while ((mb->nb_segs > 1) && (nb_seg < mb->nb_segs))
            {
              ASSERT(mb_seg != 0);
 
              b_seg = vlib_buffer_from_rte_mbuf(mb_seg);
              vlib_buffer_init_for_free_list (b_seg, fl);
              b_seg->clone_count = 0;
 
              ASSERT((b_seg->flags & VLIB_BUFFER_NEXT_PRESENT) == 0);
              ASSERT(b_seg->current_data == 0);
 
              /*
               * The driver (e.g. virtio) may not put the packet data at the start
               * of the segment, so don't assume b_seg->current_data == 0 is correct.
               */
              b_seg->current_data = (mb_seg->buf_addr + mb_seg->data_off) - (void *)b_seg->data;

              b_seg->current_length = mb_seg->data_len;
              b0->total_length_not_including_first_buffer +=
                mb_seg->data_len;
 
              b_chain->flags |= VLIB_BUFFER_NEXT_PRESENT;
              b_chain->next_buffer = vlib_get_buffer_index (vm, b_seg);
 
              b_chain = b_seg;
              mb_seg = mb_seg->next;
              nb_seg++;
            }
 
          /*
           * Turn this on if you run into
           * "bad monkey" contexts, and you want to know exactly
           * which nodes they've visited... See main.c...
           */
          VLIB_BUFFER_TRACE_TRAJECTORY_INIT(b0);
 
          if (PREDICT_FALSE (n_trace > mb_index))
            vec_add1 (xd->d_trace_buffers, bi0);

          next_worker_index = first_worker_index;

          /* 
           * Force unknown traffic onto worker 0, 
           * and into ethernet-input. $$$$ add more hashes.
           */
          h0 = (ethernet_header_t *) b0->data;

          /* Compute ingress LB hash */
          hash_key = eth_get_key(h0);
          hash = (u32)clib_xxhash(hash_key);

          if (PREDICT_TRUE (is_pow2(num_workers)))
            next_worker_index += hash & (num_workers - 1);
          else
            next_worker_index += hash % num_workers;

          /* if EFD is enabled and not already discarding from dpdk,
           * check the worker ring/queue for congestion
           */
          if (PREDICT_FALSE(tm->efd.enabled && !efd_discard_burst))
            {
              vlib_frame_queue_t *fq;

              /* fq will be valid if the ring is congested */
              fq = is_vlib_handoff_queue_congested(
                  next_worker_index, tm->efd.queue_hi_thresh,
                  congested_handoff_queue_by_worker_index);
              
              if (PREDICT_FALSE(fq != NULL))
                {
                  u32 cntr_type;
                  if (PREDICT_TRUE(cntr_type =
                                   is_efd_discardable(tm, b0, mb)))
                    {
                      /* discard the packet */
                      fq->enqueue_efd_discards++;
                      increment_efd_drop_counter(vm, cntr_type, 1);
                      rte_pktmbuf_free(mb);
                      n_buffers--;
                      mb_index++;
                      continue;
                    }
                }
            }
          
          if (next_worker_index != current_worker_index)
            {
              if (hf)
                hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

              hf = dpdk_get_handoff_queue_elt(
                     next_worker_index,
                     handoff_queue_elt_by_worker_index);

              n_left_to_next_worker = VLIB_FRAME_SIZE - hf->n_vectors;
              to_next_worker = &hf->buffer_index[hf->n_vectors];
              current_worker_index = next_worker_index;
            }
          
          /* enqueue to correct worker thread */
          to_next_worker[0] = bi0;
          to_next_worker++;
          n_left_to_next_worker--;

          if (n_left_to_next_worker == 0)
            {
              hf->n_vectors = VLIB_FRAME_SIZE;
              vlib_put_handoff_queue_elt(hf);
              current_worker_index = ~0;
              handoff_queue_elt_by_worker_index[next_worker_index] = 0;
              hf = 0;
            }
          
          n_buffers--;
          mb_index++;
        }

      if (PREDICT_FALSE (vec_len (xd->d_trace_buffers) > 0))
        {
          /* credit the trace to the trace node */
          dpdk_rx_trace (dm, node_trace, xd, queue_id, xd->d_trace_buffers,
                         vec_len (xd->d_trace_buffers));
          vlib_set_trace_count (vm, node_trace, n_trace - vec_len (xd->d_trace_buffers));
        }

      vlib_increment_combined_counter 
        (vnet_get_main()->interface_main.combined_sw_if_counters
         + VNET_INTERFACE_COUNTER_RX,
         cpu_index, 
         xd->vlib_sw_if_index,
         mb_index, n_rx_bytes);

      dpdk_worker_t * dw = vec_elt_at_index(dm->workers, cpu_index);
      dw->aggregate_rx_packets += mb_index;
      n_rx_packets += mb_index;
    }

  if (hf)
    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;
  
  /* Ship frames to the worker nodes */
  for (i = 0; i < vec_len (handoff_queue_elt_by_worker_index); i++)
    {
      if (handoff_queue_elt_by_worker_index[i])
        {
          hf = handoff_queue_elt_by_worker_index[i];
          /* 
           * It works better to let the handoff node
           * rate-adapt, always ship the handoff queue element.
           */
          if (1 || hf->n_vectors == hf->last_n_vectors)
            {
              vlib_put_handoff_queue_elt(hf);
              handoff_queue_elt_by_worker_index[i] = 0;
            }
          else
            hf->last_n_vectors = hf->n_vectors;
        }
      congested_handoff_queue_by_worker_index[i] = (vlib_frame_queue_t *)(~0);
    }
  hf = 0;
  current_worker_index = ~0;
  return n_rx_packets;
}

VLIB_REGISTER_NODE (dpdk_io_input_node) = {
  .function = dpdk_io_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "dpdk-io-input",

  /* Will be enabled if/when hardware is detected. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_dpdk_rx_dma_trace,

  .n_errors = DPDK_N_ERROR,
  .error_strings = dpdk_error_strings,

  .n_next_nodes = DPDK_RX_N_NEXT,
  .next_nodes = {
    [DPDK_RX_NEXT_DROP] = "error-drop",
    [DPDK_RX_NEXT_ETHERNET_INPUT] = "ethernet-input",
    [DPDK_RX_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [DPDK_RX_NEXT_IP6_INPUT] = "ip6-input",
    [DPDK_RX_NEXT_MPLS_INPUT] = "mpls-gre-input",
  },
};

/*
 * set_efd_bitmap()
 * Based on the operation type, set lower/upper bits for the given index value
 */
void
set_efd_bitmap (u8 *bitmap, u32 value, u32 op)
{
    int ix;

    *bitmap = 0;
    for (ix = 0; ix < 8; ix++) {
        if (((op == EFD_OPERATION_LESS_THAN) && (ix < value)) ||
            ((op == EFD_OPERATION_GREATER_OR_EQUAL) && (ix >= value))){
            (*bitmap) |= (1 << ix);
        }
    }
}

void
efd_config (u32 enabled, 
            u32 ip_prec,  u32 ip_op,
            u32 mpls_exp, u32 mpls_op,
            u32 vlan_cos, u32 vlan_op)
{
   vlib_thread_main_t * tm = vlib_get_thread_main();
   dpdk_main_t * dm = &dpdk_main;

   if (enabled) {
       tm->efd.enabled |= VLIB_EFD_DISCARD_ENABLED;
       dm->efd.enabled |= DPDK_EFD_DISCARD_ENABLED;
   } else {
       tm->efd.enabled &= ~VLIB_EFD_DISCARD_ENABLED;
       dm->efd.enabled &= ~DPDK_EFD_DISCARD_ENABLED;
   }

   set_efd_bitmap(&tm->efd.ip_prec_bitmap, ip_prec, ip_op);
   set_efd_bitmap(&tm->efd.mpls_exp_bitmap, mpls_exp, mpls_op);
   set_efd_bitmap(&tm->efd.vlan_cos_bitmap, vlan_cos, vlan_op);

}
