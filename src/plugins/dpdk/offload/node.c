#include <vnet/vnet.h>
#include <vnet/devices/devices.h>

#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan/vxlan.h>

typedef struct {
  u32 next_index;
  u32 tunnel_index;
  u32 error;
  u32 vni;
} vxlan_offload_trace_t;

typedef struct {
  dpdk_rx_dma_trace_t dpdk;
  vxlan_offload_trace_t vxlan;
} dpdk_vxlan_trace_t;

static u8 * format_vxlan_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  vxlan_offload_trace_t * t = va_arg (*args, vxlan_offload_trace_t *);

  if (t->tunnel_index != ~0)
    {
      s = format (s, "VXLAN offload decap from vxlan_tunnel%d vni %d next %d error %d",
                  t->tunnel_index, t->vni, t->next_index, t->error);
    }
  else
    {
      s = format (s, "VXLAN offload decap error - tunnel for vni %d does not exist", 
		  t->vni);
    }
  return s;
}

static u8 * format_dpdk_vxlan_rx_trace (u8 * s, va_list * args)
{
  vlib_main_t * vm = va_arg (*args, vlib_main_t *);
  vlib_node_t * node = va_arg (*args, vlib_node_t *);
  dpdk_vxlan_trace_t * t = va_arg (*args, dpdk_vxlan_trace_t *);

  s = format(s, "%U\n %U", format_dpdk_rx_dma_trace, vm, node, &t->dpdk,
      format_vxlan_rx_trace, vm, node, &t->vxlan);
  return s;
}

#define foreach_vxlan_offload_input_next        \
_(DROP, "error-drop")                           \
_(L2_INPUT, "l2-input")

typedef enum
{
#define _(s,n) DPDK_VXLAN_OFFLOAD_NEXT_##s,
  foreach_vxlan_offload_input_next
#undef _
  DPDK_VXLAN_OFFLOAD_N_NEXT,
} dpdk_offload_input_next_t;

always_inline void
dpdk_rx_error_from_mb (struct rte_mbuf *mb, u32 * next, u8 * error)
{
  if (mb->ol_flags & PKT_RX_IP_CKSUM_BAD)
    {
      *error = DPDK_ERROR_IP_CHECKSUM_ERROR;
      *next = DPDK_VXLAN_OFFLOAD_NEXT_DROP;
    }
}

static_always_inline u8
dpdk_validate_udp_csum (vlib_main_t * vm, vlib_buffer_t *b)
{
  enum {
    ip_offset = sizeof(ip4_header_t) + sizeof(udp_header_t) + sizeof(vxlan_header_t)
  };
  /* Don't verify UDP checksum for packets with explicit zero checksum. */
  u32 flags = b->flags;

  /* Verify UDP checksum */
  if ((flags & VNET_BUFFER_F_L4_CHECKSUM_COMPUTED) == 0)
  {
    vlib_buffer_advance (b, -ip_offset);
    flags = ip4_tcp_udp_validate_checksum (vm, b);
    vlib_buffer_advance (b, ip_offset);
  }

  return (flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0;
}

static_always_inline u8
dpdk_check_udp_csum (vlib_main_t * vm, vlib_buffer_t *b)
{
  enum {
    udp_offset = sizeof(udp_header_t) + sizeof(vxlan_header_t)
  };

  udp_header_t * udp = vlib_buffer_get_current(b) - udp_offset;
  /* Don't verify UDP checksum for packets with explicit zero checksum. */
  u8 good_csum = (b->flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT) != 0 ||
    udp->checksum == 0;

  return !good_csum;
}

static_always_inline u8
dpdk_check_ip_udp_len (vlib_buffer_t *b)
{
  ip4_vxlan_header_t * hdr = vlib_buffer_get_current(b) - sizeof *hdr;
  u16 ip_len = clib_net_to_host_u16 (hdr->ip4.length);
  u16 udp_len = clib_net_to_host_u16 (hdr->udp.length);
  return udp_len > ip_len;
}

static_always_inline u16
dpdk_vxlan_buf_setup(vlib_buffer_t *b, struct rte_mbuf *mb)
{
  enum {
    vxlan_offset = sizeof(ethernet_header_t) + sizeof(ip4_header_t) + sizeof(udp_header_t) +
      sizeof(vxlan_header_t)
  };

  b->current_data = mb->data_off + vxlan_offset - RTE_PKTMBUF_HEADROOM;
  b->current_length = mb->data_len - vxlan_offset;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = mb->hash.fdir.hi;
  vnet_update_l2_len (b);
  return b->current_length;
}

static void
dpdk_vxlan_offload_rx_trace (vxlan_offload_trace_t * v, vlib_buffer_t * b, u32 next, u32 error)
{
  vxlan_main_t * vxm = &vxlan_main;

  v->next_index = next;
  v->error = error;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  v->tunnel_index = next == DPDK_VXLAN_OFFLOAD_NEXT_L2_INPUT ?
    vxm->tunnel_index_by_sw_if_index[sw_if_index] : ~0;
  vxlan_header_t * vxlan = vlib_buffer_get_current (b) - sizeof *vxlan;
  v->vni = vnet_get_vni (vxlan);
}

static void
dpdk_vxlan_rx_trace (dpdk_main_t * dm,
	       vlib_node_runtime_t * node,
	       dpdk_device_t * xd,
	       u16 queue_id, u32 bi, u32 next, u32 error)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t * b = vlib_get_buffer (vm, bi);
  struct rte_mbuf * mb = rte_mbuf_from_vlib_buffer (b);

  vlib_trace_buffer (vm, node, next, b, /* follow_chain */ 0);

  dpdk_vxlan_trace_t * t = vlib_add_trace (vm, node, b, sizeof *t);
  dpdk_rx_dma_trace_t * d = &t->dpdk;
  d->queue_index = queue_id;
  d->device_index = xd->device_index;
  d->buffer_index = bi;
  d->mb = *mb;

  clib_memcpy (&d->buffer, b, sizeof *b - sizeof b->pre_data);
  clib_memcpy (&d->buffer.pre_data, b->data, sizeof d->buffer.pre_data);
  clib_memcpy (&d->data, mb->buf_addr + mb->data_off, sizeof d->data);

  dpdk_vxlan_offload_rx_trace (&t->vxlan, b, next, error);
}

static_always_inline u32
dpdk_vxlan_input (dpdk_main_t * dm, dpdk_device_t * xd,
		  vlib_node_runtime_t * node, u32 thread_index, u16 queue_id, u32 n_trace)
{
  vnet_interface_main_t * im = &vnet_main.interface_main;
  vlib_combined_counter_main_t * rx_counter[DPDK_VXLAN_OFFLOAD_N_NEXT] = {
    [DPDK_VXLAN_OFFLOAD_NEXT_DROP] = im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_DROP,
    [DPDK_VXLAN_OFFLOAD_NEXT_L2_INPUT] = im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
  };
  u32 n_buffers = dpdk_rx_burst (dm, xd, queue_id);
  if (n_buffers == 0)
      return 0;

  vlib_main_t *vm = vlib_get_main ();
  u32 next_index = DPDK_VXLAN_OFFLOAD_NEXT_L2_INPUT;
#if 0
  //only used by multiseq pkts
  vlib_buffer_free_list_t * fl =
    vlib_buffer_get_free_list (vm, VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);
#endif

  vlib_buffer_t *bt = vec_elt_at_index (dm->buffer_templates, thread_index);
  /* Update buffer template */
  bt->error = node->errors[DPDK_ERROR_NONE];
  /* as DPDK is allocating empty buffers from mempool provided before interface
     start for each queue, it is safe to store this in the template */
  bt->buffer_pool_index = xd->buffer_pool_for_queue[queue_id];

  u32 mb_index = 0;
  uword n_rx_bytes = 0;
  while (n_buffers > 0)
  {
    u32 n_left_to_next, *to_next;

    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_buffers >= 4 && n_left_to_next >= 4)
    {
      struct rte_mbuf *mb0, *mb1, *mb2, *mb3;

      mb0 = xd->rx_vectors[queue_id][mb_index];
      mb1 = xd->rx_vectors[queue_id][mb_index + 1];
      mb2 = xd->rx_vectors[queue_id][mb_index + 2];
      mb3 = xd->rx_vectors[queue_id][mb_index + 3];
      mb_index += 4;

      ASSERT (mb0);
      ASSERT (mb1);
      ASSERT (mb2);
      ASSERT (mb3);

      vlib_buffer_t *b0, *b1, *b2, *b3;
      b0 = vlib_buffer_from_rte_mbuf (mb0);
      b1 = vlib_buffer_from_rte_mbuf (mb1);
      b2 = vlib_buffer_from_rte_mbuf (mb2);
      b3 = vlib_buffer_from_rte_mbuf (mb3);

      clib_memcpy64_x4 (b0, b1, b2, b3, bt);

      u32 bi0, bi1, bi2, bi3;
      bi0 = vlib_get_buffer_index (vm, b0);
      bi1 = vlib_get_buffer_index (vm, b1);
      bi2 = vlib_get_buffer_index (vm, b2);
      bi3 = vlib_get_buffer_index (vm, b3);

      to_next[0] = bi0;
      to_next[1] = bi1;
      to_next[2] = bi2;
      to_next[3] = bi3;

      to_next += 4;
      n_left_to_next -= 4;

      n_rx_bytes += mb0->pkt_len + mb1->pkt_len + mb2->pkt_len + mb3->pkt_len;
      u16 len0 = dpdk_vxlan_buf_setup (b0, mb0);
      u16 len1 = dpdk_vxlan_buf_setup (b1, mb1);
      u16 len2 = dpdk_vxlan_buf_setup (b2, mb2);
      u16 len3 = dpdk_vxlan_buf_setup (b3, mb3);

      u32 next0, next1, next2, next3;
      next0 = next1 = next2 = next3 = next_index;

      u8 error0, error1, error2, error3;
      error0 = error1 = error2 = error3 = DPDK_ERROR_NONE;

      u8 udp_err0 = dpdk_check_ip_udp_len (b0);
      u8 udp_err1 = dpdk_check_ip_udp_len (b1);
      u8 udp_err2 = dpdk_check_ip_udp_len (b2);
      u8 udp_err3 = dpdk_check_ip_udp_len (b3);
      u8 udp_err = udp_err0 | udp_err1 | udp_err2 | udp_err3;

      u8 csum_err0 = dpdk_check_udp_csum (vm, b0);
      u8 csum_err1 = dpdk_check_udp_csum (vm, b1);
      u8 csum_err2 = dpdk_check_udp_csum (vm, b2);
      u8 csum_err3 = dpdk_check_udp_csum (vm, b3);
      u8 csum_err = csum_err0 | csum_err1 | csum_err2 | csum_err3;

      u64 or_ol_flags = (mb0->ol_flags | mb1->ol_flags |
          mb2->ol_flags | mb3->ol_flags);

      if (PREDICT_FALSE ((or_ol_flags & PKT_RX_IP_CKSUM_BAD) || csum_err ||  udp_err))
        {
          if (udp_err0)
            next0 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error0 = DPDK_ERROR_IP_CHECKSUM_ERROR;
          if (udp_err1)
            next1 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error1 = DPDK_ERROR_IP_CHECKSUM_ERROR;
          if (udp_err2)
            next2 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error2 = DPDK_ERROR_IP_CHECKSUM_ERROR;
          if (udp_err3)
            next3 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error3 = DPDK_ERROR_IP_CHECKSUM_ERROR;

          if (csum_err0 && dpdk_validate_udp_csum (vm, b0))
            next0 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error0 = DPDK_ERROR_IP_CHECKSUM_ERROR;
          if (csum_err1 && dpdk_validate_udp_csum (vm, b1))
            next1 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error1 = DPDK_ERROR_IP_CHECKSUM_ERROR;
          if (csum_err2 && dpdk_validate_udp_csum (vm, b2))
            next2 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error2 = DPDK_ERROR_IP_CHECKSUM_ERROR;
          if (csum_err3 && dpdk_validate_udp_csum (vm, b3))
            next3 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error3 = DPDK_ERROR_IP_CHECKSUM_ERROR;

          dpdk_rx_error_from_mb (mb0, &next0, &error0);
          dpdk_rx_error_from_mb (mb1, &next1, &error1);
          dpdk_rx_error_from_mb (mb2, &next2, &error2);
          dpdk_rx_error_from_mb (mb3, &next3, &error3);

          b0->error = node->errors[error0];
          b1->error = node->errors[error1];
          b2->error = node->errors[error2];
          b3->error = node->errors[error3];
        }

      u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      u32 sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
      u32 sw_if_index2 = vnet_buffer (b2)->sw_if_index[VLIB_RX];
      u32 sw_if_index3 = vnet_buffer (b3)->sw_if_index[VLIB_RX];

      vlib_increment_combined_counter (rx_counter[next0], thread_index, sw_if_index0, 1, len0);
      vlib_increment_combined_counter (rx_counter[next1], thread_index, sw_if_index1, 1, len1);
      vlib_increment_combined_counter (rx_counter[next2], thread_index, sw_if_index2, 1, len2);
      vlib_increment_combined_counter (rx_counter[next3], thread_index, sw_if_index3, 1, len3);

      switch (n_trace)
        {
          default: /* fallthrough */
                  dpdk_vxlan_rx_trace (dm, node, xd, queue_id, bi3, next3, error3);
                  n_trace--;
          case 3: /* fallthrough */
                  dpdk_vxlan_rx_trace (dm, node, xd, queue_id, bi2, next2, error2);
                  n_trace--;
          case 2: /* fallthrough */
                  dpdk_vxlan_rx_trace (dm, node, xd, queue_id, bi1, next1, error1);
                  n_trace--;
          case 1: /* fallthrough */
                  dpdk_vxlan_rx_trace (dm, node, xd, queue_id, bi0, next0, error0);
                  n_trace--;
          case 0: break;
        }

      vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
          to_next, n_left_to_next,
          bi0, bi1, bi2, bi3,
          next0, next1, next2, next3);
      n_buffers -= 4;
    }

    while (n_buffers > 0 && n_left_to_next > 0)
    {
      struct rte_mbuf *mb0 = xd->rx_vectors[queue_id][mb_index];
      mb_index++;
      ASSERT (mb0);
      vlib_buffer_t *b0 = vlib_buffer_from_rte_mbuf (mb0);

      clib_memcpy (b0, bt, CLIB_CACHE_LINE_BYTES);

      u32 bi0 = vlib_get_buffer_index (vm, b0);
      to_next[0] = bi0;
      to_next++;
      n_left_to_next--;

      n_rx_bytes += mb0->pkt_len;
      u16 len0 = dpdk_vxlan_buf_setup (b0, mb0);
      u32 next0 = next_index;
      u8 error0 = DPDK_ERROR_NONE;

      if (dpdk_check_ip_udp_len (b0) || dpdk_check_udp_csum (vm, b0))
        next0 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error0 = DPDK_ERROR_IP_CHECKSUM_ERROR;
      dpdk_rx_error_from_mb (mb0, &next0, &error0);
      b0->error = node->errors[error0];
      u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      vlib_increment_combined_counter (rx_counter[next0], thread_index, sw_if_index0, 1, len0);

      if (n_trace != 0)
        {
          dpdk_vxlan_rx_trace (dm, node, xd, queue_id, bi0, next0, error0);
          n_trace--;
        }

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
          to_next, n_left_to_next,
          bi0, next0);
      n_buffers--;
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  vlib_increment_combined_counter
    (vnet_get_main ()->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
     thread_index, xd->vlib_sw_if_index, mb_index, n_rx_bytes);

  vnet_device_increment_rx_packets (thread_index, mb_index);

  return mb_index;
}

static inline void
poll_rate_limit (dpdk_main_t * dm)
{
  /* Limit the poll rate by sleeping for N msec between polls */
  if (PREDICT_FALSE (dm->poll_sleep_usec != 0))
    {
      struct timespec ts, tsrem;

      ts.tv_sec = 0;
      ts.tv_nsec = 1000 * dm->poll_sleep_usec;

      while (nanosleep (&ts, &tsrem) < 0)
	{
	  ts = tsrem;
	}
    }
}

uword
CLIB_MULTIARCH_FN (dpdk_vxlan_offload_input) (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * f)
{
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  uword n_rx_packets = 0;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;
  u32 thread_index = node->thread_index;

  /*
   * Poll all devices on this cpu for input/interrupts.
   */
  /* *INDENT-OFF* */
  foreach_device_and_queue (dq, rt->devices_and_queues)
    {
      xd = vec_elt_at_index(dm->devices, dq->dev_instance);
      if ((xd->flags & DPDK_DEVICE_FLAG_ADMIN_UP) == 0)
        continue;
      if (PREDICT_FALSE (xd->flags & DPDK_DEVICE_FLAG_BOND_SLAVE))
	continue; 	/* Do not poll slave to a bonded interface */
      
      u32 n_trace = vlib_get_trace_count (vm, node);
      if (n_trace != 0)
        {
          uword n_rx_traced = dpdk_vxlan_input (dm, xd, node, thread_index, dq->queue_id, n_trace);
          n_rx_packets += n_rx_traced;
          n_rx_traced = clib_min (n_rx_traced, n_trace);
          vlib_set_trace_count (vm, node, n_trace - n_rx_traced);
        }
      else
        n_rx_packets += dpdk_vxlan_input (dm, xd, node, thread_index, dq->queue_id, 0);
    }
  /* *INDENT-ON* */

  poll_rate_limit (dm);

  return n_rx_packets;
}

uword
CLIB_MULTIARCH_FN (dpdk_vxlan_passthru_input) (vlib_main_t * vm,
					      vlib_node_runtime_t * node,
					      vlib_frame_t * f)
{
  enum {
    vxlan_payload_offset =
      sizeof(ethernet_header_t) + sizeof(ip4_header_t) + sizeof(udp_header_t) + sizeof(vxlan_header_t)
  };
  vnet_interface_main_t * im = &vnet_main.interface_main;
  vlib_combined_counter_main_t * rx_counter[DPDK_VXLAN_OFFLOAD_N_NEXT] = {
    [DPDK_VXLAN_OFFLOAD_NEXT_DROP] = im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_DROP,
    [DPDK_VXLAN_OFFLOAD_NEXT_L2_INPUT] = im->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
  };
  u32 thread_index = vlib_get_thread_index();

  u32 next_index = DPDK_VXLAN_OFFLOAD_NEXT_L2_INPUT;

  u32 * from = vlib_frame_vector_args (f);
  u32 n_left_from = f->n_vectors;

  while (n_left_from > 0)
  {
    u32 n_left_to_next, *to_next;

    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from >= 4 && n_left_to_next >= 4)
    {
      u32 bi0, bi1, bi2, bi3;
      bi0 = from[0];
      bi1 = from[1];
      bi2 = from[2];
      bi3 = from[3];
      from += 4;
      n_left_from -= 4;

      to_next[0] = bi0;
      to_next[1] = bi1;
      to_next[2] = bi2;
      to_next[3] = bi3;
      to_next += 4;
      n_left_to_next -= 4;

      vlib_buffer_t * b0, * b1, * b2, * b3;
      b0 = vlib_get_buffer (vm, bi0);
      b1 = vlib_get_buffer (vm, bi1);
      b2 = vlib_get_buffer (vm, bi2);
      b3 = vlib_get_buffer (vm, bi3);

      vlib_buffer_advance (b0, vxlan_payload_offset);
      vlib_buffer_advance (b1, vxlan_payload_offset);
      vlib_buffer_advance (b2, vxlan_payload_offset);
      vlib_buffer_advance (b3, vxlan_payload_offset);

      u32 next0, next1, next2, next3;
      next0 = next1 = next2 = next3 = next_index;
      u8 error0, error1, error2, error3;
      error0 = error1 = error2 = error3 = DPDK_ERROR_NONE;

      u8 udp_err0 = dpdk_check_ip_udp_len (b0);
      u8 udp_err1 = dpdk_check_ip_udp_len (b1);
      u8 udp_err2 = dpdk_check_ip_udp_len (b2);
      u8 udp_err3 = dpdk_check_ip_udp_len (b3);
      u8 udp_err = udp_err0 | udp_err1 | udp_err2 | udp_err3;

      if (PREDICT_FALSE (udp_err))
        {
          if (udp_err0)
            next0 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error0 = DPDK_ERROR_IP_CHECKSUM_ERROR;
          if (udp_err1)
            next1 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error1 = DPDK_ERROR_IP_CHECKSUM_ERROR;
          if (udp_err2)
            next2 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error2 = DPDK_ERROR_IP_CHECKSUM_ERROR;
          if (udp_err3)
            next3 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error3 = DPDK_ERROR_IP_CHECKSUM_ERROR;

          b0->error = node->errors[error0];
          b1->error = node->errors[error1];
          b2->error = node->errors[error2];
          b3->error = node->errors[error3];
        }

      vnet_update_l2_len (b0);
      vnet_update_l2_len (b1);
      vnet_update_l2_len (b2);
      vnet_update_l2_len (b3);

#if 0
      u32 len0 = vlib_buffer_length_in_chain (vm, b0);
      u32 len1 = vlib_buffer_length_in_chain (vm, b1);
      u32 len2 = vlib_buffer_length_in_chain (vm, b2);
      u32 len3 = vlib_buffer_length_in_chain (vm, b3);
#else
      u16 len0 = b0->current_length;
      u16 len1 = b1->current_length;
      u16 len2 = b2->current_length;
      u16 len3 = b3->current_length;
#endif

      u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      u32 sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
      u32 sw_if_index2 = vnet_buffer (b2)->sw_if_index[VLIB_RX];
      u32 sw_if_index3 = vnet_buffer (b3)->sw_if_index[VLIB_RX];

      vlib_increment_combined_counter (rx_counter[next0], thread_index, sw_if_index0, 1, len0);
      vlib_increment_combined_counter (rx_counter[next1], thread_index, sw_if_index1, 1, len1);
      vlib_increment_combined_counter (rx_counter[next2], thread_index, sw_if_index2, 1, len2);
      vlib_increment_combined_counter (rx_counter[next3], thread_index, sw_if_index3, 1, len3);

      u32 or_flags = b0->flags | b1->flags | b2->flags | b3->flags;
      if (PREDICT_FALSE(or_flags & VLIB_BUFFER_IS_TRACED))
      {
        if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
        {
          vxlan_offload_trace_t *tr 
            = vlib_add_trace (vm, node, b0, sizeof (*tr));
          dpdk_vxlan_offload_rx_trace (tr, b0, next0, error0);
        }
        if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED)) 
        {
          vxlan_offload_trace_t *tr 
            = vlib_add_trace (vm, node, b1, sizeof (*tr));
          dpdk_vxlan_offload_rx_trace (tr, b1, next1, error1);
        }
        if (PREDICT_FALSE(b2->flags & VLIB_BUFFER_IS_TRACED)) 
        {
          vxlan_offload_trace_t *tr 
            = vlib_add_trace (vm, node, b2, sizeof (*tr));
          dpdk_vxlan_offload_rx_trace (tr, b2, next2, error2);
        }
        if (PREDICT_FALSE(b3->flags & VLIB_BUFFER_IS_TRACED)) 
        {
          vxlan_offload_trace_t *tr 
            = vlib_add_trace (vm, node, b3, sizeof (*tr));
          dpdk_vxlan_offload_rx_trace (tr, b3, next3, error3);
        }
      }

      vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
          to_next, n_left_to_next,
          bi0, bi1, bi2, bi3,
          next0, next1, next2, next3);
    }

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0 = from[0];
      from++;
      n_left_from--;

      to_next[0] = bi0;
      to_next++;
      n_left_to_next--;

      vlib_buffer_t * b0 = vlib_get_buffer (vm, bi0);
      vlib_buffer_advance (b0, vxlan_payload_offset);
      vnet_update_l2_len (b0);

      u32 len0 = vlib_buffer_length_in_chain (vm, b0);

      u32 next0 = next_index;
      u8 error0 = DPDK_ERROR_NONE;

      if (dpdk_check_ip_udp_len (b0))
        next0 = DPDK_VXLAN_OFFLOAD_NEXT_DROP, error0 = DPDK_ERROR_IP_CHECKSUM_ERROR;

      u32 sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      vlib_increment_combined_counter (rx_counter[next0], thread_index, sw_if_index0, 1, len0);

      if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED)) 
        {
          vxlan_offload_trace_t *tr 
            = vlib_add_trace (vm, node, b0, sizeof (*tr));
          dpdk_vxlan_offload_rx_trace (tr, b0, next0, error0);
        }

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
          to_next, n_left_to_next,
          bi0, next0);
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  return f->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MULTIARCH_VARIANT
VLIB_REGISTER_NODE (dpdk_vxlan_passthru_input_node) = {
  .name = "dpdk-vxlan-passthru-input",
  .function = dpdk_vxlan_passthru_input,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .vector_size = sizeof (u32),

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_vxlan_rx_trace,

  .n_errors = DPDK_N_ERROR,
  .error_strings = dpdk_error_strings,

  .n_next_nodes = DPDK_VXLAN_OFFLOAD_N_NEXT,
  .next_nodes = {
#define _(s,n) [DPDK_VXLAN_OFFLOAD_NEXT_##s] = n,
    foreach_vxlan_offload_input_next
#undef _
  },
};
/* *INDENT-ON* */

vlib_node_function_t __clib_weak dpdk_vxlan_passthru_input_avx512;
vlib_node_function_t __clib_weak dpdk_vxlan_passthru_input_avx2;

#if __x86_64__
static void __clib_constructor
dpdk_vxlan_passthru_input_multiarch_select (void)
{
  if (dpdk_vxlan_passthru_input_avx512 && clib_cpu_supports_avx512f ())
    dpdk_vxlan_passthru_input_node.function = dpdk_vxlan_passthru_input_avx512;
  else if (dpdk_vxlan_passthru_input_avx2 && clib_cpu_supports_avx2 ())
    dpdk_vxlan_passthru_input_node.function = dpdk_vxlan_passthru_input_avx2;
}
#endif

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_vxlan_offload_input_node) = {
  .function = dpdk_vxlan_offload_input,
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "dpdk-vxlan-offload-input",
  .runtime_data_bytes = sizeof (vnet_device_input_runtime_t),

  /* Will be enabled if/when offload is requested. */
  .state = VLIB_NODE_STATE_DISABLED,

  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_dpdk_vxlan_rx_trace,

  .n_errors = DPDK_N_ERROR,
  .error_strings = dpdk_error_strings,

  .n_next_nodes = DPDK_VXLAN_OFFLOAD_N_NEXT,
  .next_nodes = {
#define _(s,n) [DPDK_VXLAN_OFFLOAD_NEXT_##s] = n,
    foreach_vxlan_offload_input_next
#undef _
  },
};
/* *INDENT-ON* */

vlib_node_function_t __clib_weak dpdk_vxlan_offload_input_avx512;
vlib_node_function_t __clib_weak dpdk_vxlan_offload_input_avx2;

#if __x86_64__
static void __clib_constructor
dpdk_input_multiarch_select (void)
{
  if (dpdk_vxlan_offload_input_avx512 && clib_cpu_supports_avx512f ())
    dpdk_vxlan_offload_input_node.function = dpdk_vxlan_offload_input_avx512;
  else if (dpdk_vxlan_offload_input_avx2 && clib_cpu_supports_avx2 ())
    dpdk_vxlan_offload_input_node.function = dpdk_vxlan_offload_input_avx2;
}
#endif
#endif
