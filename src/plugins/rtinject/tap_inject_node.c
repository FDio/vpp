/*
 * Copyright 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "tap_inject.h"

#include <netinet/in.h>
#include <vnet/ethernet/arp_packet.h>

vlib_node_registration_t tap_inject_rx_node;
vlib_node_registration_t tap_inject_tx_node;
vlib_node_registration_t tap_inject_neighbor_node;

enum {
  NEXT_NEIGHBOR_ARP,
  NEXT_NEIGHBOR_ICMP6,
};

/**
 * @brief Dynamically added tap_inject DPO type
 */
dpo_type_t tap_inject_dpo_type;

static inline void
tap_inject_tap_send_buffer (int fd, vlib_buffer_t * b)
{
  struct iovec iov;
  ssize_t n_bytes;

  iov.iov_base = vlib_buffer_get_current (b);
  iov.iov_len = b->current_length;

  n_bytes = writev (fd, &iov, 1);

  if (n_bytes < 0)
    clib_warning ("writev failed");
  else if (n_bytes < b->current_length || b->flags & VLIB_BUFFER_NEXT_PRESENT)
    clib_warning ("buffer truncated");
}

static uword
tap_inject_tx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  vlib_buffer_t * b;
  u32 * pkts;
  u32 fd;
  u32 i;

  pkts = vlib_frame_vector_args (f);

  for (i = 0; i < f->n_vectors; ++i)
    {
      b = vlib_get_buffer (vm, pkts[i]);

      fd = tap_inject_lookup_tap_fd (vnet_buffer (b)->sw_if_index[VLIB_RX]);
      if (fd == ~0)
        continue;

      /* Re-wind the buffer to the start of the Ethernet header. */
      vlib_buffer_advance (b, -b->current_data);

      tap_inject_tap_send_buffer (fd, b);
    }

  vlib_buffer_free (vm, pkts, f->n_vectors);
  return f->n_vectors;
}

VLIB_REGISTER_NODE (tap_inject_tx_node) = {
  .function = tap_inject_tx,
  .name = "tap-inject-tx",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};


static uword
tap_inject_neighbor (vlib_main_t * vm,
                     vlib_node_runtime_t * node, vlib_frame_t * f)
{
  vlib_buffer_t * b;
  u32 * pkts;
  u32 fd;
  u32 i;
  u32 bi;
  u32 next_index = node->cached_next_index;
  u32 next = ~0;
  u32 n_left;
  u32 * to_next;

  pkts = vlib_frame_vector_args (f);

  for (i = 0; i < f->n_vectors; ++i)
    {
      bi = pkts[i];
      b = vlib_get_buffer (vm, bi);

      fd = tap_inject_lookup_tap_fd (vnet_buffer (b)->sw_if_index[VLIB_RX]);
      if (fd == ~0)
        {
          vlib_buffer_free (vm, &bi, 1);
          continue;
        }

      /* Re-wind the buffer to the start of the Ethernet header. */
      vlib_buffer_advance (b, -b->current_data);

      tap_inject_tap_send_buffer (fd, b);

      /* Send the buffer to a neighbor node too? */
      {
        ethernet_header_t * eth = vlib_buffer_get_current (b);
        u16 ether_type = htons (eth->type);

        if (ether_type == ETHERNET_TYPE_ARP)
          {
            ethernet_arp_header_t * arp = (void *)(eth + 1);

            if (arp->opcode == ntohs (ETHERNET_ARP_OPCODE_reply))
              next = NEXT_NEIGHBOR_ARP;
          }
        else if (ether_type == ETHERNET_TYPE_IP6)
          {
            ip6_header_t * ip = (void *)(eth + 1);
            icmp46_header_t * icmp = (void *)(ip + 1);

            if (ip->protocol == IP_PROTOCOL_ICMP6 &&
                icmp->type == ICMP6_neighbor_advertisement)
              next = NEXT_NEIGHBOR_ICMP6;
          }
      }

      if (next == ~0)
        {
          vlib_buffer_free (vm, &bi, 1);
          continue;
        }

      /* ARP and ICMP6 expect to start processing after the Ethernet header. */
      vlib_buffer_advance (b, sizeof (ethernet_header_t));

      vlib_get_next_frame (vm, node, next_index, to_next, n_left);

      *(to_next++) = bi;
      --n_left;

      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                       n_left, bi, next);
      vlib_put_next_frame (vm, node, next_index, n_left);
    }

  return f->n_vectors;
}

VLIB_REGISTER_NODE (tap_inject_neighbor_node) = {
  .function = tap_inject_neighbor,
  .name = "tap-inject-neighbor",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 2,
  .next_nodes = {
    [NEXT_NEIGHBOR_ARP] = "arp-input",
    [NEXT_NEIGHBOR_ICMP6] = "icmp6-neighbor-solicitation",
  },
};


#define MTU 1500
#define MTU_BUFFERS ((MTU + VLIB_BUFFER_DATA_SIZE - 1) / VLIB_BUFFER_DATA_SIZE)
#define NUM_BUFFERS_TO_ALLOC 32

static inline uword
tap_rx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f, int fd)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 sw_if_index;
  struct iovec iov[MTU_BUFFERS];
  u32 bi[MTU_BUFFERS];
  vlib_buffer_t * b;
  ssize_t n_bytes;
  ssize_t n_bytes_left;
  u32 i, j;

  sw_if_index = tap_inject_lookup_sw_if_index_from_tap_fd (fd);
  if (sw_if_index == ~0)
    return 0;

  /* Allocate buffers in bulk when there are less than enough to rx an MTU. */
  if (vec_len (im->rx_buffers) < MTU_BUFFERS)
    {
      u32 len = vec_len (im->rx_buffers);

      len = vlib_buffer_alloc_from_free_list (vm,
                    &im->rx_buffers[len], NUM_BUFFERS_TO_ALLOC,
                    VLIB_BUFFER_DEFAULT_FREE_LIST_INDEX);

      _vec_len (im->rx_buffers) += len;

      if (vec_len (im->rx_buffers) < MTU_BUFFERS)
        {
          clib_warning ("failed to allocate buffers");
          return 0;
        }
    }

  /* Fill buffers from the end of the list to make it easier to resize. */
  for (i = 0, j = vec_len (im->rx_buffers) - 1; i < MTU_BUFFERS; ++i, --j)
    {
      vlib_buffer_t * b;

      bi[i] = im->rx_buffers[j];

      b = vlib_get_buffer (vm, bi[i]);

      iov[i].iov_base = b->data;
      iov[i].iov_len = VLIB_BUFFER_DATA_SIZE;
    }

  n_bytes = readv (fd, iov, MTU_BUFFERS);
  if (n_bytes < 0)
    {
      clib_warning ("readv failed");
      return 0;
    }

  b = vlib_get_buffer (vm, bi[0]);

  vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index;

  n_bytes_left = n_bytes - VLIB_BUFFER_DATA_SIZE;

  if (n_bytes_left > 0)
    {
      b->total_length_not_including_first_buffer = n_bytes_left;
      b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
    }

  b->current_length = n_bytes;

  /* If necessary, configure any remaining buffers in the chain. */
  for (i = 1; n_bytes_left > 0; ++i, n_bytes_left -= VLIB_BUFFER_DATA_SIZE)
    {
      b = vlib_get_buffer (vm, bi[i - 1]);
      b->current_length = VLIB_BUFFER_DATA_SIZE;
      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b->next_buffer = bi[i];

      b = vlib_get_buffer (vm, bi[i]);
      b->current_length = n_bytes_left;
    }

  _vec_len (im->rx_buffers) -= i;

  /* Get the packet to the output node. */
  {
    vnet_hw_interface_t * hw;
    vlib_frame_t * new_frame;
    u32 * to_next;

    hw = vnet_get_hw_interface (vnet_get_main (), sw_if_index);

    new_frame = vlib_get_frame_to_node (vm, hw->output_node_index);
    to_next = vlib_frame_vector_args (new_frame);
    to_next[0] = bi[0];
    new_frame->n_vectors = 1;

    vlib_put_frame_to_node (vm, hw->output_node_index, new_frame);
  }

  return 1;
}

static uword
tap_inject_rx (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * f)
{
  tap_inject_main_t * im = tap_inject_get_main ();
  u32 * fd;
  uword count = 0;

  vec_foreach (fd, im->rx_file_descriptors)
    {
      if (tap_rx (vm, node, f, *fd) != 1)
        {
          clib_warning ("rx failed");
          count = 0;
          break;
        }
      ++count;
    }

  vec_free (im->rx_file_descriptors);

  return count;
}

VLIB_REGISTER_NODE (tap_inject_rx_node) = {
  .function = tap_inject_rx,
  .name = "tap-inject-rx",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .vector_size = sizeof (u32),
};

/**
 * @brief no-op lock function.
 */
static void
tap_inject_dpo_lock (dpo_id_t * dpo)
{
}

/**
 * @brief no-op unlock function.
 */
static void
tap_inject_dpo_unlock (dpo_id_t * dpo)
{
}

u8 *
format_tap_inject_dpo (u8 * s, va_list * args)
{
  return (format (s, "tap-inject:[%d]", 0));
}

const static dpo_vft_t tap_inject_vft = {
  .dv_lock = tap_inject_dpo_lock,
  .dv_unlock = tap_inject_dpo_unlock,
  .dv_format = format_tap_inject_dpo,
};

const static char *const tap_inject_tx_nodes[] = {
  "tap-inject-tx",
  NULL,
};

const static char *const *const tap_inject_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = tap_inject_tx_nodes,
  [DPO_PROTO_IP6] = tap_inject_tx_nodes,
};

static clib_error_t *
tap_inject_init (vlib_main_t * vm)
{
  tap_inject_main_t * im = tap_inject_get_main ();

  im->rx_node_index = tap_inject_rx_node.index;
  im->tx_node_index = tap_inject_tx_node.index;
  im->neighbor_node_index = tap_inject_neighbor_node.index;

  tap_inject_dpo_type = dpo_register_new_type (&tap_inject_vft, tap_inject_nodes);

  vec_alloc (im->rx_buffers, NUM_BUFFERS_TO_ALLOC);
  vec_reset_length (im->rx_buffers);

  return 0;
}

VLIB_INIT_FUNCTION (tap_inject_init);
