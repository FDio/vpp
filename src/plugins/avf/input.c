/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>

#include <avf/avf.h>

#define foreach_avf_input_error \
  _(BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f,s) MRVL_PP2_INPUT_ERROR_##f,
  foreach_avf_input_error
#undef _
    AVF_INPUT_N_ERROR,
} avf_input_error_t;

static __clib_unused char *avf_input_error_strings[] = {
#define _(n,s) s,
  foreach_avf_input_error
#undef _
};

avf_rx_desc_t _last = { 0 }, *ld = &_last;

static_always_inline uword
avf_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame, avf_device_t * ad, u16 qid)
{
  u32 n_rx_packets = 0;
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);
  avf_rx_desc_t *d = (avf_rx_desc_t *) rxq->descs;

  if (memcmp (ld, d, 32))
    {
      fformat (stderr, "\ndata\n%U", format_hexdump, d, 32);
      fformat (stderr, "\ndesc %p", d);
      fformat (stderr, "\n%-20s0x%lx", "addr",
	       avf_get_u64_bits (d, 0, 63, 0));
      fformat (stderr, "\n%-20s0x%lx", "data",
	       vlib_get_buffer_data_physical_address (vm, rxq->bufs[0]));
      fformat (stderr, "\n%-20s0x%lx", "data va",
	       vlib_buffer_get_current (vlib_get_buffer (vm, rxq->bufs[0])));
      fformat (stderr, "\n");
      memcpy (ld, d, 32);
    }

  vlib_buffer_t *b = vlib_get_buffer (vm, rxq->bufs[1]);
  u64 *r = (u64 *) b->data;
  if (*r)
    clib_warning ("bingo2 %x", *r);

#if 0
  if (rxq->n_bufs == 0)
    {
      rxq->n_bufs = 8;
      vlib_buffer_alloc (vm, rxq->bufs, 8);
      for (int i = 0; i < 8; i++)
	{
	  avf_rx_desc_t *d = (avf_rx_desc_t *) rxq->descs + i * 32;
	  d->qword[0] =
	    vlib_get_buffer_data_physical_address (vm, rxq->bufs[i]);
	}
      clib_warning ("rearm q %u b0 pa %x", qid, ((u64 *) rxq->descs)[0]);
      CLIB_MEMORY_BARRIER ();
      *(rxq->qrx_tail) = 1;
      //avf_set_u32 (ad->bar0, /*AVF_QRX_TAIL(qid)*/ 0x2000, 8);  /* Tail */
    }
#endif

  return n_rx_packets;
}

uword
avf_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  u32 n_rx = 0;
  avf_main_t *am = &avf_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    avf_device_t *ad;
    ad = vec_elt_at_index (am->devices, dq->dev_instance);
    if ((ad->flags & AVF_DEVICE_F_INITIALIZED) == 0)
      continue;
    if ((ad->flags & AVF_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += avf_device_input_inline (vm, node, frame, ad, dq->queue_id);
  }
  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_input_node) = {
  .function = avf_input_fn,
  .name = "avf-input",
  .sibling_of = "device-input",
  //.format_trace = format_avf_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .n_errors = AVF_INPUT_N_ERROR,
  .error_strings = avf_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
