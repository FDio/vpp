/*
 * Copyright (c) 2024 InMon Corp.
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
#ifndef __included_sflow_h__
#define __included_sflow_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <sflow/sflow_common.h>
#include <sflow/sflow_vapi.h>
#include <sflow/sflow_psample.h>
#include <sflow/sflow_usersock.h>

#define SFLOW_DEFAULT_SAMPLING_N   10000
#define SFLOW_DEFAULT_POLLING_S	   20
#define SFLOW_DEFAULT_HEADER_BYTES 128
#define SFLOW_MAX_HEADER_BYTES	   256
#define SFLOW_MIN_HEADER_BYTES	   64
#define SFLOW_HEADER_BYTES_STEP	   32

#define SFLOW_USE_VAPI
#define SFLOW_FIFO_DEPTH  2048 // must be power of 2
#define SFLOW_POLL_WAIT_S 0.001
#define SFLOW_READ_BATCH  100

// use PSAMPLE group number to distinguish VPP samples from others
// (so that hsflowd will know to remap the ifIndex numbers if necessary)
#define SFLOW_VPP_PSAMPLE_GROUP_INGRESS 3
#define SFLOW_VPP_PSAMPLE_GROUP_EGRESS	4

#define foreach_sflow_error                                                   \
  _ (PROCESSED, "sflow packets processed")                                    \
  _ (SAMPLED, "sflow packets sampled")                                        \
  _ (DROPPED, "sflow packets dropped")                                        \
  _ (PSAMPLE_SEND, "sflow PSAMPLE sent")                                      \
  _ (PSAMPLE_SEND_FAIL, "sflow PSAMPLE send failed")

typedef enum
{
#define _(sym, str) SFLOW_ERROR_##sym,
  foreach_sflow_error
#undef _
    SFLOW_N_ERROR,
} sflow_error_t;

typedef struct
{
  u32 counters[SFLOW_N_ERROR];
} sflow_err_ctrs_t;

/* packet sample */
typedef struct
{
  u32 samplingN;
  u32 input_if_index;
  u32 output_if_index;
  u32 header_protocol;
  u32 sampled_packet_size;
  u32 header_bytes;
  u8 header[SFLOW_MAX_HEADER_BYTES];
} sflow_sample_t;

// Define SPSC FIFO for sending samples worker-to-main.
// (I did try to use VPP svm FIFO, but couldn't
// understand why it was sometimes going wrong).
typedef struct
{
  volatile u32 tx; // can change under consumer's feet
  volatile u32 rx; // can change under producer's feet
  sflow_sample_t samples[SFLOW_FIFO_DEPTH];
} sflow_fifo_t;

#define SFLOW_FIFO_NEXT(slot) ((slot + 1) & (SFLOW_FIFO_DEPTH - 1))
static inline int
sflow_fifo_enqueue (sflow_fifo_t *fifo, sflow_sample_t *sample)
{
  u32 curr_rx = clib_atomic_load_acq_n (&fifo->rx);
  u32 curr_tx = fifo->tx; // clib_atomic_load_acq_n(&fifo->tx);
  u32 next_tx = SFLOW_FIFO_NEXT (curr_tx);
  if (next_tx == curr_rx)
    return false; // full
  memcpy (&fifo->samples[next_tx], sample, sizeof (*sample));
  clib_atomic_store_rel_n (&fifo->tx, next_tx);
  return true;
}

static inline int
sflow_fifo_dequeue (sflow_fifo_t *fifo, sflow_sample_t *sample)
{
  u32 curr_rx = fifo->rx; // clib_atomic_load_acq_n(&fifo->rx);
  u32 curr_tx = clib_atomic_load_acq_n (&fifo->tx);
  if (curr_rx == curr_tx)
    return false; // empty
  memcpy (sample, &fifo->samples[curr_rx], sizeof (*sample));
  u32 next_rx = SFLOW_FIFO_NEXT (curr_rx);
  clib_atomic_store_rel_n (&fifo->rx, next_rx);
  return true;
}

/* private to worker */
typedef struct
{
  u32 smpN;
  u32 skip;
  u32 pool;
  u32 seed;
  u32 smpl;
  u32 drop;
  CLIB_CACHE_LINE_ALIGN_MARK (_fifo);
  sflow_fifo_t fifo;
} sflow_per_thread_data_t;

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;

  /* sampling state */
  u32 samplingN;
  u32 pollingS;
  u32 headerB;
  u32 total_threads;
  sflow_per_interface_data_t *per_interface_data;
  sflow_per_thread_data_t *per_thread_data;

  /* psample channel (packet samples) */
  SFLOWPS sflow_psample;
  /* usersock channel (periodic counters) */
  SFLOWUS sflow_usersock;
#define SFLOW_NETLINK_USERSOCK_MULTICAST 29
  /* dropmon channel (packet drops) */
  // SFLOWDM sflow_dropmon;

  /* sample-processing */
  u32 now_mono_S;

  /* running control */
  int running;
  u32 interfacesEnabled;

  /* main-thread counters */
  u32 psample_seq_ingress;
  u32 psample_seq_egress;
  u32 psample_send_drops;
  u32 csample_send;
  u32 csample_send_drops;
  u32 unixsock_seq;

  /* vapi query helper thread (transient) */
  CLIB_CACHE_LINE_ALIGN_MARK (_vapi);
  sflow_vapi_client_t vac;
  int vapi_requests;

} sflow_main_t;

extern sflow_main_t sflow_main;

extern vlib_node_registration_t sflow_node;

static inline u32
sflow_next_random_skip (sflow_per_thread_data_t *sfwk)
{
  /* skip==1 means "take the next packet" so this
     fn must never return 0 */
  if (sfwk->smpN <= 1)
    return 1;
  u32 lim = (2 * sfwk->smpN) - 1;
  return (random_u32 (&sfwk->seed) % lim) + 1;
}

#endif /* __included_sflow_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
