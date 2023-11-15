/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_pktio_pktio_tx_h
#define included_onp_drv_modules_pktio_pktio_tx_h

#include <onp/drv/modules/pktio/pktio_priv.h>

#include <onp/drv/inc/pool_fp.h>

#define CNXK_PKTIO_NIX_SEND_L4TYPE_TCP_CKSUM  1
#define CNXK_PKTIO_NIX_SEND_L4TYPE_SCTP_CKSUM 2
#define CNXK_PKTIO_NIX_SEND_L4TYPE_UDP_CKSUM  3

#define CNXK_PKTIO_NIX_SEND_L3TYPE_IP4	     2
#define CNXK_PKTIO_NIX_SEND_L3TYPE_IP4_CKSUM 3
#define CNXK_PKTIO_NIX_SEND_L3TYPE_IP6	     4

#define CNXK_PKTIO_SEND_HDR_DWORDS 1

static_always_inline void
cnxk_update_sq_cached_pkts (cnxk_fpsq_t *fpsq, u16 tx_pkts)
{
  fpsq->cached_pkts -= tx_pkts;
}

static_always_inline u64
cnxk_pktio_get_aura_handle (vlib_main_t *vm, cnxk_per_thread_data_t *ptd,
			    vlib_buffer_t *b, u8 n_segs, u64 *cached_aura,
			    u8 *cached_bp_index, u16 *refill_counter)
{
  u64 aura_handle;

  if (PREDICT_TRUE (*cached_bp_index == b->buffer_pool_index))
    {
      aura_handle = *cached_aura;
      *refill_counter += n_segs;
    }
  else
    {
      aura_handle = cnxk_pool_get_aura_handle (b->buffer_pool_index);
      cnxk_pktpool_update_deplete_count (vm, ptd, *refill_counter,
					 *cached_bp_index);
      *cached_aura = aura_handle;
      *cached_bp_index = b->buffer_pool_index;
      *refill_counter = n_segs;
    }
  return aura_handle;
}

#endif /* included_onp_drv_modules_pktio_pktio_tx_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
