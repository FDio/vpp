/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#ifndef _PP2_H_
#define _PP2_H_

#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/format.h>
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#define MVCONF_DBG_LEVEL	       0
#define MVCONF_PP2_BPOOL_COOKIE_SIZE   32
#define MVCONF_PP2_BPOOL_DMA_ADDR_SIZE 64
#define MVCONF_DMA_PHYS_ADDR_T_SIZE    64
#define MVCONF_SYS_DMA_UIO
#define MVCONF_TYPES_PUBLIC
#define MVCONF_DMA_PHYS_ADDR_T_PUBLIC

#include "mv_std.h"
#include "env/mv_sys_dma.h"
#include "drivers/mv_pp2.h"
#include <drivers/mv_pp2_bpool.h>
#include <drivers/mv_pp2_ppio.h>

#define MVPP2_NUM_HIFS	       9
#define MVPP2_NUM_BPOOLS       16
#define MVPP2_MAX_THREADS      4
#define MRVL_PP2_BUFF_BATCH_SZ 32

typedef struct
{
  u8 pp_id;
  struct pp2_hif *hif[MVPP2_NUM_HIFS];
  struct
  {
    struct pp2_bpool *bpool;
    struct buff_release_entry bre[MRVL_PP2_BUFF_BATCH_SZ];
  } thread[MVPP2_NUM_BPOOLS];

} mvpp2_device_t;

typedef struct
{
  u8 is_enabled : 1;
  u8 is_dsa : 1;
  struct pp2_ppio *ppio;
  u8 ppio_id;
  struct pp2_ppio_link_info last_link_info;
} mvpp2_port_t;

typedef struct
{
  u16 next;
  u16 n_enq;
  u32 *buffers;
} mvpp2_txq_t;

typedef struct
{
} mvpp2_rxq_t;

typedef struct
{
  struct pp2_ppio_desc desc;
  vnet_dev_rx_queue_t *rxq;
} mvpp2_rx_trace_t;

/* format.c */
format_function_t format_pp2_ppio_link_info;
format_function_t format_mvpp2_port_status;
format_function_t format_mvpp2_dev_info;
format_function_t format_mvpp2_rx_trace;
format_function_t format_mvpp2_rx_desc;

/* port.c */
vnet_dev_port_op_t mvpp2_port_init;
vnet_dev_port_op_no_rv_t mvpp2_port_deinit;
vnet_dev_port_op_t mvpp2_port_start;
vnet_dev_port_op_no_rv_t mvpp2_port_stop;
vnet_dev_rv_t mvpp2_port_cfg_change (vlib_main_t *, vnet_dev_port_t *,
				     vnet_dev_port_cfg_change_req_t *);
vnet_dev_rv_t
mvpp2_port_cfg_change_validate (vlib_main_t *, vnet_dev_port_t *,
				vnet_dev_port_cfg_change_req_t *);

/* queue.c */
vnet_dev_tx_queue_op_t mvpp2_txq_alloc;
vnet_dev_tx_queue_op_no_rv_t mvpp2_txq_free;

/* inline funcs */

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, mvpp2_log.class, "%U" f,                    \
	    format_vnet_dev_log, (dev),                                       \
	    clib_string_skip_prefix (__func__, "mvpp2_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_INFO, mvpp2_log.class, "%U" f,                     \
	    format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                               \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, mvpp2_log.class, "%U" f,                   \
	    format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, mvpp2_log.class, "%U" f,                  \
	    format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, mvpp2_log.class, "%U" f, format_vnet_dev_log, \
	    (dev), 0, ##__VA_ARGS__)

#define foreach_mvpp2_tx_node_counter                                         \
  _ (NO_FREE_SLOTS, no_free_slots, ERROR, "no free tx slots")                 \
  _ (PPIO_SEND, ppio_semd, ERROR, "pp2_ppio_send errors")                     \
  _ (PPIO_GET_NUM_OUTQ_DONE, ppio_get_num_outq_done, ERROR,                   \
     "pp2_ppio_get_num_outq_done errors")

typedef enum
{
#define _(f, n, s, d) MVPP2_TX_NODE_CTR_##f,
  foreach_mvpp2_tx_node_counter
#undef _
} mvpp2_tx_node_counter_t;

#define foreach_mvpp2_rx_node_counter                                         \
  _ (PPIO_RECV, ppio_recv, ERROR, "pp2_ppio_recv error")                      \
  _ (BPOOL_GET_NUM_BUFFS, bpool_get_num_bufs, ERROR,                          \
     "pp2_bpool_get_num_buffs error")                                         \
  _ (BPOOL_PUT_BUFFS, bpool_put_buffs, ERROR, "pp2_bpool_put_buffs error")    \
  _ (BUFFER_ALLOC, buffer_alloc, ERROR, "buffer alloc error")                 \
  _ (MAC_CE, mac_ce, ERROR, "MAC error (CRC error)")                          \
  _ (MAC_OR, mac_or, ERROR, "overrun error")                                  \
  _ (MAC_RSVD, mac_rsvd, ERROR, "unknown MAC error")                          \
  _ (MAC_RE, mac_re, ERROR, "resource error")                                 \
  _ (IP_HDR, ip_hdr, ERROR, "ip4 header error")

typedef enum
{
#define _(f, n, s, d) MVPP2_RX_NODE_CTR_##f,
  foreach_mvpp2_rx_node_counter
#undef _
} mvpp2_rx_node_counter_t;

#endif /* _PP2_H_ */
