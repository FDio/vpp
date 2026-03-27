/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#ifndef included_cadence_h
#define included_cadence_h

#include <vnet/dev/dev.h>

#include <cadence_regs.h>

extern vlib_log_class_registration_t cdn_log;

#define log_debug(dev, f, ...)                                                                     \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, cdn_log.class, "%U" f, format_vnet_dev_log, (dev),               \
	    clib_string_skip_prefix (__func__, "cdn_"), ##__VA_ARGS__)
#define log_info(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_INFO, cdn_log.class, "%U" f, format_vnet_dev_log, (dev), 0,             \
	    ##__VA_ARGS__)
#define log_notice(dev, f, ...)                                                                    \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, cdn_log.class, "%U" f, format_vnet_dev_log, (dev), 0,           \
	    ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                                      \
  vlib_log (VLIB_LOG_LEVEL_WARNING, cdn_log.class, "%U" f, format_vnet_dev_log, (dev), 0,          \
	    ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                                       \
  vlib_log (VLIB_LOG_LEVEL_ERR, cdn_log.class, "%U" f, format_vnet_dev_log, (dev), 0, ##__VA_ARGS__)

typedef struct
{
  void *regs;
  u32 regs_size;
  u8 is_gem : 1;
  u8 queue_mask;
  int uio_fd;
} cdn_device_t;

typedef struct
{
  u8 link_up : 1;
} cdn_port_t;

typedef struct
{
  union
  {
    struct
    {
      u32 used : 1;
      u32 wrap : 1;
      u32 waddr : 30;
    };
    u32 as_u32;
  } addr;
  union
  {
    struct
    {
      u32 frm_len : 12;
      u32 offset : 2;
      u32 sof : 1;
      u32 eof : 1;
      u32 cfi : 1;
      u32 vlan_pri : 3;
      u32 pri_tag : 1;
      u32 vlan_tag : 1;
      u32 typeid_match : 1;
      u32 sa4_match : 1;
      u32 sa3_match : 1;
      u32 sa2_match : 1;
      u32 sa1_match : 1;
      u32 reserved0 : 1;
      u32 ext_match : 1;
      u32 uhash_match : 1;
      u32 mhash_match : 1;
      u32 broadcast : 1;
    };
    u32 as_u32;
  } ctrl;
  u32 addrh;
  u32 resvd;
} cdn_rx_desc_t;

typedef struct
{
  u32 addr;
  union
  {
    struct
    {
      u32 frm_len : 11;
      u32 reserved0 : 4;
      u32 last : 1;
      u32 nocrc : 1;
      u32 lso : 2;
      u32 tcp_seq_src : 1;
      u32 reserved1 : 7;
      u32 buf_exhausted : 1;
      u32 underrun : 1;
      u32 error : 1;
      u32 wrap : 1;
      u32 used : 1;
    };
    u32 as_u32;
  } ctrl;
  u32 addrh;
  u32 resvd;
} cdn_tx_desc_t;

typedef struct
{
  u32 dummy;
} cdn_rxq_t;

typedef struct
{
  u32 dummy;
} cdn_txq_t;

static_always_inline u32
cdn_readl (cdn_device_t *cd, uword offset)
{
  return __atomic_load_n ((u32 *) ((u8 *) cd->regs + offset), __ATOMIC_RELAXED);
}

vnet_dev_rv_t cdn_port_init (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t cdn_port_start (vlib_main_t *vm, vnet_dev_port_t *port);
void cdn_port_stop (vlib_main_t *vm, vnet_dev_port_t *port);
vnet_dev_rv_t cdn_port_cfg_change_validate (vlib_main_t *vm, vnet_dev_port_t *port,
					    vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t cdn_port_cfg_change (vlib_main_t *vm, vnet_dev_port_t *port,
				   vnet_dev_port_cfg_change_req_t *req);
vnet_dev_rv_t cdn_rx_queue_alloc (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
void cdn_rx_queue_free (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq);
vnet_dev_rv_t cdn_tx_queue_alloc (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);
void cdn_tx_queue_free (vlib_main_t *vm, vnet_dev_tx_queue_t *txq);

extern vnet_dev_node_t cdn_rx_node;
extern vnet_dev_node_t cdn_tx_node;

format_function_t format_cdn_dev_info;
format_function_t format_cdn_rx_desc;
format_function_t format_cdn_tx_desc;

#endif /* included_cadence_h */
