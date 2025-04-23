/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef SRC_VNET_SESSION_SESSION_LOGGING_H_
#define SRC_VNET_SESSION_SESSION_LOGGING_H_

#include <vnet/session/session_types.h>
#include <vnet/session/application.h>

typedef struct session_log_collector_cfg_
{
  session_endpoint_cfg_t sep; /**< collector endpoint */
  u8 is_server : 1;	      /**< collector is server */
} session_log_collector_cfg_t;

typedef struct session_log_buffer_chunk_
{
  u32 chunk_index; /**< index in pool  */
  u32 next_index;  /**< next in linked list */
  u32 len;	   /**< log data length */
  u8 data[512];	   /**< log data */
} __clib_packed session_log_buffer_chunk_t;

typedef struct session_log_buffer_
{
  session_log_buffer_chunk_t *chunks; /**< pool of chunks */
  u32 head_chunk;		      /**< head of linked list */
  u32 tail_chunk;		      /**< tail of linked list  */
  u32 len;			      /**< log data length */
} session_log_buffer_t;

typedef struct session_log_collector_wrk_
{
  session_handle_t session_handle; /**< per-worker session handle */
  session_log_buffer_t buf;	   /**< per-worker log buffer */
  svm_fifo_seg_t *segs;
} session_log_collector_wrk_t;

typedef struct session_log_collector_
{
  session_log_collector_wrk_t *wrk; /**< per-thread context */
  u8 is_init : 1;		    /**< collector initialized */
  u32 collector_index;		    /**< collector index */
  u32 session_map;		    /**< map of connected sessions */
  u32 session_map_lock;		    /**< lock for session map */
  session_log_collector_cfg_t cfg;  /**< collector config */
} session_log_collector_t;

typedef struct session_logging_main_
{
  session_log_collector_t *collectors; /**< pool of collectors */
  u32 app_index;		       /**< log collector app index */

  /*
   * application config
   */
  u32 segment_size; /**< segment size */
  u32 fifo_size;    /**< fifo size */
} session_logging_main_t;

int session_log_collector_add (session_log_collector_cfg_t *cfg);
void *app_log_collector_get_cb_fn ();

#endif /* SRC_VNET_SESSION_SESSION_LOGGING_H_ */