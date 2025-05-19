/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __DAQ_VPP_H__
#define __DAQ_VPP_H__

#include <stdint.h>
#include <daq_module_api.h>
#include "daq_vpp_shared.h"

#define __unused     __attribute__ ((unused))
#define __aligned(x) __attribute__ ((__aligned__ (x)))
#if __x86_64__
#define VPP_DAQ_PAUSE() __builtin_ia32_pause ()
#elif defined(__aarch64__) || defined(__arm__)
#define VPP_DAQ_PAUSE() __asm__ ("yield")
#else
#define VPP_DAQ_PAUSE()
#endif
#define ARRAY_LEN(x) (sizeof (x) / sizeof (x[0]))

#define DEBUG(fmt, ...)                                                       \
  if (daq_vpp_main.debug)                                                     \
    printf ("%s: " fmt "\n", "daq_vpp", ##__VA_ARGS__);

#define SET_ERROR(modinst, ...)                                               \
  daq_vpp_main.daq_base_api.set_errbuf (modinst, __VA_ARGS__)

typedef struct
{
  int fd;
  uint64_t size;
  void *base;
} daq_vpp_buffer_pool_t;

typedef struct _vpp_qpair
{
  daq_vpp_qpair_header_t *hdr;
  daq_vpp_desc_index_t *enq_ring;
  daq_vpp_desc_index_t *deq_ring;
  daq_vpp_head_tail_t tail;
  uint16_t queue_size;
  int enq_fd;
  int deq_fd;
  daq_vpp_input_index_t input_index;
  uint16_t used_by_instance;
  daq_vpp_qpair_id_t qpair_id;
} __aligned (64) daq_vpp_qpair_t;

typedef struct daq_vpp_msg_pool_entry
{
  DAQ_Msg_t msg;
  DAQ_PktHdr_t pkthdr;
  daq_vpp_desc_index_t index;
  union
  {
    struct daq_vpp_msg_pool_entry *freelist_next;
    daq_vpp_qpair_t *qpair;
  };
} daq_vpp_msg_pool_entry_t;

typedef enum
{
  DAQ_VPP_INPUT_MODE_INTERRUPT = 0,
  DAQ_VPP_INPUT_MODE_POLLING,
} daq_vpp_input_mode_t;

typedef struct daq_vpp_input_t
{
  /* shared memory */
  uint64_t shm_size;
  void *shm_base;
  int shm_fd;

  /* queue pairs */
  uint16_t num_qpairs;

  char name[DAQ_VPP_MAX_INST_NAME_LEN];
  daq_vpp_qpair_t qpairs[];
} daq_vpp_input_t;

typedef struct _vpp_context
{
  /* state */
  DAQ_ModuleInstance_h modinst;
  uint16_t instance_id;
  uint8_t interrupted;
  int timeout;

  /* stats */
  DAQ_Stats_t stats;

  /* epoll and eventfd */
  int epoll_fd;
  int wakeup_fd;

  uint16_t num_qpairs;
  daq_vpp_qpair_index_t next_qpair;
  daq_vpp_qpair_t **qpairs;

  /* msg pool */
  DAQ_MsgPoolInfo_t msg_pool_info;
  daq_vpp_msg_pool_entry_t *msg_pool_freelist;
  daq_vpp_msg_pool_entry_t msg_pool[];
} daq_vpp_ctx_t;

typedef struct
{
  uint32_t debug : 1;
  uint32_t config_parsed : 1;
  uint32_t connected : 1;
  uint32_t buffer_pools_initialized : 1;
  uint32_t hangup : 1;

  /* configured */
  uint32_t msg_pool_size;
  daq_vpp_input_mode_t input_mode;
  DAQ_BaseAPI_t daq_base_api;

  /* buffer pools */
  uint8_t num_bpools;
  daq_vpp_buffer_pool_t *bpools;

  /* socket */
  int socket_fd;
  const char *socket_name;

  /* inputs */
  daq_vpp_input_t **inputs;
  uint16_t n_inputs;

  /* instances */
  uint16_t n_instances;
} daq_vpp_main_t;

extern daq_vpp_main_t daq_vpp_main;

/* main.c */
int daq_vpp_err (daq_vpp_ctx_t *ctx, char *fmt, ...);

/* config.c */
int daq_vpp_get_variable_descs (const DAQ_VariableDesc_t **var_desc_table);
int daq_vpp_parse_config (daq_vpp_ctx_t *ctx, DAQ_ModuleConfig_h modcfg);

/* socket.c */
int daq_vpp_connect (daq_vpp_ctx_t *ctx, uint16_t num_instances);
int daq_vpp_find_or_add_input (daq_vpp_ctx_t *ctx, char *name,
			       daq_vpp_input_t **inp);

#endif /* __DAQ_VPP_H__ */
