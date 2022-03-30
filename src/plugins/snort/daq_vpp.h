/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef __DAQ_VPP_H__
#define __DAQ_VPP_H__

#include <stdint.h>

#define DAQ_VPP_DEFAULT_SOCKET_FILE "snort.sock"
#define DAQ_VPP_DEFAULT_SOCKET_PATH "/run/vpp/" DAQ_VPP_DEFAULT_SOCKET_FILE
#define DAQ_VPP_INST_NAME_LEN	    32

typedef enum memif_msg_type
{
  DAQ_VPP_MSG_TYPE_NONE = 0,
  DAQ_VPP_MSG_TYPE_HELLO = 1,
  DAQ_VPP_MSG_TYPE_CONFIG = 2,
  DAQ_VPP_MSG_TYPE_BPOOL = 3,
  DAQ_VPP_MSG_TYPE_QPAIR = 4,
} daq_vpp_msg_type_t;

typedef struct
{
  char inst_name[DAQ_VPP_INST_NAME_LEN];
} daq_vpp_msg_hello_t;

typedef struct
{
  uint32_t shm_size;
  uint16_t num_bpools;
  uint16_t num_qpairs;
} daq_vpp_msg_config_t;

typedef struct
{
  uint32_t size;
} daq_vpp_msg_bpool_t;

typedef struct
{
  uint8_t log2_queue_size;
  uint32_t desc_table_offset;
  uint32_t enq_head_offset;
  uint32_t deq_head_offset;
  uint32_t enq_ring_offset;
  uint32_t deq_ring_offset;
} daq_vpp_msg_qpair_t;

typedef struct
{
  daq_vpp_msg_type_t type : 8;
  union
  {
    daq_vpp_msg_hello_t hello;
    daq_vpp_msg_config_t config;
    daq_vpp_msg_bpool_t bpool;
    daq_vpp_msg_qpair_t qpair;
  };
} daq_vpp_msg_t;

typedef enum
{
  DAQ_VPP_ACTION_DROP,
  DAQ_VPP_ACTION_FORWARD,
} daq_vpp_action_t;

typedef struct
{
  uint64_t offset;
  uint16_t length;
  uint16_t address_space_id;
  uint8_t buffer_pool;
  daq_vpp_action_t action : 8;
} daq_vpp_desc_t;

#endif /* __DAQ_VPP_H__ */
