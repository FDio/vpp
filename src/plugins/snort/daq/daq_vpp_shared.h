/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef __DAQ_VPP_SHARED_H__
#define __DAQ_VPP_SHARED_H__

#include <stdint.h>

#define DAQ_VPP_VERSION		    2
#define DAQ_VPP_DEFAULT_SOCKET_FILE "snort.sock"
#define DAQ_VPP_DEFAULT_SOCKET_PATH "/run/vpp/" DAQ_VPP_DEFAULT_SOCKET_FILE
#define DAQ_VPP_MAX_INST_NAME_LEN   32
#define DAQ_VPP_COOKIE		    0xa196c3e82a4bc68f

typedef uint8_t daq_vpp_buffer_pool_index_t;
typedef uint16_t daq_vpp_input_index_t;
typedef uint16_t daq_vpp_qpair_index_t;
typedef uint16_t daq_vpp_desc_index_t;
typedef uint32_t daq_vpp_offset_t;
typedef uint64_t daq_vpp_head_tail_t;

typedef enum
{
  DAQ_VPP_MSG_TYPE_UNKNOWN = 0,
  DAQ_VPP_MSG_TYPE_CONNECT = 1,
  DAQ_VPP_MSG_TYPE_GET_BUFFER_POOL = 2,
  DAQ_VPP_MSG_TYPE_GET_INPUT = 3,
  DAQ_VPP_MSG_TYPE_ATTACH_QPAIR = 4,
} __attribute__ ((packed)) daq_vpp_msg_type_t;

typedef enum
{
  DAQ_VPP_OK = 0,
  DAQ_VPP_ERR_SOCKET = 1,
  DAQ_VPP_ERR_MALLOC_FAIL = 2,
  DAQ_VPP_ERR_UNSUPPORTED_VERSION = 3,
  DAQ_VPP_ERR_INVALID_MESSAGE = 4,
  DAQ_VPP_ERR_INVALID_INDEX = 5,
  DAQ_VPP_ERR_UNKNOWN_INPUT = 6,
  DAQ_VPP_ERR_QPAIR_IN_USE = 7,
  DAQ_VPP_ERR_QPAIR_NOT_READY = 8,
} __attribute__ ((packed)) daq_vpp_rv_t;

static inline __attribute__ ((__always_inline__)) const char *
daq_vpp_rv_string (daq_vpp_rv_t err)
{
  const char *msg_errors[] = {
    [DAQ_VPP_OK] = "no error",
    [DAQ_VPP_ERR_SOCKET] = "socket error",
    [DAQ_VPP_ERR_MALLOC_FAIL] = "memory allocation error",
    [DAQ_VPP_ERR_UNSUPPORTED_VERSION] = "unsuported version",
    [DAQ_VPP_ERR_INVALID_MESSAGE] = "invalid message",
    [DAQ_VPP_ERR_INVALID_INDEX] = "invalid index",
    [DAQ_VPP_ERR_UNKNOWN_INPUT] = "unknown input",
    [DAQ_VPP_ERR_QPAIR_IN_USE] = "qpair alredy in use",
    [DAQ_VPP_ERR_QPAIR_NOT_READY] = "qpair not ready",
  };
  if (err >= (sizeof (msg_errors) / sizeof (msg_errors[0])))
    return 0;
  return msg_errors[err];
}

typedef struct
{
  uint16_t thread_id;
  uint16_t queue_id;
} daq_vpp_qpair_id_t;

typedef struct
{
  uint32_t daq_version;
  uint16_t num_snort_instances;
} daq_vpp_msg_req_connect_t;

typedef struct
{
  uint16_t num_bpools;
} daq_vpp_msg_reply_connect_t;

typedef struct
{
  daq_vpp_buffer_pool_index_t buffer_pool_index;
} daq_vpp_msg_req_get_buffer_pool_t;

typedef struct
{
  daq_vpp_buffer_pool_index_t buffer_pool_index;
  uint64_t size;
} daq_vpp_msg_reply_get_buffer_pool_t;

typedef struct
{
  char input_name[DAQ_VPP_MAX_INST_NAME_LEN];
} daq_vpp_msg_req_get_input_t;

typedef struct
{
  daq_vpp_input_index_t input_index;
  uint64_t shm_size;
  uint16_t num_qpairs;
} daq_vpp_msg_reply_get_input_t;

typedef struct
{
  daq_vpp_input_index_t input_index;
  daq_vpp_qpair_index_t qpair_index;
} daq_vpp_msg_req_attach_qpair_t;

typedef struct
{
  daq_vpp_qpair_id_t qpair_id;
  daq_vpp_input_index_t input_index;
  daq_vpp_qpair_index_t qpair_index;
  uint8_t log2_queue_size;
  daq_vpp_offset_t qpair_header_offset;
  daq_vpp_offset_t enq_ring_offset;
  daq_vpp_offset_t deq_ring_offset;
} daq_vpp_msg_reply_attach_qpair_t;

typedef struct
{
  daq_vpp_msg_type_t type;
  union
  {
    daq_vpp_msg_req_connect_t connect;
    daq_vpp_msg_req_get_buffer_pool_t get_buffer_pool;
    daq_vpp_msg_req_get_input_t get_input;
    daq_vpp_msg_req_attach_qpair_t attach_qpair;
  };
} daq_vpp_msg_req_t;

typedef struct
{
  daq_vpp_msg_type_t type;
  daq_vpp_rv_t err;
  union
  {
    daq_vpp_msg_reply_connect_t connect;
    daq_vpp_msg_reply_get_buffer_pool_t get_buffer_pool;
    daq_vpp_msg_reply_get_input_t get_input;
    daq_vpp_msg_reply_attach_qpair_t attach_qpair;
  };
} daq_vpp_msg_reply_t;

typedef enum
{
  DAQ_VPP_ACTION_DROP,
  DAQ_VPP_ACTION_FORWARD,
} __attribute__ ((packed)) daq_vpp_action_t;

typedef struct
{
  daq_vpp_offset_t offset;
  uint16_t length;
  uint16_t address_space_id;
  uint8_t buffer_pool;
  daq_vpp_action_t action;
} daq_vpp_desc_t;

typedef struct
{
  /* enqueue */
  daq_vpp_head_tail_t __attribute__ ((__aligned__ (64))) enq_head;
  uint64_t cookie;

  /* dequeue */
  daq_vpp_head_tail_t __attribute__ ((__aligned__ (64))) deq_head;

  /* descriptors */
  daq_vpp_desc_t __attribute__ ((__aligned__ (64))) descs[];
} daq_vpp_qpair_header_t;

_Static_assert (sizeof (daq_vpp_qpair_header_t) == 128,
		"size must be two achelines");

#endif /* __DAQ_VPP_SHARED_H__ */
