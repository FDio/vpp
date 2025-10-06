/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021-2025 Cisco Systems, Inc.
 */

#ifndef __DAQ_VPP_SHARED_H__
#define __DAQ_VPP_SHARED_H__

#define DAQ_VPP_VERSION		    2
#define DAQ_VPP_DEFAULT_SOCKET_FILE "snort.sock"
#define DAQ_VPP_DEFAULT_SOCKET_PATH "/run/vpp/" DAQ_VPP_DEFAULT_SOCKET_FILE
#define DAQ_VPP_MAX_INST_NAME_LEN   32
#define DAQ_VPP_COOKIE		    0xa196c3e82a4bc68f
#define DAQ_VPP_PKT_FLAG_PRE_ROUTING (1 << 2)

typedef enum
{
  DAQ_VPP_VERDICT_PASS = 0,
  DAQ_VPP_VERDICT_BLOCK,
  DAQ_VPP_VERDICT_REPLACE,
  DAQ_VPP_VERDICT_WHITELIST,
  DAQ_VPP_VERDICT_BLACKLIST,
  DAQ_VPP_VERDICT_IGNORE,
  DAQ_VPP_MAX_DAQ_VERDICT,
} daq_vpp_verdict_t;

typedef enum
{
  DAQ_VPP_MODE_NONE = 0,
  DAQ_VPP_MODE_PASSIVE,
  DAQ_VPP_MODE_INLINE,
  DAQ_VPP_MODE_READ_FILE,
  DAQ_VPP_MAX_DAQ_MODE,
} daq_vpp_mode_t;

typedef enum
{
  DAQ_VPP_DESC_FLAG_NONE = 0,
  // descriptor is free
  DAQ_VPP_DESC_FLAG_FREE = (1 << 0),
  // descriptor is available (to be processed)
  DAQ_VPP_DESC_FLAG_AVAIL =
    (1 << 1), // descriptor is available (to be processed)
  // descriptor is being processed (by snort), do not modify
  DAQ_VPP_DESC_FLAG_IN_PROCESSING = (1 << 2),
  // descriptor has been processed (by snort) and can be recycled
  DAQ_VPP_DESC_FLAG_USED = (1 << 3),
  // descriptor is an empty buffer (to be filled with new packet data) for
  // packet injection
  DAQ_VPP_DESC_FLAG_EMPTY_BUFFER = (1 << 4),
  // descriptor has been injected (by snort) and is ready for transmission
  DAQ_VPP_DESC_FLAG_INJECTED = (1 << 5),
} daq_vpp_desc_flags_t;

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
  DAQ_VPP_ERR_INVALID_MODE = 9,
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
    [DAQ_VPP_ERR_INVALID_MODE] = "invalid mode",
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
  daq_vpp_mode_t mode; /* mode */
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
  uint8_t log2_ebuf_queue_size;
  daq_vpp_offset_t qpair_header_offset;
  daq_vpp_offset_t enq_ring_offset;
  daq_vpp_offset_t deq_ring_offset;
  daq_vpp_offset_t ebuf_ring_offset;
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

typedef struct
{
  union
  {
    struct
    {
      uint32_t flags; /* DAQ_PKT_FLAG_* */
      uint32_t flow_id;
      int32_t ingress_index;
      uint16_t address_space_id;
    };
    struct
    {
      uint32_t desc_index; /* descriptor index */
    };
    struct
    {
      daq_vpp_verdict_t verdict; /* verdict */
    };
    uint32_t data[4];
  };
} daq_vpp_pkt_metadata_t;

_Static_assert (sizeof (daq_vpp_pkt_metadata_t) == 16,
		"let it be 128-bits, so it fits into single load/store");

typedef struct
{
  daq_vpp_desc_flags_t flags;
  daq_vpp_offset_t offset;
  uint16_t length;
  uint8_t buffer_pool;
  daq_vpp_pkt_metadata_t metadata;
} daq_vpp_desc_t;

typedef struct
{
  /* enqueue */
  struct
  {
    daq_vpp_head_tail_t head;
    uint8_t interrupt_pending;
    uint64_t cookie;
  } __attribute__ ((__aligned__ (64))) enq;

  /* dequeue */
  struct
  {
    daq_vpp_head_tail_t head;
    uint8_t interrupt_pending;
  } __attribute__ ((__aligned__ (64))) deq;

  /* empty buffer enqueue */
  struct
  {
    daq_vpp_head_tail_t head;
    uint8_t interrupt_pending;
  } __attribute__ ((__aligned__ (64))) ebuf;

  /* descriptors */
  daq_vpp_desc_t __attribute__ ((__aligned__ (64))) descs[];
} daq_vpp_qpair_header_t;

_Static_assert (sizeof (daq_vpp_qpair_header_t) == 192,
		"size must be three cachelines");

#endif /* __DAQ_VPP_SHARED_H__ */
