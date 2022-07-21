/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef VAPI_INTERNAL_H
#define VAPI_INTERNAL_H

#include <endian.h>
#include <string.h>
#include <vppinfra/types.h>

/**
 * @file vapi_internal.h
 *
 * internal vpp api C declarations
 *
 * This file contains internal vpp api C declarations. It's not intended to be
 * used by the client programmer and the API defined here might change at any
 * time..
 */

#ifdef __cplusplus
extern "C" {
#endif

struct vapi_ctx_s;

typedef struct __attribute__ ((__packed__))
{
  u16 _vl_msg_id;
  u32 context;
} vapi_type_msg_header1_t;

typedef struct __attribute__ ((__packed__))
{
  u16 _vl_msg_id;
  u32 client_index;
  u32 context;
} vapi_type_msg_header2_t;

static inline void
vapi_type_msg_header1_t_hton (vapi_type_msg_header1_t * h)
{
  h->_vl_msg_id = htobe16 (h->_vl_msg_id);
}

static inline void
vapi_type_msg_header1_t_ntoh (vapi_type_msg_header1_t * h)
{
  h->_vl_msg_id = be16toh (h->_vl_msg_id);
}

static inline void
vapi_type_msg_header2_t_hton (vapi_type_msg_header2_t * h)
{
  h->_vl_msg_id = htobe16 (h->_vl_msg_id);
}

static inline void
vapi_type_msg_header2_t_ntoh (vapi_type_msg_header2_t * h)
{
  h->_vl_msg_id = be16toh (h->_vl_msg_id);
}


#include <vapi/vapi.h>

typedef vapi_error_e (*vapi_cb_t) (struct vapi_ctx_s *, void *, vapi_error_e,
				   bool, void *);

typedef void (*generic_swap_fn_t) (void *payload);
typedef int (*verify_msg_size_fn_t) (void *msg, uword buf_size);

typedef struct
{
  const char *name;
  size_t name_len;
  const char *name_with_crc;
  size_t name_with_crc_len;
  bool has_context;
  unsigned int context_offset;
  unsigned int payload_offset;
  verify_msg_size_fn_t verify_msg_size;
  generic_swap_fn_t swap_to_be;
  generic_swap_fn_t swap_to_host;
  vapi_msg_id_t id;		/* assigned at run-time */
} vapi_message_desc_t;

typedef struct
{
  const char *name;
  int payload_offset;
  size_t size;
  void (*swap_to_be) (void *payload);
  void (*swap_to_host) (void *payload);
} vapi_event_desc_t;

vapi_msg_id_t vapi_register_msg (vapi_message_desc_t * msg);
u16 vapi_lookup_vl_msg_id (vapi_ctx_t ctx, vapi_msg_id_t id);
vapi_msg_id_t vapi_lookup_vapi_msg_id_t (vapi_ctx_t ctx, u16 vl_msg_id);
int vapi_get_client_index (vapi_ctx_t ctx);
bool vapi_is_nonblocking (vapi_ctx_t ctx);
bool vapi_requests_empty (vapi_ctx_t ctx);
bool vapi_requests_full (vapi_ctx_t ctx);
size_t vapi_get_request_count (vapi_ctx_t ctx);
size_t vapi_get_max_request_count (vapi_ctx_t ctx);
u32 vapi_gen_req_context (vapi_ctx_t ctx);

enum vapi_request_type
{
  VAPI_REQUEST_REG = 0,
  VAPI_REQUEST_DUMP = 1,
  VAPI_REQUEST_STREAM = 2,
};

void vapi_store_request (vapi_ctx_t ctx, u32 context,
			 vapi_msg_id_t response_id,
			 enum vapi_request_type type, vapi_cb_t callback,
			 void *callback_ctx);
int vapi_get_payload_offset (vapi_msg_id_t id);
void (*vapi_get_swap_to_host_func (vapi_msg_id_t id)) (void *payload);
void (*vapi_get_swap_to_be_func (vapi_msg_id_t id)) (void *payload);
size_t vapi_get_context_offset (vapi_msg_id_t id);
bool vapi_msg_is_with_context (vapi_msg_id_t id);
size_t vapi_get_message_count();
const char *vapi_get_msg_name(vapi_msg_id_t id);

vapi_error_e vapi_producer_lock (vapi_ctx_t ctx);
vapi_error_e vapi_producer_unlock (vapi_ctx_t ctx);

#ifdef __cplusplus
}
#endif

#endif
