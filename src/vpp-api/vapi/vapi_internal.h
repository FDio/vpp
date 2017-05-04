#ifndef VAPI_INTERNAL_H
#define VAPI_INTERNAL_H

#include <string.h>
#include <vppinfra/types.h>

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

void vapi_type_msg_header1_t_hton(vapi_type_msg_header1_t *h);
void vapi_type_msg_header1_t_ntoh(vapi_type_msg_header1_t *h);
void vapi_type_msg_header2_t_hton(vapi_type_msg_header2_t *h);
void vapi_type_msg_header2_t_ntoh(vapi_type_msg_header2_t *h);

#include <vapi.h>
#include <vpe.api.vapi.h>

typedef vapi_error_e (*vapi_cb_t) (struct vapi_ctx_s *, void *, vapi_error_e,
				   bool, void *);

typedef void (*generic_swap_fn_t) (void *payload);

typedef struct
{
  const char *name;
  size_t name_len;
  const char *name_with_crc;
  size_t name_with_crc_len;
  bool has_context;
  size_t context_offset;
  size_t payload_offset;
  size_t size;
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

extern bool *__vapi_msg_is_with_context;

vapi_msg_id_t vapi_register_msg (vapi_message_desc_t * msg);
void vapi_register_event (vapi_event_desc_t * event);
u16 vapi_lookup_vl_msg_id (vapi_ctx_t ctx, vapi_msg_id_t id);
int vapi_get_client_index (vapi_ctx_t ctx);
bool vapi_is_nonblocking (vapi_ctx_t ctx);
bool vapi_requests_full (vapi_ctx_t ctx);
size_t vapi_get_request_count (vapi_ctx_t ctx);
size_t vapi_get_max_request_count (vapi_ctx_t ctx);
u32 vapi_gen_req_context (vapi_ctx_t ctx);
vapi_error_e vapi_send_control_ping (vapi_ctx_t ctx,
                                     void *msg, u32 context);
void vapi_store_request (vapi_ctx_t ctx, u32 context, bool is_dump,
			 vapi_cb_t callback, void *callback_ctx);
int vapi_get_payload_offset (vapi_msg_id_t id);
void (*vapi_get_swap_to_host_func (vapi_msg_id_t id)) (void *payload);
void (*vapi_get_swap_to_be_func (vapi_msg_id_t id)) (void *payload);
size_t vapi_get_message_size (vapi_msg_id_t id);
size_t vapi_get_context_offset (vapi_msg_id_t id);

#endif
