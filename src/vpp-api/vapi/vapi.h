#ifndef vpp_api_h_included
#define vpp_api_h_included

#include <string.h>
#include <stdbool.h>
#include <vppinfra/types.h>

typedef enum {
  VAPI_OK = 0,
  VAPI_EINVAL,
  VAPI_EAGAIN,
  VAPI_ENOTSUP,
  VAPI_ENOMEM,
  VAPI_ENORESP,
  VAPI_EMAP_FAIL,
  VAPI_ECON_FAIL,
  VAPI_EUSER,
} vapi_error_e;

typedef enum {
  VAPI_MODE_BLOCKING = 1,
  VAPI_MODE_NONBLOCKING = 2,
} vapi_mode_e;

typedef enum {
  VAPI_WAIT_FOR_READ,
  VAPI_WAIT_FOR_WRITE,
  VAPI_WAIT_FOR_READ_WRITE,
} vapi_wait_mode_e;

typedef int vapi_msg_id_t;

typedef struct vapi_ctx_s vapi_ctx_t;
void *vapi_msg_alloc (vapi_ctx_t *ctx, size_t size);
void vapi_msg_free (vapi_ctx_t *ctx, void *msg);
vapi_ctx_t *vapi_ctx_alloc ();
void vapi_ctx_free (vapi_ctx_t *ctx);
bool vapi_is_msg_available (vapi_ctx_t *ctx, vapi_msg_id_t type);
vapi_error_e vapi_connect (vapi_ctx_t *ctx, const char *name,
                           const char *chroot_prefix, int max_queued_requests,
                           vapi_mode_e mode);
vapi_error_e vapi_disconnect (vapi_ctx_t *ctx);
vapi_error_e vapi_get_fd (vapi_ctx_t *ctx, int *fd);
vapi_error_e vapi_send (vapi_ctx_t *ctx, void *msg);
vapi_error_e vapi_recv (vapi_ctx_t *ctx, void **msg, size_t *msg_size);
vapi_error_e vapi_wait (vapi_ctx_t *ctx, vapi_wait_mode_e mode);
vapi_error_e vapi_dispatch_one (vapi_ctx_t *ctx);
vapi_error_e vapi_dispatch (vapi_ctx_t *ctx);

typedef vapi_error_e (*vapi_generic_event_cb) (vapi_ctx_t *ctx,
                                               void *callback_ctx,
                                               void *payload);

void vapi_set_event_cb (vapi_ctx_t *ctx, vapi_msg_id_t id,
                        vapi_generic_event_cb callback, void *callback_ctx);
void vapi_clear_event_cb (vapi_ctx_t *ctx, vapi_msg_id_t id);

#endif
