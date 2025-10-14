/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <http/http3/http3.h>
#include <http/http_private.h>

typedef struct
{
  http_req_t base;
  http3_stream_type_t stream_type;
} http3_req_ctx_t;

typedef struct
{
  u32 hc_index;
  http3_conn_settings_t peer_settings;
} http3_conn_ctx_t;

typedef struct
{
  http3_conn_ctx_t *conn_pool;
  http3_req_ctx_t *req_pool;
} http3_worker_ctx_t;

typedef struct
{
  http3_worker_ctx_t *workers;
  http3_conn_settings_t settings;
} http3_main_t;

static http3_main_t http3_main;

static_always_inline http3_worker_ctx_t *
http3_worker_get (clib_thread_index_t thread_index)
{
  return &http3_main.workers[thread_index];
}

static_always_inline http3_req_ctx_t *
http3_req_get (u32 req_index, clib_thread_index_t thread_index)
{
  http3_worker_ctx_t *wrk = http3_worker_get (thread_index);

  return pool_elt_at_index (wrk->req_pool, req_index);
}

/*****************/
/* http core VFT */
/*****************/

static void
http3_enable_callback (void)
{
  http3_main_t *h3m = &http3_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;

  num_threads = 1 /* main thread */ + vtm->n_threads;

  vec_validate (h3m->workers, num_threads - 1);
}

static int
http3_update_settings (http3_settings_t type, u64 value)
{
  http3_main_t *h3m = &http3_main;

  switch (type)
    {
#define _(v, label, member, min, max, default_value, server, client)          \
  case HTTP3_SETTINGS_##label:                                                \
    if (!(value >= min && value <= max))                                      \
      return -1;                                                              \
    h3m->settings.member = value;                                             \
    return 0;
      foreach_http3_settings
#undef _
	default : return -1;
    }
}

static uword
http3_unformat_config_callback (unformat_input_t *input)
{
  u64 value;

  if (!input)
    return 0;

  unformat_skip_white_space (input);
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "max-field-section-size %lu", &value))
	{
	  if (http3_update_settings (HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE,
				     value))
	    return 0;
	}
    }
  return 1;
}

static u32
http3_hc_index_get_by_req_index (u32 req_index,
				 clib_thread_index_t thread_index)
{
  http3_req_ctx_t *req;

  req = http3_req_get (req_index, thread_index);
  return req->base.hr_hc_index;
}

static transport_connection_t *
http3_req_get_connection (u32 req_index, clib_thread_index_t thread_index)
{
  http3_req_ctx_t *req;
  req = http3_req_get (req_index, thread_index);
  return &(req->base.connection);
}

static u8 *
format_http3_req (u8 *s, va_list *args)
{
  http3_req_ctx_t *req = va_arg (*args, http3_req_ctx_t *);
  http_conn_t *hc = va_arg (*args, http_conn_t *);
  session_t *ts;

  ts = session_get_from_handle (hc->hc_tc_session_handle);
  s = format (s, "[%d:%d][H3] app_wrk %u hc_index %u ts %d:%d",
	      req->base.c_thread_index, req->base.c_s_index,
	      req->base.hr_pa_wrk_index, req->base.hr_hc_index,
	      ts->thread_index, ts->session_index);

  return s;
}

static u8 *
http3_format_req (u8 *s, va_list *args)
{
  u32 req_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  http_conn_t *hc = va_arg (*args, http_conn_t *);
  u32 verbose = va_arg (*args, u32);
  http3_req_ctx_t *req;

  req = http3_req_get (req_index, thread_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_http3_req, req, hc);
  if (verbose)
    {
      /* FIXME */
    }

  return s;
}

const static http_engine_vft_t http3_engine = {
  .name = "http3",
  .enable_callback = http3_enable_callback,
  .unformat_cfg_callback = http3_unformat_config_callback,
  .hc_index_get_by_req_index = http3_hc_index_get_by_req_index,
  .req_get_connection = http3_req_get_connection,
  .format_req = http3_format_req,
};

clib_error_t *
http3_init (vlib_main_t *vm)
{
  http3_main_t *h3m = &http3_main;

  h3m->settings = http3_default_conn_settings;
  h3m->settings.max_field_section_size = 1 << 14; /* by default unlimited */
  http_register_engine (&http3_engine, HTTP_VERSION_3);

  return 0;
}

VLIB_INIT_FUNCTION (http3_init) = {
  .runs_after = VLIB_INITS ("http_transport_init"),
};
