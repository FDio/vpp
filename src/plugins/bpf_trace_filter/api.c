/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <bpf_trace_filter/bpf_trace_filter.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

/* define message IDs */
#include <bpf_trace_filter/bpf_trace_filter.api_enum.h>
#include <bpf_trace_filter/bpf_trace_filter.api_types.h>

#define REPLY_MSG_ID_BASE (bm->msg_id_base)
#include <vlibapi/api_helper_macros.h>

static void
vl_api_bpf_trace_filter_set_t_handler (vl_api_bpf_trace_filter_set_t *mp)
{
  bpf_trace_filter_main_t *bm = &bpf_trace_filter_main;
  vl_api_bpf_trace_filter_set_reply_t *rmp;
  clib_error_t *err = 0;
  int rv = 0;
  u8 is_del = !mp->is_add;
  char *bpf_expr;

  bpf_expr = vl_api_from_api_to_new_c_string (&mp->filter);
  err = bpf_trace_filter_set_unset (bpf_expr, is_del, 0);

  if (err)
    {
      rv = -1;
      clib_error_report (err);
    }
  vec_free (bpf_expr);

  REPLY_MACRO (VL_API_BPF_TRACE_FILTER_SET_REPLY);
}

static void
vl_api_bpf_trace_filter_set_v2_t_handler (vl_api_bpf_trace_filter_set_v2_t *mp)
{
  bpf_trace_filter_main_t *bm = &bpf_trace_filter_main;
  vl_api_bpf_trace_filter_set_v2_reply_t *rmp;
  clib_error_t *err = 0;
  int rv = 0;
  u8 is_del = !mp->is_add;
  u8 optimize = !!mp->optimize;
  char *bpf_expr;

  bpf_expr = vl_api_from_api_to_new_c_string (&mp->filter);
  err = bpf_trace_filter_set_unset (bpf_expr, is_del, optimize);

  if (err)
    {
      rv = -1;
      clib_error_report (err);
    }
  vec_free (bpf_expr);

  REPLY_MACRO (VL_API_BPF_TRACE_FILTER_SET_V2_REPLY);
}

#include <bpf_trace_filter/bpf_trace_filter.api.c>

static clib_error_t *
bpf_trace_filter_plugin_api_hookup (vlib_main_t *vm)
{
  bpf_trace_filter_main_t *bm = &bpf_trace_filter_main;

  /* ask for a correctly-sized block of API message decode slots */
  bm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (bpf_trace_filter_plugin_api_hookup);
