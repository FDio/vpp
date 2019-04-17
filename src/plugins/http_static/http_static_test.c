/*
 * http_static.c - skeleton vpp-api-test plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
 */
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <http_static/http_static_msg_enum.h>

/* define message structures */
#define vl_typedefs
#include <http_static/http_static_all_api_h.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun		/* define message structures */
#include <http_static/http_static_all_api_h.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <http_static/http_static_all_api_h.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <http_static/http_static_all_api_h.h>
#undef vl_api_version


typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} http_static_test_main_t;

http_static_test_main_t http_static_test_main;

#define __plugin_msg_base http_static_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

#define foreach_standard_reply_retval_handler   \
_(http_static_enable_reply)

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = http_static_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
foreach_standard_reply_retval_handler;
#undef _

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */
#define foreach_vpe_api_reply_msg                       \
_(HTTP_STATIC_ENABLE_REPLY, http_static_enable_reply)


static int
api_http_static_enable (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_http_static_enable_t *mp;
  u64 tmp;
  u8 *www_root = 0;
  u8 *uri = 0;
  u32 prealloc_fifos = 0;
  u32 private_segment_size = 0;
  u32 fifo_size = 8 << 10;
  u32 cache_size_limit = 1 << 20;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "www-root %s", &www_root))
	;
      else if (unformat (line_input, "prealloc-fifos %d", &prealloc_fifos))
	;
      else if (unformat (line_input, "private-segment-size %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      errmsg ("private segment size %llu, too large", tmp);
	      return -99;
	    }
	  private_segment_size = (u32) tmp;
	}
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
			 &tmp))
	{
	  fifo_size = (u32) tmp;
	}
      else if (unformat (line_input, "cache-size %U", unformat_memory_size,
			 &tmp))
	{
	  if (tmp < (128ULL << 10))
	    {
	      errmsg ("cache-size must be at least 128kb");
	      return -99;
	    }
	  cache_size_limit = (u32) tmp;
	}

      else if (unformat (line_input, "uri %s", &uri))
	;
      else
	{
	  errmsg ("unknown input `%U'", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (www_root == 0)
    {
      errmsg ("Must specify www-root");
      return -99;
    }

  if (uri == 0)
    uri = format (0, "tcp://0.0.0.0/80%c", 0);



  /* Construct the API message */
  M (HTTP_STATIC_ENABLE, mp);
  clib_strncpy ((char *) mp->www_root, (char *) www_root,
		ARRAY_LEN (mp->www_root) - 1);
  clib_strncpy ((char *) mp->uri, (char *) uri, ARRAY_LEN (mp->uri) - 1);
  mp->fifo_size = ntohl (fifo_size);
  mp->cache_size_limit = ntohl (cache_size_limit);
  mp->prealloc_fifos = ntohl (prealloc_fifos);
  mp->private_segment_size = ntohl (private_segment_size);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
#define foreach_vpe_api_msg                                             \
_(http_static_enable, "www-root <path> [prealloc-fios <nn>]\n"          \
"[private-segment-size <nnMG>] [fifo-size <nbytes>] [uri <uri>]\n")

static void
http_static_api_hookup (vat_main_t * vam)
{
  http_static_test_main_t *htmp = &http_static_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + htmp->msg_id_base),     \
                           #n,                                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t *
vat_plugin_register (vat_main_t * vam)
{
  http_static_test_main_t *htmp = &http_static_test_main;
  u8 *name;

  htmp->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "http_static_%08x%c", api_version, 0);
  htmp->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (htmp->msg_id_base != (u16) ~ 0)
    http_static_api_hookup (vam);

  vec_free (name);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
