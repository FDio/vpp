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
#include <http_static/http_static.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <http_static/http_static.api_enum.h>
#include <http_static/http_static.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} http_static_test_main_t;

http_static_test_main_t http_static_test_main;

#define __plugin_msg_base http_static_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

static int
api_http_static_enable_v4 (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_http_static_enable_v4_t *mp;
  u64 tmp;
  u8 *www_root = 0;
  u8 *uri = 0;
  u32 prealloc_fifos = 0;
  u32 private_segment_size = 0;
  u32 fifo_size = 8 << 10;
  u32 cache_size_limit = 1 << 20;
  u32 max_age = HSS_DEFAULT_MAX_AGE;
  u32 keepalive_timeout = HSS_DEFAULT_KEEPALIVE_TIMEOUT;
  u64 max_body_size = HSS_DEFAULT_MAX_BODY_SIZE;
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
	  if (tmp >= 0x100000000ULL)
	    {
	      errmsg ("fifo-size %llu, too large", tmp);
	      return -99;
	    }
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
      else if (unformat (line_input, "max-age %d", &max_age))
	;
      else if (unformat (line_input, "keepalive-timeout %d",
			 &keepalive_timeout))
	;
      else if (unformat (line_input, "uri %s", &uri))
	;
      else if (unformat (line_input, "max-body-size %llu", &max_body_size))
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
  M (HTTP_STATIC_ENABLE_V4, mp);
  strncpy_s ((char *) mp->www_root, 256, (const char *) www_root, 256);
  strncpy_s ((char *) mp->uri, 256, (const char *) uri, 256);
  mp->fifo_size = ntohl (fifo_size);
  mp->cache_size_limit = ntohl (cache_size_limit);
  mp->prealloc_fifos = ntohl (prealloc_fifos);
  mp->private_segment_size = ntohl (private_segment_size);
  mp->max_age = ntohl (max_age);
  mp->keepalive_timeout = ntohl (keepalive_timeout);
  mp->max_body_size = ntohl (max_body_size);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_http_static_enable_v5 (vat_main_t *vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_http_static_enable_v5_t *mp;
  u64 tmp;
  u8 *www_root = 0;
  u8 *uri = 0;
  u32 prealloc_fifos = 0;
  u32 private_segment_size = 0;
  u32 fifo_size = 8 << 10;
  u32 cache_size_limit = 1 << 20;
  u32 max_age = HSS_DEFAULT_MAX_AGE;
  u32 keepalive_timeout = HSS_DEFAULT_KEEPALIVE_TIMEOUT;
  u64 max_body_size = HSS_DEFAULT_MAX_BODY_SIZE;
  u32 rx_buff_thresh = HSS_DEFAULT_RX_BUFFER_THRESH;
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
	  if (tmp >= 0x100000000ULL)
	    {
	      errmsg ("fifo-size %llu, too large", tmp);
	      return -99;
	    }
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
      else if (unformat (line_input, "max-age %d", &max_age))
	;
      else if (unformat (line_input, "keepalive-timeout %d",
			 &keepalive_timeout))
	;
      else if (unformat (line_input, "uri %s", &uri))
	;
      else if (unformat (line_input, "max-body-size %U", unformat_memory_size,
			 &max_body_size))
	;
      else if (unformat (line_input, "rx-buff-thresh %U", unformat_memory_size,
			 &rx_buff_thresh))
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
  M (HTTP_STATIC_ENABLE_V4, mp);
  strncpy_s ((char *) mp->www_root, 256, (const char *) www_root, 256);
  strncpy_s ((char *) mp->uri, 256, (const char *) uri, 256);
  mp->fifo_size = ntohl (fifo_size);
  mp->cache_size_limit = ntohl (cache_size_limit);
  mp->prealloc_fifos = ntohl (prealloc_fifos);
  mp->private_segment_size = ntohl (private_segment_size);
  mp->max_age = ntohl (max_age);
  mp->keepalive_timeout = ntohl (keepalive_timeout);
  mp->max_body_size = ntohl (max_body_size);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#include <http_static/http_static.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
