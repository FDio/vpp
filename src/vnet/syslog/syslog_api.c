/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/fib/fib_table.h>
#include <vnet/syslog/syslog.h>

#include <vnet/format_fns.h>
#include <vnet/syslog/syslog.api_enum.h>
#include <vnet/syslog/syslog.api_types.h>

#define REPLY_MSG_ID_BASE syslog_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static int
syslog_severity_decode (vl_api_syslog_severity_t v, syslog_severity_t * s)
{
  v = ntohl (v);
  int rv = 0;

  switch (v)
    {
    case SYSLOG_API_SEVERITY_EMERG:
      *s = SYSLOG_SEVERITY_EMERGENCY;
      break;
    case SYSLOG_API_SEVERITY_ALERT:
      *s = SYSLOG_SEVERITY_ALERT;
      break;
    case SYSLOG_API_SEVERITY_CRIT:
      *s = SYSLOG_SEVERITY_CRITICAL;
      break;
    case SYSLOG_API_SEVERITY_ERR:
      *s = SYSLOG_SEVERITY_ERROR;
      break;
    case SYSLOG_API_SEVERITY_WARN:
      *s = SYSLOG_SEVERITY_WARNING;
      break;
    case SYSLOG_API_SEVERITY_NOTICE:
      *s = SYSLOG_SEVERITY_NOTICE;
      break;
    case SYSLOG_API_SEVERITY_INFO:
      *s = SYSLOG_SEVERITY_INFORMATIONAL;
      break;
    case SYSLOG_API_SEVERITY_DBG:
      *s = SYSLOG_SEVERITY_DEBUG;
      break;
    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  return rv;
}

static int
syslog_severity_encode (syslog_severity_t v, vl_api_syslog_severity_t * s)
{
  int rv = 0;
  switch (v)
    {
    case SYSLOG_SEVERITY_EMERGENCY:
      *s = SYSLOG_API_SEVERITY_EMERG;
      break;
    case SYSLOG_SEVERITY_ALERT:
      *s = SYSLOG_API_SEVERITY_ALERT;
      break;
    case SYSLOG_SEVERITY_CRITICAL:
      *s = SYSLOG_API_SEVERITY_CRIT;
      break;
    case SYSLOG_SEVERITY_ERROR:
      *s = SYSLOG_API_SEVERITY_ERR;
      break;
    case SYSLOG_SEVERITY_WARNING:
      *s = SYSLOG_API_SEVERITY_WARN;
      break;
    case SYSLOG_SEVERITY_NOTICE:
      *s = SYSLOG_API_SEVERITY_NOTICE;
      break;
    case SYSLOG_SEVERITY_INFORMATIONAL:
      *s = SYSLOG_API_SEVERITY_INFO;
      break;
    case SYSLOG_SEVERITY_DEBUG:
      *s = SYSLOG_API_SEVERITY_DBG;
      break;
    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
    }

  *s = htonl (*s);
  return rv;
}

static void
vl_api_syslog_set_sender_t_handler (vl_api_syslog_set_sender_t * mp)
{
  vl_api_syslog_set_sender_reply_t *rmp;
  ip4_address_t collector, src;

  clib_memcpy (&collector, &mp->collector_address, sizeof (collector));
  clib_memcpy (&src, &mp->src_address, sizeof (src));

  int rv = set_syslog_sender (&collector, ntohs (mp->collector_port), &src,
			      ntohl (mp->vrf_id), ntohl (mp->max_msg_size));

  REPLY_MACRO (VL_API_SYSLOG_SET_SENDER_REPLY);
}

static void
vl_api_syslog_get_sender_t_handler (vl_api_syslog_get_sender_t * mp)
{
  int rv = 0;
  vl_api_syslog_get_sender_reply_t *rmp;
  syslog_main_t *sm = &syslog_main;
  u32 vrf_id;

  REPLY_MACRO2 (VL_API_SYSLOG_GET_SENDER_REPLY,
  ({
    clib_memcpy (&rmp->collector_address, &(sm->collector),
                 sizeof(ip4_address_t));
    clib_memcpy (&rmp->src_address, &(sm->src_address),
                 sizeof(ip4_address_t));
    rmp->collector_port = htons (sm->collector_port);
    if (sm->fib_index == ~0)
      vrf_id = ~0;
    else
      vrf_id = htonl (fib_table_get_table_id (sm->fib_index, FIB_PROTOCOL_IP4));
    rmp->vrf_id = vrf_id;
    rmp->max_msg_size = htonl (sm->max_msg_size);
  }))
}

static void
vl_api_syslog_set_filter_t_handler (vl_api_syslog_set_filter_t * mp)
{
  vl_api_syslog_set_filter_reply_t *rmp;
  syslog_main_t *sm = &syslog_main;
  int rv = 0;
  syslog_severity_t s;

  rv = syslog_severity_decode (mp->severity, &s);
  if (rv)
    goto send_reply;

  sm->severity_filter = s;

send_reply:
  REPLY_MACRO (VL_API_SYSLOG_SET_FILTER_REPLY);
}

static void
vl_api_syslog_get_filter_t_handler (vl_api_syslog_get_filter_t * mp)
{
  int rv = 0;
  vl_api_syslog_get_filter_reply_t *rmp;
  syslog_main_t *sm = &syslog_main;

  REPLY_MACRO2 (VL_API_SYSLOG_GET_FILTER_REPLY,
  ({
     rv = syslog_severity_encode (sm->severity_filter, &rmp->severity);
  }))
}

#include <vnet/syslog/syslog.api.c>

static clib_error_t *
syslog_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (syslog_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
