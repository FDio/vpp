/*
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
 */

#ifndef included_vppcom_h
#define included_vppcom_h

#include <netdb.h>
#include <errno.h>
#include <sys/epoll.h>

/*
 * VPPCOM Public API Definitions, Enums, and Data Structures
 */
#define INVALID_SESSION_ID                   (~0)
#define VPPCOM_VRF_DEFAULT                   0
#define VPPCOM_CONF_DEFAULT                  "/etc/vpp/vcl.conf"
#define VPPCOM_ENV_CONF                      "VCL_CONFIG"
#define VPPCOM_ENV_DEBUG                     "VCL_DEBUG"
#define VPPCOM_ENV_APP_PROXY_TRANSPORT_TCP   "VCL_APP_PROXY_TRANSPORT_TCP"
#define VPPCOM_ENV_APP_PROXY_TRANSPORT_UDP   "VCL_APP_PROXY_TRANSPORT_UDP"
#define VPPCOM_ENV_APP_NAMESPACE_ID          "VCL_APP_NAMESPACE_ID"
#define VPPCOM_ENV_APP_NAMESPACE_SECRET      "VCL_APP_NAMESPACE_SECRET"
#define VPPCOM_ENV_APP_SCOPE_LOCAL           "VCL_APP_SCOPE_LOCAL"
#define VPPCOM_ENV_APP_SCOPE_GLOBAL          "VCL_APP_SCOPE_GLOBAL"

typedef enum
{
  VPPCOM_PROTO_TCP = 0,
  VPPCOM_PROTO_UDP,
} vppcom_proto_t;

typedef enum
{
  VPPCOM_IS_IP6 = 0,
  VPPCOM_IS_IP4,
} vppcom_is_ip4_t;

typedef struct vppcom_endpt_t_
{
  uint32_t vrf;
  uint8_t is_cut_thru;
  uint8_t is_ip4;
  uint8_t *ip;
  uint16_t port;
} vppcom_endpt_t;

typedef enum
{
  VPPCOM_OK = 0,
  VPPCOM_EAGAIN = -EAGAIN,
  VPPCOM_ENOMEM = -ENOMEM,
  VPPCOM_EINVAL = -EINVAL,
  VPPCOM_EBADFD = -EBADFD,
  VPPCOM_EAFNOSUPPORT = -EAFNOSUPPORT,
  VPPCOM_ECONNRESET = -ECONNRESET,
  VPPCOM_ECONNREFUSED = -ECONNREFUSED,
  VPPCOM_ETIMEDOUT = -ETIMEDOUT,
} vppcom_error_t;

typedef enum
{
  VPPCOM_ATTR_GET_NREAD,
  VPPCOM_ATTR_GET_NWRITE,
  VPPCOM_ATTR_GET_FLAGS,
  VPPCOM_ATTR_SET_FLAGS,
  VPPCOM_ATTR_GET_LCL_ADDR,
  VPPCOM_ATTR_GET_PEER_ADDR,
  VPPCOM_ATTR_SET_REUSEADDR,
  VPPCOM_ATTR_SET_BROADCAST,
  VPPCOM_ATTR_SET_V6ONLY,
  VPPCOM_ATTR_SET_KEEPALIVE,
  VPPCOM_ATTR_SET_TCP_KEEPIDLE,
  VPPCOM_ATTR_SET_TCP_KEEPINTVL,
} vppcom_attr_op_t;

/*
 * VPPCOM Public API Functions
 */
static inline const char *
vppcom_retval_str (int retval)
{
  char *st;

  switch (retval)
    {
    case VPPCOM_OK:
      st = "VPPCOM_OK";
      break;

    case VPPCOM_EAGAIN:
      st = "VPPCOM_EAGAIN";
      break;

    case VPPCOM_EINVAL:
      st = "VPPCOM_EINVAL";
      break;

    case VPPCOM_EBADFD:
      st = "VPPCOM_EBADFD";
      break;

    case VPPCOM_EAFNOSUPPORT:
      st = "VPPCOM_EAFNOSUPPORT";
      break;

    case VPPCOM_ECONNRESET:
      st = "VPPCOM_ECONNRESET";
      break;

    case VPPCOM_ECONNREFUSED:
      st = "VPPCOM_ECONNREFUSED";
      break;

    case VPPCOM_ETIMEDOUT:
      st = "VPPCOM_ETIMEDOUT";
      break;

    default:
      st = "UNKNOWN_STATE";
      break;
    }

  return st;
}

/* TBD: make these constructor/destructor function */
extern int vppcom_app_create (char *app_name);
extern void vppcom_app_destroy (void);

extern int vppcom_session_create (uint32_t vrf, uint8_t proto,
				  uint8_t is_nonblocking);
extern int vppcom_session_close (uint32_t session_index);

extern int vppcom_session_bind (uint32_t session_index, vppcom_endpt_t * ep);
extern int vppcom_session_listen (uint32_t session_index, uint32_t q_len);
extern int vppcom_session_accept (uint32_t session_index,
				  vppcom_endpt_t * client_ep,
				  uint32_t flags, double wait_for_time);

extern int vppcom_session_connect (uint32_t session_index,
				   vppcom_endpt_t * server_ep);
extern int vppcom_session_read (uint32_t session_index, void *buf, int n);
extern int vppcom_session_write (uint32_t session_index, void *buf, int n);

extern int vppcom_select (unsigned long n_bits,
			  unsigned long *read_map,
			  unsigned long *write_map,
			  unsigned long *except_map, double wait_for_time);

extern int vppcom_epoll_create (void);
extern int vppcom_epoll_ctl (uint32_t vep_idx, int op,
			     uint32_t session_index,
			     struct epoll_event *event);
extern int vppcom_epoll_wait (uint32_t vep_idx, struct epoll_event *events,
			      int maxevents, double wait_for_time);
extern int vppcom_session_attr (uint32_t session_index, uint32_t op,
				void *buffer, uint32_t * buflen);
extern int vppcom_session_recvfrom (uint32_t session_index, void *buffer,
				    uint32_t buflen, int flags,
				    vppcom_endpt_t * ep);
extern int vppcom_session_sendto (uint32_t session_index, void *buffer,
				  uint32_t buflen, int flags,
				  vppcom_endpt_t * ep);

#endif /* included_vppcom_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
