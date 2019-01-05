/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * VCL Locked Sessions
 */

#ifndef SRC_VCL_VCL_LOCKED_H_
#define SRC_VCL_VCL_LOCKED_H_

#include <vcl/vppcom.h>

#define VLS_INVALID_HANDLE ((int)-1)

typedef int vls_handle_t;

vls_handle_t vls_create (uint8_t proto, uint8_t is_nonblocking);
int vls_close (vls_handle_t vlsh);
int vls_bind (vls_handle_t vlsh, vppcom_endpt_t * ep);
int vls_listen (vls_handle_t vlsh, int q_len);
int vls_connect (vls_handle_t vlsh, vppcom_endpt_t * server_ep);
vls_handle_t vls_accept (vls_handle_t vlsh, vppcom_endpt_t * ep, int flags);
ssize_t vls_read (vls_handle_t vlsh, void *buf, size_t nbytes);
ssize_t vls_recvfrom (vls_handle_t vlsh, void *buffer, uint32_t buflen,
		      int flags, vppcom_endpt_t * ep);
int vls_write (vls_handle_t vlsh, void *buf, size_t nbytes);
int vls_write_msg (vls_handle_t vlsh, void *buf, size_t nbytes);
int vls_sendto (vls_handle_t vlsh, void *buf, int buflen, int flags,
		vppcom_endpt_t * ep);
int vls_attr (vls_handle_t vlsh, uint32_t op, void *buffer,
	      uint32_t * buflen);
vls_handle_t vls_epoll_create (void);
int vls_epoll_ctl (vls_handle_t ep_vlsh, int op, vls_handle_t vlsh,
		   struct epoll_event *event);
int vls_epoll_wait (vls_handle_t ep_vlsh, struct epoll_event *events,
		    int maxevents, double wait_for_time);
vcl_session_handle_t vlsh_to_sh (vls_handle_t vlsh);
vcl_session_handle_t vlsh_to_session_index (vls_handle_t vlsh);
vls_handle_t vls_session_index_to_vlsh (uint32_t session_index);
int vls_app_create (char *app_name);

#endif /* SRC_VCL_VCL_LOCKED_H_ */
