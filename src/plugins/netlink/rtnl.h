/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef RTNL_H_
#define RTNL_H_

#include <vlib/vlib.h>

#include <linux/netlink.h>
#include <vppinfra/clib.h>

typedef enum {
  RTNL_ERR_UNKNOWN,
} rtnl_error_t;

#define RTNL_NETNS_NAMELEN 128

/*
 * RTNL stream implements an RTNL overlay
 * for receiving continuous updates for a given namespace.
 * When the stream is initially opened, dump requests are sent
 * in order to retrieve the original state.
 * handle_error is called any time synchronization cannot be
 * achieved. When called, state is reset to its original state and
 * new dump requests are sent.
 */

typedef struct rtnl_stream_s {
  char name[RTNL_NETNS_NAMELEN + 1];
  void (*recv_message)(struct nlmsghdr *hdr, uword opaque);
  void (*error)(rtnl_error_t err, uword opaque);
  uword opaque;
} rtnl_stream_t;

u32 rtnl_stream_open(rtnl_stream_t *template);
void rtnl_stream_close(u32 handle);

/*
 * Executes a function in a synchronously executed thread in the
 * given namespace.
 * Returns 0 on success, and -errno on error.
 */
int rtnl_exec_in_namespace(u32 handle, void *(*fn)(void *), void *arg, void **ret);
int rtnl_exec_in_namespace_by_name(char *nsname, void *(*fn)(void *), void *arg, void **ret);

u8 *format_rtnl_nsname2path(u8 *s, va_list *args);

#endif
