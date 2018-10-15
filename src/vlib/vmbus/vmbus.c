/*
 * Copyright (c) 2018, Microsoft Corporation.
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
/*
 * vmbus.c: generic UUID handling
 *
 * Much of this code is based of libuuid which is
 * Copyright (C) 1996, 1997 Theodore Ts'o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.	 IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <vlib/vlib.h>
#include <vlib/vmbus/vmbus.h>
#include <vlib/unix/unix.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <net/if.h>

vlib_vmbus_addr_t * __attribute__ ((weak)) vlib_vmbus_get_all_dev_addrs ()
{
  return NULL;
}

uword
unformat_vlib_vmbus_addr (unformat_input_t * input, va_list * args)
{
  vlib_vmbus_addr_t *addr = va_arg (*args, vlib_vmbus_addr_t *);
  uword ret = 0;
  u8 *s;

  if (!unformat (input, "%s", &s))
    return 0;

  if (uuid_parse ((char *) s, addr->guid) == 0)
    ret = 1;

  vec_free (s);

  return ret;
}

u8 *
format_vlib_vmbus_addr (u8 * s, va_list * va)
{
  vlib_vmbus_addr_t *addr = va_arg (*va, vlib_vmbus_addr_t *);
  char tmp[40];

  uuid_unparse (addr->guid, tmp);
  return format (s, "%s", tmp);
}

clib_error_t *
vmbus_bus_init (vlib_main_t * vm)
{
  return vlib_call_init_function (vm, vmbus_bus_init);
}

VLIB_INIT_FUNCTION (vmbus_bus_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
