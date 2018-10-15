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
 * vmbus.h: VMBus definitions.
 */

#ifndef included_vlib_vmbus_h
#define included_vlib_vmbus_h

#include <vlib/vlib.h>

typedef struct
{
  u8 guid[16];
} vlib_vmbus_addr_t;
typedef u32 vlib_vmbus_dev_handle_t;

vlib_vmbus_addr_t *vlib_vmbus_get_all_dev_addrs ();
vlib_vmbus_addr_t *vlib_vmbus_get_addr (vlib_vmbus_dev_handle_t h);
uword vlib_vmbus_get_private_data (vlib_vmbus_dev_handle_t h);
void vlib_vmbus_set_private_data (vlib_vmbus_dev_handle_t h,
				  uword private_data);

clib_error_t *vlib_vmbus_bind_to_uio (vlib_vmbus_addr_t * addr);
#endif /* included_vlib_vmbus_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
