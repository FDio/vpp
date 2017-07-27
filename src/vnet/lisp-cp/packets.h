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

#include <vnet/vnet.h>
#include <vnet/lisp-cp/lisp_types.h>

#define IP_DF 0x4000		/* don't fragment */

void *pkt_push_ip (vlib_main_t * vm, vlib_buffer_t * b, ip_address_t * src,
		   ip_address_t * dst, u32 proto, u8 csum_offload);

void *pkt_push_udp_and_ip (vlib_main_t * vm, vlib_buffer_t * b, u16 sp,
			   u16 dp, ip_address_t * sip, ip_address_t * dip,
			   u8 cksum_offload);

void *pkt_push_ecm_hdr (vlib_buffer_t * b);

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
