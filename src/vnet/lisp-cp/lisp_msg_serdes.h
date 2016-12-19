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

#ifndef VNET_LISP_GPE_LISP_MSG_BUILDER_H_
#define VNET_LISP_GPE_LISP_MSG_BUILDER_H_

#include <vnet/vnet.h>
#include <vnet/lisp-cp/lisp_cp_messages.h>
#include <vnet/lisp-cp/control.h>

void *lisp_msg_put_mreq (lisp_cp_main_t * lcm, vlib_buffer_t * b,
			 gid_address_t * seid, gid_address_t * deid,
			 gid_address_t * rlocs, u8 is_smr_invoked,
			 u8 rloc_probe_set, u64 * nonce);

void *lisp_msg_put_map_register (vlib_buffer_t * b, mapping_t * records,
				 u8 want_map_notify, u16 auth_data_len,
				 u64 * nonce, u32 * msg_len);

void *lisp_msg_push_ecm (vlib_main_t * vm, vlib_buffer_t * b, int lp, int rp,
			 gid_address_t * la, gid_address_t * ra);

void *lisp_msg_put_map_reply (vlib_buffer_t * b, mapping_t * record,
			      u64 nonce, u8 probe_bit);

u32
lisp_msg_parse_mapping_record (vlib_buffer_t * b, gid_address_t * eid,
			       locator_t ** locs, locator_t * probed_);

u32 lisp_msg_parse_addr (vlib_buffer_t * b, gid_address_t * eid);

u32 lisp_msg_parse_eid_rec (vlib_buffer_t * b, gid_address_t * eid);

u32
lisp_msg_parse_itr_rlocs (vlib_buffer_t * b, gid_address_t ** rlocs,
			  u8 rloc_count);

#endif /* VNET_LISP_GPE_LISP_MSG_BUILDER_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
