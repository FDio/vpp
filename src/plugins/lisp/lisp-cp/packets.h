/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#include <vnet/vnet.h>
#include <lisp/lisp-cp/lisp_types.h>

#define IP_DF 0x4000		/* don't fragment */

void *pkt_push_ip (vlib_main_t * vm, vlib_buffer_t * b, ip_address_t * src,
		   ip_address_t * dst, u32 proto, u8 csum_offload);

void *pkt_push_udp_and_ip (vlib_main_t * vm, vlib_buffer_t * b, u16 sp,
			   u16 dp, ip_address_t * sip, ip_address_t * dip,
			   u8 cksum_offload);

void *pkt_push_ecm_hdr (vlib_buffer_t *b);
